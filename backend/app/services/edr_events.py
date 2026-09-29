"""Translate endpoint-agent telemetry into the events the Sigma rules read.

Three producers reach the correlation engine through
`edr_transport.publish_agent_batch`, and each speaks its own dialect:

  * node-tauri  POST /edr/events   {kind, process_name, process_path,
                                    command_line, user, target, extra}
                                   For file and registry kinds the path / key is
                                   in `target`; for tcp_* it is "ip:port".
  * Python agent POST /agents/events {category, title, details{...}}; the route
                                   forwards the category as `kind` and keeps the
                                   whole `details` dict.
  * node-tauri  POST /nodes/events  registry_persistence_new /
                                   new_service_installed, bridged in
                                   app/api/nodes.py into the same shape.

`translate_edr_event` is the single place that knows those shapes. It returns
zero or more events whose fields are the ones the rules filter on, so a rule
never has to know which agent produced its input. Anything it cannot translate
faithfully yields nothing: an event that lands on a rule with the wrong or an
empty field is worse than an event that is not delivered.

Field contract, per event type (what a rule may rely on):

  process_creation     path=exe path, process_name, cmdline (alias command_line),
                       ppid, username. `path` is ONLY the executable; command
                       tokens belong to `cmdline_*` clauses.
  process_termination  pid only. Nothing may treat an exit as a start.
  file_creation / file_modification / file_deletion
                       path = the file (also readable as file_name).
  registry_modification / registry_deletion
                       path = the key, registry_value.
  dll_load             path = the loaded image.
  network_connection   source_ip = destination_ip = the REMOTE peer, the
                       convention connection_monitor.build_event documents.
                       The local address is only ever kept as local_addr.
  service_install      service_name, service_path.
  rdp_login            auth_result, username, rdp_source_ip (host-only event).
  canary_modified      path = the canary file (host-only event).
"""
from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any, Optional

# kind (as published on the bus) -> the event_type a rule is filed under.
# Kinds that need the payload to decide (fim, windows_event, forensic) map to the
# type they usually produce; translate_edr_event refines or drops them.
EDR_EVENT_MAP: dict[str, str] = {
    # host_monitor (in-process) and the Python agent's `fim` category
    "fim": "file_modification",
    "file_create": "file_creation",
    "file_created": "file_creation",
    "file_write": "file_modification",
    "file_modify": "file_modification",
    "file_modified": "file_modification",
    # A deletion is not persistence, tampering with a config, or a write, so it
    # is its own type. Mapping it to file_modification made deleting
    # authorized_keys or a cron file look like installing one.
    "file_delete": "file_deletion",
    "file_deleted": "file_deletion",
    # Python agent category: it reports NEW processes only.
    "process": "process_creation",
    "process_start": "process_creation",
    # An exit is not a launch. Mapping it to process_creation made every
    # process rule evaluate the exit of a process that had no command line.
    "process_stop": "process_termination",
    "image_load": "dll_load",
    "registry_set": "registry_modification",
    "registry_delete": "registry_deletion",
    # Outbound only, see _network_event.
    "tcp_connect": "network_connection",
    "network": "network_connection",
    "network_anomaly": "connection",
    # /nodes/events bridge (4697 service install)
    "service_install": "service_install",
    # Python agent Windows Security log (4624 logon type 10)
    "windows_event": "rdp_login",
    # node-tauri ransomware module: one forensic incident carries its signals
    "forensic": "canary_modified",
}

_FIM_EVENT_TYPE = {
    "created": "file_creation",
    "modified": "file_modification",
    "moved": "file_modification",
    "deleted": "file_deletion",
}

# Security 4624 StringInserts (Microsoft docs): 5 = TargetUserName,
# 8 = LogonType, 18 = IpAddress.
_4624_USER, _4624_ADDR = 5, 18

_MAX_TEXT = 4096


def _first(*values: Any) -> Any:
    for v in values:
        if v not in (None, ""):
            return v
    return None


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        value = " ".join(str(v) for v in value)
    return str(value)[:_MAX_TEXT]


def _parse_peer(target: Any) -> tuple[Optional[str], Optional[int]]:
    """`ip:port`, `[v6]:port`, bare `ip` -> (ip, port). (None, None) if not an IP."""
    if not isinstance(target, str) or not target.strip():
        return None, None
    raw = target.strip()
    if raw.startswith("["):
        host, _, rest = raw[1:].partition("]")
        port_s = rest.lstrip(":")
    elif raw.count(":") == 1:
        host, _, port_s = raw.partition(":")
    else:
        host, port_s = raw, ""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None, None
    port = int(port_s) if port_s.isdigit() and 0 < int(port_s) < 65536 else None
    return host, port


def _timestamp(data: dict) -> str:
    return str(_first(data.get("timestamp"), data.get("at"), datetime.utcnow().isoformat()))


def _base(data: dict, details: dict, event_type: str, default_host: str) -> dict:
    """Fields every endpoint event carries, whatever produced it."""
    own_ip = data.get("source_ip")
    return {
        "event_type": event_type,
        # Endpoint telemetry has no remote attacker: its subject is the HOST.
        # The 127.0.0.1 stamp only keeps source_ip-grouped rules from meeting
        # None; `host_only` marks it as a placeholder (see _on_rule_triggered).
        # An event that DOES carry its own source_ip is a real network
        # observation and keeps the IP gate.
        "source_ip": own_ip or "127.0.0.1",
        "host_only": not own_ip,
        "severity": data.get("severity") or "medium",
        "timestamp": _timestamp(data),
        "source": "edr",
        "agent_id": data.get("agent_id"),
        "hostname": _first(data.get("hostname"), data.get("agent_id"), default_host),
        "pid": _first(data.get("pid"), details.get("pid")),
        "ppid": _first(data.get("ppid"), details.get("ppid")),
        "username": _first(
            data.get("user"), data.get("username"), details.get("user"), details.get("username")
        ),
    }


def _process_fields(data: dict, details: dict) -> dict:
    """The acting process, under the names the rules read.

    node-tauri and host_monitor send process_name / process_path / command_line;
    the Python agent sends name / cmdline (a joined string) inside `details`.
    Legacy spellings (name, exe, cmdline) stay accepted for other producers.
    """
    return {
        "process_name": _text(_first(
            data.get("process_name"), data.get("name"),
            details.get("process_name"), details.get("name"),
        )),
        "process_path": _text(_first(
            data.get("process_path"), data.get("exe"),
            details.get("process_path"), details.get("exe"),
        )),
        "cmdline": _text(_first(
            data.get("command_line"), data.get("cmdline"),
            details.get("command_line"), details.get("cmdline"),
        )),
    }


def _network_event(data: dict, details: dict, base: dict) -> list[dict]:
    """A connection the endpoint OPENED, named after the remote peer.

    source_ip / destination_ip carry the remote peer, exactly as
    connection_monitor.build_event does, and for the same reason: the incident
    is opened against, and the responder blocks, the C2 server -- never the
    victim endpoint. The local address is kept as local_addr for the analyst and
    is never placed in a field a response action resolves a target from.

    Only outbound connections are translated. For an accepted connection the
    ETW `daddr` is not reliably the remote side, and naming the wrong side would
    put the customer's own address in source_ip.

    The engine drops peers that are internal or safelisted before evaluation
    (see CorrelationEngine._on_edr_event), via `_gate_ip`.
    """
    peer_raw = _first(data.get("target"), details.get("remote_addr"), data.get("remote_addr"))
    peer, port = _parse_peer(peer_raw)
    if peer is None:
        return []
    return [{
        **base,
        "event_type": "network_connection",
        "source_ip": peer,
        "host_only": False,
        "destination_ip": peer,
        "destination_port": port,
        "remote_ip": peer,
        "remote_port": port,
        "direction": "outbound",
        "protocol": "tcp",
        "local_addr": _first(details.get("local_addr"), data.get("local_addr")),
        **_process_fields(data, details),
        "_gate_ip": peer,
    }]


def _rdp_event(data: dict, details: dict, base: dict) -> list[dict]:
    """Successful Security 4624 logon type 10 from a remote address.

    The event stays host-only: a successful RDP login is not proof of an
    attacker (it is an admin at least as often), so it must never hand the
    responder an address to block. The address is kept as rdp_source_ip and is
    required, because the rule's premise is a login from an EXTERNAL address.
    """
    try:
        event_id = int(details.get("event_id"))
    except (TypeError, ValueError):
        return []
    if event_id != 4624:
        return []
    logon = str(details.get("logon_type") or "")
    if not (details.get("rdp_logon") is True or "RDP" in logon or "RemoteInteractive" in logon):
        return []
    strings = details.get("strings")
    if not isinstance(strings, list) or len(strings) <= _4624_ADDR:
        return []
    addr, _ = _parse_peer(str(strings[_4624_ADDR]))
    if addr is None:
        return []
    return [{
        **base,
        "event_type": "rdp_login",
        "auth_result": "success",
        "username": _first(str(strings[_4624_USER]) if len(strings) > _4624_USER else None,
                           base.get("username")),
        "rdp_source_ip": addr,
        "_gate_ip": addr,
    }]


def _canary_events(data: dict, details: dict, base: dict) -> list[dict]:
    """One canary_modified per canary_modified signal of a ransomware incident.

    The node-tauri ransomware module posts a forensic incident only after two or
    more signals correlated on the endpoint, so a canary signal inside it is
    evidence the agent already stood behind, not a raw filesystem event.
    """
    signals = details.get("signals")
    if not isinstance(signals, list):
        return []
    out = []
    for sig in signals:
        if not isinstance(sig, dict) or sig.get("kind") != "canary_modified":
            continue
        canary = _text(sig.get("detail"))
        out.append({
            **base,
            "event_type": "canary_modified",
            "severity": "critical",
            "path": canary,
            "canary_id": canary,
            "process_pid": details.get("process_pid"),
            "process_name": _text(details.get("process_name")),
            "process_path": _text(details.get("process_path")),
            "timestamp": str(_first(sig.get("at"), base["timestamp"])),
        })
    return out


def translate_edr_event(data: Any, *, default_host: str) -> list[dict]:
    """Endpoint payload -> events for CorrelationEngine.evaluate (may be empty)."""
    if not isinstance(data, dict):
        return []
    kind = data.get("kind") or data.get("type", "")
    mapped = EDR_EVENT_MAP.get(kind)
    if not mapped:
        return []
    details = data.get("details") if isinstance(data.get("details"), dict) else {}
    extra = data.get("extra") if isinstance(data.get("extra"), dict) else {}
    base = _base(data, details, mapped, default_host)

    if mapped == "network_connection":
        return _network_event(data, details, base)
    if mapped == "rdp_login":
        return _rdp_event(data, details, base)
    if mapped == "canary_modified":
        return _canary_events(data, details, base)
    if mapped == "connection":
        return [{**base, **_process_fields(data, details)}]

    proc = _process_fields(data, details)
    event = {**base, **proc}

    if mapped in ("process_creation", "process_termination"):
        event["path"] = proc["process_path"]
        if mapped == "process_termination":
            event["cmdline"] = ""
        return [event]

    if kind == "fim" and details.get("event_type") in _FIM_EVENT_TYPE:
        event["event_type"] = _FIM_EVENT_TYPE[details["event_type"]]

    if mapped == "service_install":
        event["service_name"] = _text(_first(extra.get("service_name"), details.get("service_name")))
        event["service_path"] = _text(_first(extra.get("service_path"), details.get("service_path")))
        event["path"] = event["service_path"]
        return [event]

    if mapped in ("registry_modification", "registry_deletion"):
        event["path"] = _text(_first(data.get("target"), details.get("key")))
        event["registry_value"] = _text(_first(extra.get("value"), details.get("value")))
        return [event]

    if mapped == "dll_load":
        # ETW reports the loaded image as ImageName -> process_path.
        event["path"] = _text(_first(data.get("target"), proc["process_path"]))
        return [event]

    # file_*: the file is `target` (node-tauri), `file_path` (Python agent) or
    # `path` (host_monitor). A process path is NOT a fallback: a file event that
    # cannot say which file must not match path rules on the actor's exe.
    event["path"] = _text(_first(
        data.get("target"), data.get("path"), data.get("file_path"),
        details.get("file_path"), details.get("path"),
    ))
    return [event] if event["path"] else []

