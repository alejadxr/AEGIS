"""Real endpoint-agent payload shapes, and the real ingest routes to push them through.

The wire dicts below are what each agent POSTs (field names taken from
node-tauri src-tauri/src/edr/mod.rs, ransomware/mod.rs and lib.rs, and from
agent/aegis_agent.py). `through_*` run the REAL route function against a fake DB
and return what it handed to the correlation engine (the `edr.event_batch`
payload), so tests exercise agent JSON -> route -> translator -> rule.

Hostnames and addresses are RFC 5737 / example.test only.
"""
from __future__ import annotations

import asyncio
import gzip
import json
from types import SimpleNamespace

HOST = "ws-finance-01.example.test"
AGENT_ID = "agent-0001"
CLIENT_ID = "client-0001"

C2_PEER = "198.51.100.77"      # remote peer of an outbound connection (test-net)
LOCAL_ADDR = "203.0.113.25"    # the endpoint's own address: must never be a target


class Bus:
    def __init__(self):
        self.published: list[tuple[str, dict]] = []

    async def publish(self, topic, data=None, *a, **k):
        self.published.append((topic, data))

    publish_critical = publish
    publish_high = publish

    def subscribe(self, *a, **k):
        pass

    def batches(self) -> list[dict]:
        return [d for t, d in self.published if t == "edr.event_batch"]


# ---------------------------------------------------------------------------
# node-tauri POST /edr/events
# ---------------------------------------------------------------------------

def tauri_event(kind, *, pid=4242, ppid=1000, name=None, path=None, cmd=None,
                user="EXAMPLE\\jdoe", target=None, extra=None):
    return {
        "kind": kind, "at": "2026-09-29T10:00:00Z", "pid": pid, "ppid": ppid,
        "process_name": name, "process_path": path, "command_line": cmd,
        "user": user, "target": target, "extra": extra if extra is not None else None,
    }


VSSADMIN = tauri_event(
    "process_start", name="vssadmin.exe",
    path="C:\\Windows\\System32\\vssadmin.exe",
    cmd="vssadmin.exe delete shadows /all /quiet")
PS_ENC = tauri_event(
    "process_start", name="powershell.exe",
    path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    cmd="powershell.exe -NoProfile -WindowStyle Hidden -enc "
        "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA")
PS_BENIGN = tauri_event(
    "process_start", name="powershell.exe",
    path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    cmd="powershell.exe -ExecutionPolicy Bypass -File C:\\ops\\rotate-logs.ps1")
CHROME = tauri_event(
    "process_start", name="chrome.exe",
    path="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    cmd="chrome.exe --type=renderer --enable-features=NetworkService")
VSSADMIN_EXIT = tauri_event("process_stop", name="vssadmin.exe",
                            path="C:\\Windows\\System32\\vssadmin.exe")
FILE_STARTUP = tauri_event(
    "file_create", pid=812, ppid=None, name="dropper.exe", path=None,
    target="C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\"
           "Programs\\Startup\\updater.exe",
    extra={"source": "etw_kernel_file"})
FILE_BENIGN = tauri_event(
    "file_write", pid=812, ppid=None, target="C:\\Users\\jdoe\\Documents\\notes.txt",
    extra={"source": "etw_kernel_file"})
REG_RUN = tauri_event(
    "registry_set", pid=None, ppid=None,
    target="\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
    extra={"source": "etw_kernel_registry", "value": "Updater"})
REG_BENIGN = tauri_event(
    "registry_set", pid=None, ppid=None,
    target="\\REGISTRY\\USER\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
    extra={"source": "etw_kernel_registry", "value": "a"})
REG_DELETE = tauri_event(
    "registry_delete", pid=None, ppid=None,
    target="\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\OldTool",
    extra={"source": "etw_kernel_registry", "value": "OldTool"})
DLL_TEMP = tauri_event(
    "image_load", pid=900, name="evil.dll",
    path="C:\\Users\\jdoe\\AppData\\Local\\Temp\\evil.dll",
    extra={"source": "etw_kernel_process"})
DLL_BENIGN = tauri_event(
    "image_load", pid=900, name="kernel32.dll",
    path="C:\\Windows\\System32\\kernel32.dll", extra={"source": "etw_kernel_process"})
TCP_IRC = tauri_event("tcp_connect", pid=910, ppid=None,
                      target=f"{C2_PEER}:6667", extra={"source": "etw_kernel_network"})
TCP_HTTPS = tauri_event("tcp_connect", pid=910, ppid=None,
                        target=f"{C2_PEER}:443", extra={"source": "etw_kernel_network"})
TCP_LAN_IRC = tauri_event("tcp_connect", pid=910, ppid=None,
                          target="10.20.30.40:6667", extra={"source": "etw_kernel_network"})
TCP_ACCEPT = tauri_event("tcp_accept", pid=910, ppid=None,
                         target=f"{LOCAL_ADDR}:6667", extra={"source": "etw_kernel_network"})


# ---------------------------------------------------------------------------
# Python agent POST /agents/events  (EventItem: category/severity/title/details)
# ---------------------------------------------------------------------------

def py_event(category, severity, title, details):
    return {"category": category, "severity": severity, "title": title,
            "details": details, "timestamp": "2026-09-29T10:00:00"}


PY_PROC_SSH_TUNNEL = py_event(
    "process", "info", "New process: ssh (PID 3100)",
    {"pid": 3100, "name": "ssh", "cmdline": "ssh -N -L 8080:10.0.0.5:80 jump.example.test",
     "username": "jdoe", "cpu_percent": 0.0, "memory_percent": 0.1,
     "create_time": 1_790_000_000.0, "ppid": 1, "connections": []})
PY_PROC_SSH_PLAIN = py_event(
    "process", "info", "New process: ssh (PID 3101)",
    {"pid": 3101, "name": "ssh", "cmdline": "ssh -l jdoe jump.example.test",
     "username": "jdoe", "ppid": 1, "connections": []})
PY_PROC_LS = py_event(
    "process", "info", "New process: ls (PID 3102)",
    {"pid": 3102, "name": "ls", "cmdline": "ls -l -R -D /home", "username": "jdoe",
     "ppid": 1, "connections": []})
PY_FIM_CRON = py_event(
    "fim", "high", "File created: /etc/cron.d/backdoor",
    {"file_path": "/etc/cron.d/backdoor", "event_type": "created",
     "hash_before": "", "hash_after": "0" * 64})
PY_FIM_CRON_DELETED = py_event(
    "fim", "high", "File deleted: /etc/cron.d/backdoor",
    {"file_path": "/etc/cron.d/backdoor", "event_type": "deleted",
     "hash_before": "0" * 64, "hash_after": ""})
PY_FIM_BENIGN = py_event(
    "fim", "low", "File modified: /home/jdoe/notes.txt",
    {"file_path": "/home/jdoe/notes.txt", "event_type": "modified",
     "hash_before": "1" * 64, "hash_after": "2" * 64})
PY_NET_TOR = py_event(
    "network", "info", f"New outbound connection: curl -> {C2_PEER}:9001",
    {"local_addr": f"{LOCAL_ADDR}:51000", "remote_addr": f"{C2_PEER}:9001",
     "pid": 3200, "process_name": "curl", "status": "ESTABLISHED"})
PY_NET_LISTEN = py_event(
    "network", "medium", "New listening port: 0.0.0.0:6667 (ircd)",
    {"local_addr": "0.0.0.0:6667", "pid": 3201, "process_name": "ircd", "status": "LISTEN"})


def py_win_4624(address, logon="RemoteInteractive (RDP)", rdp=True):
    strings = ["S-1-5-18", "WS-FINANCE-01$", "EXAMPLE", "0x3e7", "S-1-5-21-1", "jdoe",
               "EXAMPLE", "0x1a2b3c", "10", "User32", "Negotiate", "WS-FINANCE-01",
               "{00000000-0000-0000-0000-000000000000}", "-", "-", "0", "1234",
               "C:\\Windows\\System32\\svchost.exe", address, "0"]
    details = {"event_id": 4624, "event_name": "Successful Logon",
               "time_generated": "2026-09-29 10:00:00", "source": "Microsoft-Windows-Security-Auditing",
               "computer": "WS-FINANCE-01", "strings": strings, "logon_type": logon}
    if rdp:
        details["rdp_logon"] = True
    return py_event("windows_event", "info", "Windows Event 4624: Successful Logon", details)


PY_RDP_EXTERNAL = py_win_4624(C2_PEER)
PY_RDP_INTERNAL = py_win_4624("10.20.30.40")
PY_CONSOLE_LOGON = py_win_4624("-", logon="Interactive (console)", rdp=False)

# node-tauri ransomware module: POST /agents/events, category "forensic"
FORENSIC_CANARY = py_event(
    "forensic", "critical", "Ransomware activity detected (pid=Some(4321), 2 signals)",
    {"node_id": AGENT_ID, "detected_at": "2026-09-29T10:00:00+00:00",
     "process_pid": 4321, "process_name": "locker.exe",
     "process_path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\locker.exe",
     "signals": [
         {"kind": "entropy_spike", "detail": "entropy 7.9 on 40 files", "at": "2026-09-29T10:00:00+00:00"},
         {"kind": "canary_modified", "detail": "C:\\Users\\jdoe\\Documents\\.aegis-canary.docx",
          "at": "2026-09-29T10:00:00+00:00"}],
     "affected_files": [], "killed_pids": [4321], "rollback_status": "unsupported_platform",
     "rollback_files_restored": 0, "severity": "critical"})
FORENSIC_NO_CANARY = py_event(
    "forensic", "critical", "Ransomware activity detected (pid=Some(4321), 2 signals)",
    {"node_id": AGENT_ID, "process_pid": 4321, "process_name": "locker.exe",
     "signals": [
         {"kind": "entropy_spike", "detail": "entropy 7.9", "at": "2026-09-29T10:00:00+00:00"},
         {"kind": "shadow_copy_deletion", "detail": "vssadmin", "at": "2026-09-29T10:00:00+00:00"}]})

# node-tauri POST /nodes/events
NODE_REGISTRY = {
    "node_id": AGENT_ID, "event_type": "registry_persistence_new", "severity": "high",
    "details": {"key": "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                "value": 'String("C:\\\\Users\\\\jdoe\\\\updater.exe")', "hive": "HKCU"},
    "timestamp": "2026-09-29T10:00:00+00:00"}
NODE_PSEXEC = {
    "node_id": AGENT_ID, "event_type": "new_service_installed", "severity": "medium",
    "details": {"event_id": 4697, "service_name": "PSEXESVC",
                "service_path": "%SystemRoot%\\PSEXESVC.exe", "source": "Security"},
    "timestamp": "2026-09-29T10:00:00+00:00"}
NODE_SERVICE_BENIGN = {
    "node_id": AGENT_ID, "event_type": "new_service_installed", "severity": "medium",
    "details": {"event_id": 4697, "service_name": "Spooler2",
                "service_path": "C:\\Windows\\System32\\spoolsv.exe", "source": "Security"},
    "timestamp": "2026-09-29T10:00:00+00:00"}


# ---------------------------------------------------------------------------
# Real routes, fake DB
# ---------------------------------------------------------------------------

class _Result:
    def __init__(self, agent):
        self._agent = agent

    def first(self):
        return self._agent

    def scalar_one_or_none(self):
        return self._agent


class FakeDB:
    def __init__(self, agent):
        self.agent = agent
        self.rows: list = []

    async def get(self, _model, _id):
        return self.agent

    async def execute(self, *_a, **_k):
        return _Result(self.agent)

    def add(self, row):
        self.rows.append(row)

    async def commit(self):
        pass


def agent_row():
    return SimpleNamespace(id=AGENT_ID, client_id=CLIENT_ID, hostname=HOST, ip_address=LOCAL_ADDR)


class _FakeRequest:
    def __init__(self, payload: dict, gz: bool = False):
        raw = json.dumps(payload).encode()
        self._raw = gzip.compress(raw) if gz else raw
        self.headers = {"content-encoding": "gzip"} if gz else {}

    async def body(self):
        return self._raw


def through_tauri_route(monkeypatch, events: list[dict]) -> dict:
    """POST /edr/events -> the batch handed to the engine."""
    from app.api import edr as edr_api
    from app.services import edr_transport

    bus = Bus()
    monkeypatch.setattr(edr_transport, "event_bus", bus)
    monkeypatch.setattr(edr_api, "event_bus", bus)

    async def _no_chains(*a, **k):
        return []
    monkeypatch.setattr(edr_api, "evaluate_event", _no_chains)
    payload = {"agent_id": AGENT_ID, "events_dropped_total": 0, "events": events}
    asyncio.run(edr_api.ingest_events(
        _FakeRequest(payload), db=FakeDB(agent_row()), auth=SimpleNamespace(client_id=CLIENT_ID)))
    return bus.batches()[0] if bus.batches() else {"events": []}


def through_python_route(monkeypatch, events: list[dict]) -> dict:
    """POST /agents/events -> the batch handed to the engine."""
    from app.api import agents as agents_api
    from app.services import edr_transport

    bus = Bus()
    monkeypatch.setattr(edr_transport, "event_bus", bus)
    monkeypatch.setattr(agents_api, "event_bus", bus)
    body = agents_api.EventBatchRequest(agent_id=AGENT_ID, events=events)
    auth = SimpleNamespace(client=SimpleNamespace(id=CLIENT_ID))
    asyncio.run(agents_api.ingest_events(body, auth=auth, db=FakeDB(agent_row())))
    return bus.batches()[0] if bus.batches() else {"events": []}


def through_nodes_route(monkeypatch, payload: dict) -> tuple[dict, FakeDB]:
    """POST /nodes/events -> (batch handed to the engine, the fake db)."""
    from app.api import nodes as nodes_api
    from app.services import edr_transport

    bus = Bus()
    monkeypatch.setattr(edr_transport, "event_bus", bus)
    nodes_api._node_event_seen.clear()
    db = FakeDB(agent_row())
    asyncio.run(nodes_api.receive_node_event(nodes_api.NodeEventRequest(**payload), db=db))
    return (bus.batches()[0] if bus.batches() else {"events": []}), db


# Every wire payload above, by producer, for tests that need "what can arrive".
TAURI_SAMPLES = [VSSADMIN, PS_ENC, PS_BENIGN, CHROME, VSSADMIN_EXIT, FILE_STARTUP, FILE_BENIGN,
                 REG_RUN, REG_BENIGN, REG_DELETE, DLL_TEMP, DLL_BENIGN, TCP_IRC, TCP_HTTPS, TCP_LAN_IRC,
                 TCP_ACCEPT]
PY_SAMPLES = [PY_PROC_SSH_TUNNEL, PY_PROC_SSH_PLAIN, PY_PROC_LS, PY_FIM_CRON, PY_FIM_CRON_DELETED,
              PY_FIM_BENIGN, PY_NET_TOR, PY_NET_LISTEN, PY_RDP_EXTERNAL, PY_RDP_INTERNAL,
              PY_CONSOLE_LOGON, FORENSIC_CANARY, FORENSIC_NO_CANARY]
NODE_SAMPLES = [NODE_REGISTRY, NODE_PSEXEC, NODE_SERVICE_BENIGN]


def all_bus_events() -> list[dict]:
    """Every sample as the correlation engine receives it (routes really run)."""
    import pytest

    out: list[dict] = []
    with pytest.MonkeyPatch.context() as mp:
        out += through_tauri_route(mp, TAURI_SAMPLES)["events"]
        out += through_python_route(mp, PY_SAMPLES)["events"]
        for payload in NODE_SAMPLES:
            out += through_nodes_route(mp, payload)[0]["events"]
    return out
