"""Unit tests for lateral movement Sigma rules (Task T4).

Rules under test:
  - ransomware_rdp_then_encrypt  (rdp_login, count_threshold=1, filter auth_result=success)
  - ransomware_smb_lateral       (smb_write, count_threshold=20, group_by source_ip)
  - ransomware_winrm_exec        (process_create, count_threshold=1, group_by hostname)

Design note — rdp_then_encrypt:
  The plan (§R-A.2.10) proposed a composite event_type combining rdp_login +
  mass file-extension change. Inspection of app/schemas/rule.py confirms that
  RuleCondition.event_type is a plain str — there is no composite/required_events
  schema support at the per-Rule level. That capability is exclusive to ChainRule.
  Therefore this rule is authored as a simple rdp_login detector (the RDP-login leg
  only), and the composite correlation is delegated to the ransomware_chain rule
  written by T5, which references both ransomware_rdp_then_encrypt and
  ransomware_extension_mass_change in its chain steps.
"""
from __future__ import annotations

import re
import time
from collections import deque, defaultdict
from pathlib import Path

import pytest

RULES_PATH = Path(__file__).parent.parent.parent / "app" / "rules"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def pack():
    from app.services.rules_loader import load_rules
    return load_rules(RULES_PATH)


def _make_engine():
    from app.services.correlation_engine import CorrelationEngine
    from app.services.rules_loader import load_rules

    engine = CorrelationEngine.__new__(CorrelationEngine)
    engine.MAX_EVENTS = 10_000
    engine.COOLDOWN_SECONDS = 60
    engine._window = deque(maxlen=engine.MAX_EVENTS)
    engine._fired = {}
    engine._chain_fired = {}
    engine._sigma_fire_log = defaultdict(list)
    engine._stats = {
        "events_processed": 0,
        "rules_triggered": 0,
        "chains_triggered": 0,
        "custom_rules": 0,
        "started_at": "",
    }
    engine._event_bus = None
    engine._watcher = None
    pack = load_rules(RULES_PATH)
    engine._rule_pack = pack
    engine._rules = [r for rules in pack.rules.values() for r in rules]
    engine._chain_rules = list(pack.chains)
    engine._rules_by_type = engine._build_type_index(engine._rules)
    return engine


# ---------------------------------------------------------------------------
# Rule loading — schema assertions
# ---------------------------------------------------------------------------

def test_rdp_then_encrypt_loads(pack):
    assert "ransomware_rdp_then_encrypt" in pack.by_id


def test_smb_lateral_loads(pack):
    assert "ransomware_smb_lateral" in pack.by_id


def test_winrm_exec_loads(pack):
    assert "ransomware_winrm_exec" in pack.by_id


def test_rdp_then_encrypt_fields(pack):
    rule = pack.by_id["ransomware_rdp_then_encrypt"]
    assert rule["severity"] == "critical"
    assert "T1133" in rule["techniques"]
    assert "T1021.001" in rule["techniques"]
    cond = rule["condition"]
    assert cond.get("event_type") == "rdp_login"
    assert cond["count_threshold"] == 1
    assert cond.get("group_by") == "hostname"


def test_smb_lateral_fields(pack):
    rule = pack.by_id["ransomware_smb_lateral"]
    assert rule["severity"] == "high"
    assert "T1021.002" in rule["techniques"]
    cond = rule["condition"]
    assert cond.get("event_type") == "smb_write"
    assert cond["count_threshold"] == 20
    assert cond.get("time_window_seconds") == 60
    assert cond.get("group_by") == "source_ip"


def test_winrm_exec_fields(pack):
    rule = pack.by_id["ransomware_winrm_exec"]
    assert rule["severity"] == "high"
    assert "T1021.006" in rule["techniques"]
    assert "T1059" in rule["techniques"]
    cond = rule["condition"]
    assert cond.get("event_type") == "process_create"
    assert cond["count_threshold"] == 1
    assert cond.get("group_by") == "hostname"


# ---------------------------------------------------------------------------
# Event-type index assertions
# ---------------------------------------------------------------------------

def test_rdp_then_encrypt_in_event_index(pack):
    ids = [r["id"] for r in pack.rules.get("rdp_login", [])]
    assert "ransomware_rdp_then_encrypt" in ids


def test_smb_lateral_in_event_index(pack):
    ids = [r["id"] for r in pack.rules.get("smb_write", [])]
    assert "ransomware_smb_lateral" in ids


def test_winrm_exec_in_event_index(pack):
    ids = [r["id"] for r in pack.rules.get("process_create", [])]
    assert "ransomware_winrm_exec" in ids


# ---------------------------------------------------------------------------
# rdp_then_encrypt — engine evaluation
# ---------------------------------------------------------------------------

def _rdp_event(auth_result: str = "success", source_ip: str = "203.0.113.5") -> dict:
    return {
        "event_type": "rdp_login",
        "hostname": "victim-host",
        "username": "administrator",
        "source_ip": source_ip,
        "auth_result": auth_result,
        "timestamp": time.time(),
    }


def test_rdp_fires_on_successful_login():
    """A single rdp_login with auth_result=success trips the rule."""
    eng = _make_engine()
    rule = eng._rule_pack.by_id["ransomware_rdp_then_encrypt"]
    now = time.time()

    event = _rdp_event(auth_result="success")
    eng._window.append((now, event))
    assert eng._check_rule(rule, event, now)


def test_rdp_no_fire_on_failed_login():
    """A failed RDP login (auth_result=failure) should NOT trip the rule."""
    eng = _make_engine()
    rule = eng._rule_pack.by_id["ransomware_rdp_then_encrypt"]
    now = time.time()

    event = _rdp_event(auth_result="failure")
    eng._window.append((now, event))
    assert not eng._check_rule(rule, event, now)


def test_rdp_no_fire_on_wrong_event_type():
    """An auth_success event (not rdp_login) must not trip the rdp rule."""
    eng = _make_engine()
    rule = eng._rule_pack.by_id["ransomware_rdp_then_encrypt"]
    now = time.time()

    event = {"event_type": "auth_success", "hostname": "victim-host", "timestamp": now}
    eng._window.append((now, event))
    assert not eng._check_rule(rule, event, now)


# ---------------------------------------------------------------------------
# smb_lateral — count threshold and group_by isolation
# ---------------------------------------------------------------------------

def _smb_event(source_ip: str = "10.0.0.50", share: str = r"\\server\C$") -> dict:
    return {
        "event_type": "smb_write",
        "source_ip": source_ip,
        "target_share": share,
        "hostname": "fileserver-1",
        "bytes_written": 1024,
        "timestamp": time.time(),
    }


def test_smb_lateral_fires_at_threshold():
    """20 smb_write events from the same source_ip trips the rule."""
    eng = _make_engine()
    rule = eng._rule_pack.by_id["ransomware_smb_lateral"]
    now = time.time()

    for _ in range(20):
        eng._window.append((now, _smb_event(source_ip="192.168.1.99")))

    assert eng._check_rule(rule, _smb_event(source_ip="192.168.1.99"), now)


def test_smb_lateral_no_fire_below_threshold():
    """19 smb_write events must NOT trip the rule (threshold is 20)."""
    eng = _make_engine()
    rule = eng._rule_pack.by_id["ransomware_smb_lateral"]
    now = time.time()

    for _ in range(19):
        eng._window.append((now, _smb_event(source_ip="192.168.1.77")))

    assert not eng._check_rule(rule, _smb_event(source_ip="192.168.1.77"), now)


def test_smb_lateral_isolates_by_source_ip():
    """Events from two different IPs (10 each) must not combine to trip the rule."""
    eng = _make_engine()
    rule = eng._rule_pack.by_id["ransomware_smb_lateral"]
    now = time.time()

    for _ in range(10):
        eng._window.append((now, _smb_event(source_ip="192.168.1.11")))
    for _ in range(10):
        eng._window.append((now, _smb_event(source_ip="192.168.1.22")))

    assert not eng._check_rule(rule, _smb_event(source_ip="192.168.1.11"), now)
    assert not eng._check_rule(rule, _smb_event(source_ip="192.168.1.22"), now)


def test_smb_lateral_no_fire_on_wrong_event_type():
    """smb_access events (not smb_write) must not trip this rule."""
    eng = _make_engine()
    rule = eng._rule_pack.by_id["ransomware_smb_lateral"]
    now = time.time()

    # Fill window with smb_access events
    for _ in range(20):
        eng._window.append((now, {
            "event_type": "smb_access",
            "source_ip": "192.168.1.55",
            "timestamp": now,
        }))

    wrong_type_event = {
        "event_type": "smb_access",
        "source_ip": "192.168.1.55",
        "timestamp": now,
    }
    assert not eng._check_rule(rule, wrong_type_event, now)


# ---------------------------------------------------------------------------
# winrm_exec — single-event trip, filter enforcement
# ---------------------------------------------------------------------------

def _winrm_event(
    process_path: str = r"C:\Windows\System32\wsmprovhost.exe",
    parent: str = r"C:\Windows\System32\svchost.exe",
) -> dict:
    return {
        "event_type": "process_create",
        "hostname": "lateral-target",
        "username": "SYSTEM",
        "process_path": process_path,
        "parent_process_path": parent,
        "command_line": "-Embedding",
        "timestamp": time.time(),
    }


def test_winrm_fires_on_single_wsmprovhost():
    """One process_create for wsmprovhost trips the rule immediately."""
    eng = _make_engine()
    rule = eng._rule_pack.by_id["ransomware_winrm_exec"]
    now = time.time()

    event = _winrm_event()
    eng._window.append((now, event))
    assert eng._check_rule(rule, event, now)


def test_winrm_no_fire_on_wrong_event_type():
    """A connection event (not process_create) must not trip the winrm rule."""
    eng = _make_engine()
    rule = eng._rule_pack.by_id["ransomware_winrm_exec"]
    now = time.time()

    event = {"event_type": "connection", "hostname": "lateral-target", "timestamp": now}
    eng._window.append((now, event))
    assert not eng._check_rule(rule, event, now)


# ---------------------------------------------------------------------------
# customDetails — regex patterns stored for EDR/agent layer enforcement
# ---------------------------------------------------------------------------

def test_winrm_custom_details_has_process_path_regex(pack):
    rule = pack.by_id["ransomware_winrm_exec"]
    assert "process_path_regex" in rule["customDetails"]
    assert "wsmprovhost" in rule["customDetails"]["process_path_regex"]


def test_winrm_custom_details_has_parent_process_regex(pack):
    rule = pack.by_id["ransomware_winrm_exec"]
    assert "parent_process_regex" in rule["customDetails"]
    assert "svchost" in rule["customDetails"]["parent_process_regex"]


def test_smb_custom_details_has_target_share_regex(pack):
    rule = pack.by_id["ransomware_smb_lateral"]
    assert "target_share_regex" in rule["customDetails"]
    assert r"C\$" in rule["customDetails"]["target_share_regex"]


def test_rdp_filter_has_auth_result(pack):
    rule = pack.by_id["ransomware_rdp_then_encrypt"]
    filt = rule["condition"].filter
    assert filt.get("auth_result") == "success"


# ---------------------------------------------------------------------------
# Regex pattern correctness — validate patterns against expected input
# ---------------------------------------------------------------------------

SMB_SHARE_REGEX = re.compile(r'(?i)\\(C\$|ADMIN\$|IPC\$)')
WINRM_PROC_REGEX = re.compile(r'(?i)wsmprovhost\.exe')
WINRM_PARENT_REGEX = re.compile(r'(?i)svchost\.exe')


@pytest.mark.parametrize("share,should_match", [
    (r"\\server\C$", True),
    (r"\\server\ADMIN$", True),
    (r"\\server\IPC$", True),
    (r"\\server\ADMIN$\path", True),
    (r"\\server\Users", False),
    (r"\\server\shared", False),
])
def test_smb_share_regex_patterns(share: str, should_match: bool):
    matched = bool(SMB_SHARE_REGEX.search(share))
    assert matched == should_match, f"Share '{share}': expected {should_match}, got {matched}"


@pytest.mark.parametrize("proc,should_match", [
    (r"C:\Windows\System32\wsmprovhost.exe", True),
    (r"C:\Windows\SysWOW64\wsmprovhost.exe", True),
    (r"wsmprovhost.exe", True),
    (r"C:\Windows\System32\cmd.exe", False),
    (r"C:\Windows\System32\powershell.exe", False),
])
def test_winrm_process_regex_patterns(proc: str, should_match: bool):
    matched = bool(WINRM_PROC_REGEX.search(proc))
    assert matched == should_match, f"Process '{proc}': expected {should_match}, got {matched}"
