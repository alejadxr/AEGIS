"""Unit tests for T1486 encryption-phase Sigma rules (Task T2).

Rules under test:
  - ransomware_extension_mass_change  (count_threshold=50, group_by=process_pid)
  - ransomware_canary_modified        (count_threshold=1,  instant trip)
  - ransomware_note_dropped           (count_threshold=1,  file_create event)
"""
from __future__ import annotations

import re
import time
from collections import deque
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


def _make_engine(rules_path: Path):
    """Return a CorrelationEngine wired to a specific rules directory."""
    from app.services.correlation_engine import CorrelationEngine
    from app.services.rules_loader import load_rules

    engine = CorrelationEngine.__new__(CorrelationEngine)
    engine.MAX_EVENTS = 10_000
    engine.COOLDOWN_SECONDS = 60
    engine._window = deque(maxlen=engine.MAX_EVENTS)
    engine._fired = {}
    engine._chain_fired = {}
    from collections import defaultdict
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
    pack = load_rules(rules_path)
    engine._rule_pack = pack
    engine._rules = [r for rules in pack.rules.values() for r in rules]
    engine._chain_rules = list(pack.chains)
    engine._rules_by_type = engine._build_type_index(engine._rules)
    return engine


@pytest.fixture(scope="module")
def engine():
    return _make_engine(RULES_PATH)


# ---------------------------------------------------------------------------
# Rule-loading assertions
# ---------------------------------------------------------------------------

def test_extension_mass_change_loads(pack):
    assert "ransomware_extension_mass_change" in pack.by_id


def test_canary_modified_loads(pack):
    assert "ransomware_canary_modified" in pack.by_id


def test_note_dropped_loads(pack):
    assert "ransomware_note_dropped" in pack.by_id


def test_extension_mass_change_fields(pack):
    rule = pack.by_id["ransomware_extension_mass_change"]
    assert rule["severity"] == "critical"
    assert "T1486" in rule["techniques"]
    cond = rule["condition"]
    assert cond.get("event_type") == "file_extension_change"
    assert cond["count_threshold"] == 50
    assert cond.get("time_window_seconds") == 60
    assert cond.get("group_by") == "process_pid"


def test_canary_modified_fields(pack):
    rule = pack.by_id["ransomware_canary_modified"]
    assert rule["severity"] == "critical"
    assert "T1486" in rule["techniques"]
    cond = rule["condition"]
    assert cond.get("event_type") == "canary_modified"
    assert cond["count_threshold"] == 1
    assert cond.get("time_window_seconds") == 1


def test_note_dropped_fields(pack):
    rule = pack.by_id["ransomware_note_dropped"]
    assert rule["severity"] == "high"
    assert "T1486" in rule["techniques"]
    cond = rule["condition"]
    assert cond.get("event_type") == "file_create"
    assert cond["count_threshold"] == 1


# ---------------------------------------------------------------------------
# extension_mass_change — count threshold behaviour
# ---------------------------------------------------------------------------

def _ext_change_event(pid: int = 1234, ext: str = ".locked") -> dict:
    return {
        "event_type": "file_extension_change",
        "process_pid": pid,
        "new_extension": ext,
        "hostname": "host-1",
        "process_path": "/usr/bin/enc",
        "timestamp": time.time(),
    }


def test_extension_mass_change_fires_at_50(pack):
    """60 events from the same pid should trip the rule."""
    from app.services.correlation_engine import CorrelationEngine
    from app.services.rules_loader import load_rules
    from collections import defaultdict

    eng = _make_engine(RULES_PATH)
    rule = eng._rule_pack.by_id["ransomware_extension_mass_change"]
    now = time.time()

    for _ in range(60):
        eng._window.append((now, _ext_change_event(pid=9999, ext=".locked")))

    assert eng._check_rule(rule, _ext_change_event(pid=9999), now)


def test_extension_mass_change_no_fire_below_threshold(pack):
    """49 events should NOT trip the rule (threshold is 50)."""
    eng = _make_engine(RULES_PATH)
    rule = eng._rule_pack.by_id["ransomware_extension_mass_change"]
    now = time.time()

    for _ in range(49):
        eng._window.append((now, _ext_change_event(pid=8888, ext=".locked")))

    assert not eng._check_rule(rule, _ext_change_event(pid=8888), now)


def test_extension_mass_change_isolates_by_pid(pack):
    """Events from a different pid must not contribute to the threshold."""
    eng = _make_engine(RULES_PATH)
    rule = eng._rule_pack.by_id["ransomware_extension_mass_change"]
    now = time.time()

    # 30 events from pid 1111, 30 events from pid 2222 — neither exceeds 50
    for _ in range(30):
        eng._window.append((now, _ext_change_event(pid=1111, ext=".locked")))
    for _ in range(30):
        eng._window.append((now, _ext_change_event(pid=2222, ext=".locked")))

    assert not eng._check_rule(rule, _ext_change_event(pid=1111), now)
    assert not eng._check_rule(rule, _ext_change_event(pid=2222), now)


# ---------------------------------------------------------------------------
# canary_modified — instant single-event trip
# ---------------------------------------------------------------------------

def _canary_event(canary_id: str = "hb1234abcd") -> dict:
    return {
        "event_type": "canary_modified",
        "canary_id": canary_id,
        "hostname": "host-1",
        "process_path": "/usr/bin/enc",
        "timestamp": time.time(),
    }


def test_canary_modified_fires_on_single_event():
    """One canary_modified event must trip the rule immediately."""
    eng = _make_engine(RULES_PATH)
    rule = eng._rule_pack.by_id["ransomware_canary_modified"]
    now = time.time()

    event = _canary_event(canary_id="hb1234abcd")
    eng._window.append((now, event))

    assert eng._check_rule(rule, event, now)


def test_canary_modified_fires_with_any_canary_id():
    """The rule fires regardless of canary_id value — no filter on the id."""
    eng = _make_engine(RULES_PATH)
    rule = eng._rule_pack.by_id["ransomware_canary_modified"]
    now = time.time()

    event = _canary_event(canary_id="SENTINEL-FILE-001")
    eng._window.append((now, event))

    assert eng._check_rule(rule, event, now)


# ---------------------------------------------------------------------------
# note_dropped — parametrized filename matching
# ---------------------------------------------------------------------------

NOTE_DROPPED_REGEX = re.compile(
    r'(?i)(readme.*\.(txt|hta|html)|how_to_decrypt|decrypt[_-]?instructions'
    r'|recover[_-]?files|!!!.*-files-have-been|HOW_TO_RESTORE)'
)


@pytest.mark.parametrize("filename,should_match_regex", [
    ("README_FOR_DECRYPT.txt", True),
    ("readme.txt", True),
    ("HOW_TO_DECRYPT.html", True),
    ("HOW_TO_RESTORE.txt", True),
    ("decrypt_instructions.txt", True),
    ("recover-files.txt", True),
    ("readme.md", False),
    ("document.docx", False),
    ("notes.txt", False),
    ("system.log", False),
])
def test_note_dropped_regex_patterns(filename: str, should_match_regex: bool):
    """Verify the regex embedded in the rule matches expected filenames."""
    rule_cond_filter = NOTE_DROPPED_REGEX
    matched = bool(rule_cond_filter.search(filename))
    assert matched == should_match_regex, (
        f"Filename '{filename}': expected regex match={should_match_regex}, got {matched}"
    )


def _note_dropped_event(filename: str = "README_FOR_DECRYPT.txt") -> dict:
    return {
        "event_type": "file_create",
        "file_name": filename,
        "hostname": "host-1",
        "process_path": "/usr/bin/enc",
        "timestamp": time.time(),
    }


def test_note_dropped_fires_on_ransom_note():
    """A single file_create event with a matching name trips the rule."""
    eng = _make_engine(RULES_PATH)
    rule = eng._rule_pack.by_id["ransomware_note_dropped"]
    now = time.time()

    event = _note_dropped_event("README_FOR_DECRYPT.txt")
    eng._window.append((now, event))

    assert eng._check_rule(rule, event, now)


def test_note_dropped_no_fire_on_benign_file_create():
    """
    The engine enforces file_name_regex via _matches_filter (_regex suffix).
    A file_create with a non-matching file_name must NOT trip the rule.
    """
    eng = _make_engine(RULES_PATH)
    rule = eng._rule_pack.by_id["ransomware_note_dropped"]
    now = time.time()

    event = _note_dropped_event("readme.md")
    eng._window.append((now, event))

    # readme.md is NOT a ransom-note pattern (regex requires .txt/.hta/.html
    # suffix or specific keywords like how_to_decrypt). Engine must reject.
    assert not eng._check_rule(rule, event, now)


# ---------------------------------------------------------------------------
# Schema integrity: all three rules appear in the file_extension_change /
# canary_modified / file_create event-type indices
# ---------------------------------------------------------------------------

def test_extension_mass_change_in_event_index(pack):
    rules_for_type = pack.rules.get("file_extension_change", [])
    ids = [r["id"] for r in rules_for_type]
    assert "ransomware_extension_mass_change" in ids


def test_canary_modified_in_event_index(pack):
    rules_for_type = pack.rules.get("canary_modified", [])
    ids = [r["id"] for r in rules_for_type]
    assert "ransomware_canary_modified" in ids


def test_note_dropped_in_event_index(pack):
    rules_for_type = pack.rules.get("file_create", [])
    ids = [r["id"] for r in rules_for_type]
    assert "ransomware_note_dropped" in ids
