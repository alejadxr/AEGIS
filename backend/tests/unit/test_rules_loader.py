"""Unit tests for YAML rules loader (Phase C)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
import yaml

RULES_PATH = Path(__file__).parent.parent.parent / "app" / "rules"


def _loader():
    from app.services.rules_loader import load_rules
    return load_rules(RULES_PATH)


@pytest.fixture(scope="module")
def pack():
    return _loader()


# ---------------------------------------------------------------------------
# Count assertions
# ---------------------------------------------------------------------------

def test_sigma_rule_count(pack):
    assert pack.sigma_count >= 122, (
        f"Expected >= 122 sigma rules, got {pack.sigma_count}"
    )


def test_chain_rule_count(pack):
    assert len(pack.chains) >= 5, (
        f"Expected >= 5 chain rules, got {len(pack.chains)}"
    )


# ---------------------------------------------------------------------------
# Index / lookup
# ---------------------------------------------------------------------------

def test_by_id_contains_brute_force_ssh(pack):
    assert "brute_force_ssh" in pack.by_id


def test_auth_failure_event_type_has_rules(pack):
    auth_rules = pack.rules.get("auth_failure", [])
    assert len(auth_rules) >= 5, (
        f"Expected >= 5 rules for auth_failure, got {len(auth_rules)}"
    )


def test_brute_force_rule_fields(pack):
    rule = pack.by_id["brute_force_ssh"]
    assert rule["id"] == "brute_force_ssh"
    assert rule["severity"] == "high"
    assert rule["title"] == "SSH Brute Force Detected"
    cond = rule["condition"]
    assert cond.get("event_type") == "auth_failure"
    assert cond["count_threshold"] == 5
    assert "count_threshold" in cond


def test_chain_rules_have_chain_steps(pack):
    for chain in pack.chains:
        steps = chain.get("chain", [])
        assert len(steps) >= 2, f"Chain {chain['id']} has < 2 steps"


def test_chain_steps_dict_access(pack):
    chain = pack.chains[0]
    steps = chain.get("chain", [])
    step = steps[0]
    # ChainStep must support .get() for engine compatibility
    assert step.get("within", 3600) > 0
    # At least sigma_rule or event_type must be set
    assert step.get("sigma_rule") or step.get("event_type")


def test_advanced_intrusion_chain_exists(pack):
    ids = {c["id"] for c in pack.chains}
    assert "advanced_intrusion_chain" in ids


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

def test_malformed_yaml_is_skipped(tmp_path):
    """A bad YAML file should be silently skipped, not crash the loader."""
    from app.services.rules_loader import load_rules

    # Write a valid YAML rule file
    valid_dir = tmp_path / "sigma" / "test"
    valid_dir.mkdir(parents=True)
    good_rule = {
        "id": "test_valid_rule",
        "name": "Test Valid Rule",
        "kind": "sigma",
        "severity": "low",
        "tactics": [],
        "techniques": [],
        "data_sources": ["pm2"],
        "condition": {"event_type": "test_event"},
        "entityMappings": [],
    }
    (valid_dir / "test_valid_rule.yaml").write_text(
        yaml.dump(good_rule), encoding="utf-8"
    )

    # Write a malformed YAML file
    (valid_dir / "bad_syntax.yaml").write_text(
        "id: bad\n  malformed: [unclosed", encoding="utf-8"
    )

    # Write a YAML file that's valid YAML but fails schema validation
    bad_schema = {"id": "bad_schema", "severity": "INVALID_SEVERITY", "condition": {"event_type": "x"}}
    (valid_dir / "bad_schema.yaml").write_text(
        yaml.dump(bad_schema), encoding="utf-8"
    )

    pack = load_rules(tmp_path)
    assert pack.sigma_count == 1  # Only the valid rule loaded
    assert "test_valid_rule" in pack.by_id


def test_technique_validator_rejects_bad_id():
    """Techniques must match T####[.###] pattern."""
    from pydantic import ValidationError
    from app.schemas.rule import Rule, RuleCondition

    with pytest.raises(ValidationError):
        Rule(
            id="test",
            name="Test",
            severity="low",
            techniques=["INVALID"],
            condition=RuleCondition(event_type="test"),
        )


def test_technique_validator_accepts_valid_id():
    from app.schemas.rule import Rule, RuleCondition

    rule = Rule(
        id="test_rule",
        name="Test Rule",
        severity="medium",
        techniques=["T1110", "T1110.001"],
        condition=RuleCondition(event_type="auth_failure"),
    )
    assert "T1110" in rule.techniques


def test_rule_id_validator_rejects_spaces():
    from pydantic import ValidationError
    from app.schemas.rule import Rule, RuleCondition

    with pytest.raises(ValidationError):
        Rule(
            id="has spaces",
            name="Bad",
            severity="low",
            condition=RuleCondition(event_type="x"),
        )


# ---------------------------------------------------------------------------
# Dict-like compat (engine uses rule["field"] and rule.get("field"))
# ---------------------------------------------------------------------------

def test_rule_dict_access(pack):
    rule = pack.by_id["brute_force_ssh"]
    assert rule["id"] == "brute_force_ssh"
    assert rule["severity"] == "high"
    assert rule.get("enabled", True) is True
    assert rule.get("nonexistent_key", "default") == "default"


def test_rule_condition_dict_access(pack):
    rule = pack.by_id["brute_force_ssh"]
    cond = rule["condition"]
    assert cond.get("event_type") == "auth_failure"
    assert cond.get("time_window_seconds", 60) == 300
    assert cond.get("group_by") == "source_ip"
    assert "count_threshold" in cond
    assert "nonexistent" not in cond


# ---------------------------------------------------------------------------
# Hot-reload test (skipped if watchdog not available)
# ---------------------------------------------------------------------------

def test_hot_reload(tmp_path):
    """Writing a new YAML file should trigger a hot-reload within ~2s."""
    pytest.importorskip("watchdog", reason="watchdog not installed — hot-reload disabled")

    from app.services.rules_loader import load_rules, start_watcher

    pack = load_rules(tmp_path)
    observer = start_watcher(pack, tmp_path)
    assert observer is not None

    try:
        # Write a new rule file after watcher is running
        rule_dir = tmp_path / "sigma" / "test"
        rule_dir.mkdir(parents=True, exist_ok=True)
        new_rule = {
            "id": "hot_reload_test",
            "name": "Hot Reload Test",
            "kind": "sigma",
            "severity": "low",
            "tactics": [],
            "techniques": [],
            "data_sources": ["pm2"],
            "condition": {"event_type": "hot_test_event"},
            "entityMappings": [],
        }
        (rule_dir / "hot_reload_test.yaml").write_text(
            yaml.dump(new_rule), encoding="utf-8"
        )

        # Wait up to 3s for debounced reload
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if "hot_reload_test" in pack.by_id:
                break
            time.sleep(0.1)

        assert "hot_reload_test" in pack.by_id, (
            "Hot-reload did not pick up new rule within 3s"
        )
    finally:
        observer.stop()
        observer.join(timeout=2)
