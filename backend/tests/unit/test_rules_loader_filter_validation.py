# backend/tests/unit/test_rules_loader_filter_validation.py
"""Load-time validation of filter vocabulary.

A rule whose filter uses a key the interpreter does not implement used to
load, validate against the schema, count toward the rule total and never
match — silently. `validate_filter` (correlation_engine) reports such clauses
and rules_loader logs them once per load, naming rule id, key and file. The
rule is still loaded: a typo must not take the rest of the pack down.
"""
from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml

from app.services.correlation_engine import (
    _UNSUPPORTED_FILTER_SUFFIXES,
    BUILT_IN_RULES,
    validate_filter,
)

RULES_PATH = Path(__file__).parent.parent.parent / "app" / "rules"


def _rule(rule_id: str, filt: dict) -> dict:
    return {
        "id": rule_id,
        "name": f"Test {rule_id}",
        "kind": "sigma",
        "severity": "low",
        "tactics": [],
        "techniques": [],
        "data_sources": ["pm2"],
        "condition": {"event_type": "http_request", "filter": filt},
        "entityMappings": [],
    }


# ---------------------------------------------------------------------------
# validate_filter
# ---------------------------------------------------------------------------

def test_full_supported_vocabulary_passes():
    filt = {
        "method": "POST",
        "destination_port": [6667, 6668],
        "suid": True,
        "path_contains": [".php", ".jsp"],
        "path_contains_all": ["Transfer-Encoding:", "Content-Length:"],
        "path_excludes": ["/api/v1/health"],
        "ua_contains": ["sqlmap"],
        "tags_contains": "scanner",
        "bytes_gt": 104_857_600,
        "ratio_gt": 0.5,
        "command_line_regex": r"(?i)bcdedit.*?recoveryenabled\s+no",
    }
    assert validate_filter(filt) == []


def test_unsupported_comparison_suffix_is_reported():
    problems = validate_filter({"domain_age_days_lt": 30})
    assert [k for k, _ in problems] == ["domain_age_days_lt"]
    assert "'_lt' is not implemented" in problems[0][1]
    assert "_contains" in problems[0][1]  # tells the author what IS supported


@pytest.mark.parametrize("key", ["x_lte", "x_gte", "x_ne", "x_in", "x_not_in", "x_startswith",
                                 "x_endswith", "x_matches", "x_like", "x_between", "x_not_contains",
                                 "x_icontains", "x_exists", "x_include", "x_excludes_all"])
def test_every_listed_unsupported_suffix_is_reported(key):
    assert validate_filter({key: 1}), key


def test_misspelled_operator_gets_a_suggestion():
    problems = validate_filter({"ua_contins": ["sqlmap"]})
    assert problems == [("ua_contins", "unknown operator '_contins' — did you mean '_contains'?")]
    assert validate_filter({"path_regexp": "a+"})[0][1].endswith("did you mean '_regex'?")


def test_gt_needs_a_number():
    assert validate_filter({"bytes_gt": "100"}) == [("bytes_gt", "_gt needs a numeric threshold, got str")]
    assert validate_filter({"bytes_gt": True})[0][0] == "bytes_gt"
    assert validate_filter({"bytes_gt": 100}) == []
    assert validate_filter({"bytes_gt": 0.5}) == []


def test_regex_must_compile():
    problems = validate_filter({"command_line_regex": "(unclosed"})
    assert problems[0][0] == "command_line_regex"
    assert problems[0][1].startswith("invalid regex:")
    assert validate_filter({"command_line_regex": 5})[0][1].startswith("_regex needs a pattern string")


def test_substring_operators_need_text_fragments():
    assert validate_filter({"path_contains": []}) == [("path_contains", "empty fragment list can never match")]
    assert validate_filter({"path_contains": {"a": 1}})[0][1].startswith("substring operators need a list")
    assert validate_filter({"ua_contains": [None]})[0][1] == "fragment None is not text"
    assert validate_filter({"ua_contains": [["nested"]]})[0][0] == "ua_contains"
    # Harmless shapes are accepted: empty _contains_all / _excludes are no-ops.
    assert validate_filter({"path_contains_all": [], "path_excludes": []}) == []


def test_operator_without_field_and_bad_shapes_are_reported():
    assert validate_filter({"_contains": ["x"]}) == [("_contains", "operator has no field name in front of it")]
    assert validate_filter({"meta": {"a": 1}}) == [("meta", "mapping values are not comparable to event fields")]
    assert validate_filter("not a dict")[0][0] == "<filter>"
    assert validate_filter({7: "x"})[0] == ("7", "filter keys must be strings")


# ---------------------------------------------------------------------------
# The shipped corpus
# ---------------------------------------------------------------------------

def test_corpus_flags_are_all_genuine_and_the_known_dead_clause_is_caught():
    """Every clause flagged on the real corpus must be a real unsupported
    operator (no false positives on the legacy vocabulary), and the one clause
    known to be dead today — `domain_age_days_lt` in sigma_c2_https_new_domain,
    evaluated as equality on a field nobody emits — must be among them."""
    flagged: list[tuple[str, str, str]] = []
    n_rules = 0
    for yaml_path in sorted(RULES_PATH.rglob("*.yaml")):
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("kind") == "chain":
            continue
        n_rules += 1
        for key, reason in validate_filter((data.get("condition") or {}).get("filter") or {}):
            flagged.append((data.get("id"), key, reason))
    assert n_rules >= 172, f"corpus shrank to {n_rules} sigma rules"

    for rule_id, key, reason in flagged:
        assert key.endswith(_UNSUPPORTED_FILTER_SUFFIXES) or "did you mean" in reason, (
            f"false positive on legacy vocabulary: {rule_id} {key!r}: {reason}"
        )
    assert ("sigma_c2_https_new_domain", "domain_age_days_lt") in {(r, k) for r, k, _ in flagged}, flagged


def test_builtin_rules_have_exactly_the_one_known_dead_clause():
    flagged = [(r["id"], k) for r in BUILT_IN_RULES
               for k, _ in validate_filter((r.get("condition") or {}).get("filter") or {})]
    assert flagged == [("sigma_c2_https_new_domain", "domain_age_days_lt")]


# ---------------------------------------------------------------------------
# rules_loader integration: warn, name rule/key/file, keep loading
# ---------------------------------------------------------------------------

def test_loader_warns_with_rule_id_key_and_file_but_still_loads_the_rule(tmp_path, caplog):
    from app.services.rules_loader import load_rules

    rules_dir = tmp_path / "sigma" / "test"
    rules_dir.mkdir(parents=True)
    (rules_dir / "typo.yaml").write_text(yaml.dump(_rule("rule_with_typo", {"ua_contins": ["sqlmap"]})))
    (rules_dir / "dead_lt.yaml").write_text(yaml.dump(_rule("rule_with_lt", {"age_lt": 30, "method": "GET"})))
    (rules_dir / "fine.yaml").write_text(yaml.dump(_rule("rule_fine", {"ua_contains": ["sqlmap"]})))

    with caplog.at_level(logging.WARNING, logger="aegis.rules_loader"):
        pack = load_rules(tmp_path)

    # Nothing was dropped: warn and continue.
    assert pack.sigma_count == 3
    assert {"rule_with_typo", "rule_with_lt", "rule_fine"} <= set(pack.by_id)

    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 2, warnings
    typo = next(w for w in warnings if "rule_with_typo" in w)
    assert "'ua_contins'" in typo and "typo.yaml" in typo and "did you mean '_contains'" in typo
    lt = next(w for w in warnings if "rule_with_lt" in w)
    assert "'age_lt'" in lt and "dead_lt.yaml" in lt and "'method'" not in lt


def test_loader_is_quiet_on_a_clean_pack(tmp_path, caplog):
    from app.services.rules_loader import load_rules

    rules_dir = tmp_path / "sigma" / "test"
    rules_dir.mkdir(parents=True)
    (rules_dir / "fine.yaml").write_text(yaml.dump(_rule("rule_fine", {"ua_contains": ["sqlmap"], "bytes_gt": 1})))
    with caplog.at_level(logging.WARNING, logger="aegis.rules_loader"):
        pack = load_rules(tmp_path)
    assert pack.sigma_count == 1
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


def test_real_corpus_loads_fully_and_warns_only_about_genuine_problems(caplog):
    """The whole pack on disk still validates and loads; the loader's warnings
    are exactly the validator's findings (nothing extra, nothing hidden)."""
    from app.services.rules_loader import load_rules

    with caplog.at_level(logging.WARNING, logger="aegis.rules_loader"):
        pack = load_rules(RULES_PATH)
    # Sigma rules only: chain rules have no filter and are validated elsewhere.
    assert pack.sigma_count >= 172

    filter_warnings = [r.getMessage() for r in caplog.records
                       if r.levelno == logging.WARNING and "cannot be honoured" in r.getMessage()]
    expected = {
        (rule.id, key)
        for rule in pack.by_id.values() if rule.kind == "sigma"
        for key, _ in validate_filter(rule.condition.filter)
    }
    assert len(filter_warnings) == len(expected)
    for rule_id, key in expected:
        assert any(f"'{rule_id}'" in w and f"'{key}'" in w for w in filter_warnings), (rule_id, key)
    assert ("sigma_c2_https_new_domain", "domain_age_days_lt") in expected


# ---------------------------------------------------------------------------
# add_rule (runtime custom rules) gets the same check
# ---------------------------------------------------------------------------

def test_add_rule_warns_but_accepts_a_rule_with_an_unsupported_clause(caplog, monkeypatch):
    from app.services import correlation_engine as ce
    from app.services import rules_loader

    # Real constructor (so it keeps working when __init__ grows), with an empty
    # pack, no watcher and no in-code rules: the engine holds only what add_rule adds.
    monkeypatch.setattr(rules_loader, "load_rules", lambda _path: rules_loader.RulePack())
    monkeypatch.setattr(rules_loader, "start_watcher", lambda _pack, _path: None)
    monkeypatch.setattr(ce, "BUILT_IN_RULES", [])
    monkeypatch.setattr(ce, "CHAIN_RULES", [])
    engine = ce.CorrelationEngine()
    assert engine._rules == []

    with caplog.at_level(logging.WARNING, logger="aegis.correlation"):
        added = engine.add_rule({
            "id": "custom_ua_typo", "title": "Custom", "severity": "low",
            "condition": {"event_type": "http_request", "filter": {"ua_contins": ["sqlmap"]}},
        })
    assert added["id"] == "custom_ua_typo"
    assert engine._rules_by_type["http_request"][0]["id"] == "custom_ua_typo"
    msgs = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("'custom_ua_typo'" in m and "'ua_contins'" in m and "add_rule" in m for m in msgs), msgs
