"""The 2026-11-20 incident: AEGIS permanently blocked its own office.

One POST /graphql from the lab's public address matched a low-severity,
single-request rule; an LLM labelled it "honeypot_recon"; that label alone was
treated as a confirmed exploit class.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app.core import safelist_store as store
from app.services import own_egress
from app.services.ai_engine import AIDecisionEngine

LLM = {"kind": "agent", "source": "openrouter:some/free-model"}


def _graphql_alert():
    return {
        "source": "correlation_engine", "pattern": "sigma_web_framework_probe",
        "rule_id": "sigma_web_framework_probe", "severity": "low", "source_ip": "203.0.113.10",
        "triggering_event": {"source": "sable", "event_type": "http_request", "threat_type": "http_traffic",
                             "request_path": "/graphql", "response_status": 200},
    }


def _confirmed(alert, triage, threat_type):
    return AIDecisionEngine()._alert_block_confirmed(alert, triage, threat_type)


def test_a_model_calling_it_honeypot_recon_does_not_confirm_the_block():
    triage = {"severity": "low", "confidence": 0.9, "threat_type": "honeypot_recon", "_provenance": LLM}
    confirmed, why = _confirmed(_graphql_alert(), triage, "honeypot_recon")
    assert confirmed is False, why


def test_a_real_honeypot_event_is_still_confirmed():
    alert = {"source": "ssh_honeypot", "event_type": "honeypot_interaction", "source_ip": "203.0.113.10"}
    triage = {"severity": "medium", "confidence": 0.9, "_provenance": LLM}
    confirmed, why = _confirmed(alert, triage, "honeypot_recon")
    assert confirmed is True and "honeypot_source" in why


@pytest.mark.parametrize("label", ["sql_injection", "rce", "malware", "c2_communication"])
def test_any_exploit_label_from_a_model_needs_evidence(label):
    triage = {"severity": "low", "confidence": 0.95, "_provenance": LLM}
    assert _confirmed(_graphql_alert(), triage, label)[0] is False


def test_model_label_counts_when_the_detector_agrees():
    alert = {"threat_type": "sql_injection", "severity": "high", "source_ip": "203.0.113.10"}
    triage = {"severity": "high", "confidence": 0.9, "_provenance": LLM}
    confirmed, why = _confirmed(alert, triage, "sql_injection")
    assert confirmed is True and "detector_agrees" in why


def test_deterministic_triage_keeps_its_old_meaning():
    triage = {"severity": "high", "confidence": 0.9, "_provenance": {"kind": "algorithm"}}
    assert _confirmed({"source_ip": "203.0.113.10"}, triage, "port_scan")[0] is True
    assert _confirmed({"source_ip": "203.0.113.10"}, {"severity": "high", "confidence": 0.9}, "rce")[0] is True


# --- the install's own public address ------------------------------------------

@pytest.fixture
def lists(monkeypatch, tmp_path):
    monkeypatch.setattr(store, "SAFELIST_FILE", tmp_path / "safelist.json")
    monkeypatch.setattr(store, "_next_check", 0.0)
    store.load()
    yield
    store.load()


def _ours():
    return {e["value"] for e in store.list_entries(store.INTERNAL) if e["added_by"] == own_egress.ADDED_BY}


def test_current_address_is_safelisted_and_seen_by_the_shared_gate(lists):
    from app.core.attack_detector import _is_safe_ip
    assert _is_safe_ip("45.33.32.156") is False
    own_egress.record("45.33.32.156")
    assert _ours() == {"45.33.32.156"}
    assert _is_safe_ip("45.33.32.156") is True


def test_lease_change_keeps_the_old_address_for_a_week_then_drops_it(lists):
    t0 = datetime(2026, 11, 1, tzinfo=timezone.utc)
    own_egress.record("45.33.32.156", now=t0)
    own_egress.record("45.33.32.200", now=t0 + timedelta(days=1))
    assert _ours() == {"45.33.32.156", "45.33.32.200"}
    out = own_egress.record("45.33.32.200", now=t0 + timedelta(days=9))
    assert out["dropped"] == ["45.33.32.156"] and _ours() == {"45.33.32.200"}


def test_entries_an_operator_added_are_never_removed(lists):
    store.add(store.INTERNAL, "45.33.32.50", False, "op@example.com", "home")
    t0 = datetime(2026, 11, 1, tzinfo=timezone.utc)
    own_egress.record("45.33.32.156", now=t0)
    own_egress.record("45.33.32.200", now=t0 + timedelta(days=30))
    assert store.has(store.INTERNAL, "45.33.32.50")


@pytest.mark.parametrize("body", ["10.0.0.5", "127.0.0.1", "<html>blocked</html>", "", "999.1.1.1", "100.64.0.9"])
def test_a_lookup_answer_that_is_not_a_public_address_is_ignored(body):
    assert own_egress._public_ip(body) is None


def test_public_answer_is_normalised():
    assert own_egress._public_ip(" 45.33.32.156\n") == "45.33.32.156"
