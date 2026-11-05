"""A rule's authored severity can be raised only with evidence.

Production, 14 days: 51 correlation incidents ended above their rule's
severity, 28 by one level, 16 by two, 7 by three (rules authored `low` ended
critical). 50 of the 51 came from burst merging, one from the model. Severity
drives blocking, so inflation turned single probes into blocks.
Documentation addresses only (RFC 5737) and example.com.
"""
import pytest

from app.services import incident_quality as iq
from app.services.ai_engine import ai_engine
from tests.unit.test_incident_quality import (  # noqa: F401  (fixtures)
    ATTACKER, _alert, _incidents, _rule, engine_under_test, factory,
)

# ------------------------------------------------------------ the bound itself

def test_no_evidence_caps_at_one_level_above_the_rule():
    sev, why = iq.bound_escalation("low", "critical", _alert(_rule("a", "low")))
    assert sev == "medium"
    assert "capped" in why and "nothing confirms" in why


def test_a_404_blocks_any_raise():
    sev, why = iq.bound_escalation("low", "high", _alert(_rule("a", "low"), status=404))
    assert sev == "low" and "probe missed" in why


def test_one_level_up_is_allowed_and_recorded():
    sev, why = iq.bound_escalation("low", "medium", _alert(_rule("a", "low")))
    assert sev == "medium" and why


def test_no_jump_means_no_reason():
    assert iq.bound_escalation("high", "high", {}) == ("high", None)
    assert iq.bound_escalation("high", "low", {}) == ("low", None)


@pytest.mark.parametrize("extra,needle", [
    ({"status": 200}, "answered 200"),
    ({"chain_id": "c1"}, "chain"),
    ({"known_attacker": True}, "known attacker"),
])
def test_hard_evidence_allows_a_bigger_jump_and_says_why(extra, needle):
    extra = dict(extra)
    status = extra.pop("status", None)
    sev, why = iq.bound_escalation("low", "critical", _alert(_rule("a", "low"), status=status, **extra))
    assert sev == "critical" and needle in why


def test_edr_confirmation_is_evidence():
    alert = {"source": "edr", "host": "host1.example.com"}
    assert iq.bound_escalation("low", "high", alert)[0] == "high"


# ------------------------------------------------------------ burst merging

async def test_critical_rule_in_a_low_burst_is_still_critical(factory, engine_under_test):
    """The ceiling is the matching rule's own severity, not the incident's."""
    low, crit = _rule("a", "low"), _rule("b", "critical")
    await engine_under_test._create_incident(low, _alert(low))
    await engine_under_test._create_incident(crit, _alert(crit))
    (inc,) = await _incidents(factory)
    assert inc.severity == "critical"
    assert inc.ai_analysis["severity_escalations"][-1]["authored"] == "critical"


async def test_404_on_a_critical_cve_rule_reads_high_not_low(factory, engine_under_test):
    low, crit = _rule("a", "low"), _rule("b", "critical")
    await engine_under_test._create_incident(low, _alert(low, status=404))
    await engine_under_test._create_incident(crit, _alert(crit, status=404))
    (inc,) = await _incidents(factory)
    assert inc.severity == "high"


async def test_boosted_low_match_cannot_jump_past_one_level(factory, engine_under_test):
    """A low rule whose alert was rated critical (boost / model) is capped."""
    first, second = _rule("a", "low"), _rule("b", "low")
    await engine_under_test._create_incident(first, _alert(first))
    await engine_under_test._create_incident(second, _alert(second, severity="critical"))
    (inc,) = await _incidents(factory)
    assert inc.severity == "medium"
    esc = inc.ai_analysis["severity_escalations"][-1]
    assert esc["proposed"] == "critical" and "capped" in esc["reason"]


async def test_low_rule_with_a_2xx_escalates_and_records_reason(factory, engine_under_test):
    first, second = _rule("a", "low"), _rule("b", "low")
    await engine_under_test._create_incident(first, _alert(first))
    await engine_under_test._create_incident(second, _alert(second, status=200, severity="critical"))
    (inc,) = await _incidents(factory)
    assert inc.severity == "critical"
    assert "answered 200" in inc.ai_analysis["severity_escalations"][-1]["reason"]


async def test_confirmed_chain_still_reaches_critical(factory, engine_under_test):
    low = _rule("a", "low")
    await engine_under_test._create_incident(low, _alert(low, status=404))
    chain = _rule("chain1", "critical")
    await engine_under_test._create_incident(chain, _alert(chain, status=404, chain_id="chain1"))
    (inc,) = await _incidents(factory)
    assert inc.severity == "critical"


# ------------------------------------------------------------ the AI step

async def _create(factory, alert, ai_severity):
    triage = {"severity": ai_severity, "summary": "probe", "threat_type": "unknown", "confidence": 0.95}
    async with factory() as db:
        from app.models.client import Client
        client = await db.get(Client, "c1")
        from unittest.mock import patch
        with patch("app.core.attack_detector._is_safe_ip", return_value=False):
            inc = await ai_engine._create_incident(alert, triage, {}, client, db)
    return inc, triage


async def test_ai_cannot_inflate_a_low_rule_without_evidence(factory):
    rule = _rule("a", "low")
    inc, triage = await _create(factory, _alert(rule), "critical")
    assert inc.severity == "medium"
    assert triage["severity_ai"] == "critical" and "capped" in triage["severity_bound_reason"]
    assert inc.ai_analysis["triage"]["severity_bound_reason"]


async def test_ai_may_raise_a_low_rule_further_on_a_2xx(factory):
    rule = _rule("a", "low")
    inc, triage = await _create(factory, _alert(rule, status=200), "critical")
    assert inc.severity == "critical"
    assert "answered 200" in triage["severity_bound_reason"]


async def test_ai_escalation_never_flips_a_probe_into_a_block(factory):
    """The block gate reads triage severity: it must see the bounded value."""
    rule = _rule("a", "low")
    alert = _alert(rule, status=404)
    _, triage = await _create(factory, alert, "critical")
    confirmed, reason = ai_engine._alert_block_confirmed(alert, triage, "unknown")
    assert not confirmed, reason


async def test_ai_inflation_on_a_404_probe_stays_low(factory):
    inc, _ = await _create(factory, _alert(_rule("a", "low"), status=404), "critical")
    assert inc.severity == "low"
