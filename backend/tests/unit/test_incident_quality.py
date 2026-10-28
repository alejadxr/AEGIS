"""Burst merging, evidence-gated wording and evidence-gated severity.

Drives the real CorrelationEngine._create_incident against an in-memory
SQLite session; only the AI call is replaced (by the same incident-creation
code the AI path runs, fed the rule's own text) so no network is involved.
Documentation addresses only (RFC 5737 / 3849) and example.com.
"""
import asyncio
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
import pytest_asyncio
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.models.asset import Asset
from app.models.base import Base
from app.models.client import Client
from app.models.incident import Incident
from app.services import incident_quality as iq
from app.services.ai_engine import ai_engine
from app.services.correlation_engine import BUILT_IN_RULES, CorrelationEngine

ATTACKER = "198.51.100.7"
OTHER = "203.0.113.9"


@pytest_asyncio.fixture
async def factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    @event.listens_for(engine.sync_engine, "connect")
    def _fk_on(conn, _rec):
        conn.execute("PRAGMA foreign_keys=ON")

    async with engine.begin() as conn:
        await conn.run_sync(
            lambda c: Base.metadata.create_all(c, tables=[Client.__table__, Asset.__table__, Incident.__table__])
        )
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as db:
        db.add(Client(id="c1", name="t", slug="t", api_key="k"))
        await db.commit()
    yield maker
    await engine.dispose()


@pytest.fixture
def engine_under_test(factory):
    """A correlation engine whose incidents go to the SQLite session."""

    async def fake_process_alert(alert_data, client, db):
        triage = {
            "severity": alert_data["severity"],
            "summary": alert_data["description"],
            "threat_type": "unknown",
        }
        await ai_engine._create_incident(alert_data, triage, {}, client, db)

    with patch("app.database.async_session", factory), \
         patch("app.core.attack_detector._is_safe_ip", return_value=False), \
         patch.object(ai_engine, "process_alert", side_effect=fake_process_alert):
        yield CorrelationEngine()


def _rule(rid, severity="high", title=None):
    return {"id": rid, "title": title or f"Probe {rid}", "severity": severity, "description": f"{rid} probe", "mitre": []}


def _alert(rule, source_ip=ATTACKER, status=None, app="landing", **extra):
    event_ = {"event_type": "http_request", "source_ip": source_ip, "request_path": "/x",
              "request_method": "POST", "source": app}
    if status is not None:
        event_["response_status"] = status
    return {
        "event_type": "correlation_triggered", "rule_id": rule["id"], "rule_title": rule["title"],
        "severity": rule["severity"], "description": rule["description"],
        "triggering_event": event_, "source_ip": source_ip,
        "source": "correlation_engine", "pattern": rule["id"], **extra,
    }


async def _incidents(factory):
    async with factory() as db:
        return (await db.execute(select(Incident).order_by(Incident.detected_at))).scalars().all()


# ---------------------------------------------------------------- Problem 1

async def test_nine_rule_burst_is_one_incident(factory, engine_under_test):
    rules = [_rule(f"cve_{i}", "high" if i != 4 else "critical") for i in range(9)]
    # Concurrent, like the real engine: one asyncio task per fired rule.
    await asyncio.gather(*(engine_under_test._create_incident(r, _alert(r)) for r in rules))
    incidents = await _incidents(factory)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.severity == "critical"
    matched = inc.ai_analysis["matched_rules"]
    assert {m["id"] for m in matched} == {r["id"] for r in rules}
    assert {m["title"] for m in matched} == {r["title"] for r in rules}
    for r in rules:
        assert r["title"] in inc.description
    assert inc.title.startswith("CRITICAL:")


async def test_severity_only_goes_up(factory, engine_under_test):
    crit, low = _rule("a", "critical"), _rule("b", "medium")
    await engine_under_test._create_incident(crit, _alert(crit))
    await engine_under_test._create_incident(low, _alert(low))
    (inc,) = await _incidents(factory)
    assert inc.severity == "critical"


async def test_returning_attacker_after_window_gets_new_incident(factory, engine_under_test):
    a, b = _rule("a"), _rule("b")
    await engine_under_test._create_incident(a, _alert(a))
    stale = datetime.utcnow() - iq_window() - timedelta(minutes=1)
    async with factory() as db:
        inc = (await db.execute(select(Incident))).scalars().one()
        inc.detected_at = stale
        await db.commit()
    await engine_under_test._create_incident(b, _alert(b))
    assert len(await _incidents(factory)) == 2


def iq_window():
    from app.services.firewall_sync import INCIDENT_BURST_WINDOW
    return INCIDENT_BURST_WINDOW


async def test_continuing_scan_keeps_feeding_one_incident(factory, engine_under_test):
    """The window slides from last activity, so a long scan is still one incident."""
    a, b, c = _rule("a"), _rule("b"), _rule("c")
    await engine_under_test._create_incident(a, _alert(a))
    async with factory() as db:
        inc = (await db.execute(select(Incident))).scalars().one()
        inc.detected_at = datetime.utcnow() - timedelta(minutes=9)
        await db.commit()
    await engine_under_test._create_incident(b, _alert(b))  # 9 min in: merges, bumps last_seen
    async with factory() as db:
        inc = (await db.execute(select(Incident))).scalars().one()
        inc.detected_at = datetime.utcnow() - timedelta(minutes=18)
        await db.commit()
    await engine_under_test._create_incident(c, _alert(c))  # 18 min after start, 9 after last hit
    assert len(await _incidents(factory)) == 1


async def test_different_sources_never_merge(factory, engine_under_test):
    a = _rule("a")
    await engine_under_test._create_incident(a, _alert(a, source_ip=ATTACKER))
    await engine_under_test._create_incident(a, _alert(a, source_ip=OTHER))
    assert len(await _incidents(factory)) == 2


async def test_different_targets_of_one_source_do_not_merge(factory, engine_under_test):
    a, b = _rule("a"), _rule("b")
    await engine_under_test._create_incident(a, _alert(a, app="landing"))
    await engine_under_test._create_incident(b, _alert(b, app="wilabia"))
    assert len(await _incidents(factory)) == 2


async def test_host_incidents_do_not_merge_across_hosts(factory, engine_under_test):
    a, b = _rule("a"), _rule("b")

    def host_alert(rule, host):
        al = _alert(rule, source_ip=None, host=host)
        al["triggering_event"] = {"event_type": "process", "hostname": host, "source": "edr"}
        return al

    await engine_under_test._create_incident(a, host_alert(a, "ws-a.example.com"))
    await engine_under_test._create_incident(b, host_alert(b, "ws-b.example.com"))
    assert len(await _incidents(factory)) == 2
    await engine_under_test._create_incident(b, host_alert(b, "ws-a.example.com"))
    incidents = await _incidents(factory)
    assert len(incidents) == 2
    # An unmerged incident has no matched_rules yet; the merged one lists both rules.
    assert sorted(len(i.ai_analysis.get("matched_rules", [None])) for i in incidents) == [1, 2]


# ---------------------------------------------------------------- Problem 2

def test_web_shell_rule_is_worded_as_an_attempt_and_keeps_its_id():
    (rule,) = [r for r in BUILT_IN_RULES if r["id"] == "web_shell_activity"]
    assert "Detected" not in rule["title"] and "Attempt" in rule["title"]
    assert "not confirmed" in rule["description"]


CLAIM = "The attacker successfully accessed the metadata endpoint, resulting in a successful HTTP 200 response."


@pytest.mark.parametrize("status", [404, None])
def test_no_success_wording_without_a_2xx(status):
    alert = _alert(_rule("a"), status=status)
    out = iq.describe_without_overclaim(CLAIM, alert)
    assert "successful" not in out.lower()
    assert "attempted to access" in out


def test_success_wording_is_kept_on_a_2xx():
    assert iq.describe_without_overclaim(CLAIM, _alert(_rule("a"), status=200)) == CLAIM


def test_non_http_alerts_keep_their_wording():
    ssh = {"source": "log_watcher", "source_ip": ATTACKER, "triggering_event": {"event_type": "auth_success"}}
    text = "Successful login after brute force"
    assert iq.describe_without_overclaim(text, ssh) == text


async def test_model_claim_is_scrubbed_on_the_incident(factory, engine_under_test):
    """The model ignores the prompt; the stored title and description must still be clean."""
    rule = _rule("langflow", "critical")
    rule["description"] = CLAIM
    await engine_under_test._create_incident(rule, _alert(rule, status=404))
    (inc,) = await _incidents(factory)
    assert "successful" not in (inc.title + inc.description).lower()


# ---------------------------------------------------------------- Problem 3

@pytest.mark.parametrize("status", [404, 410])
async def test_404_lowers_severity_one_level_and_says_why(factory, engine_under_test, status):
    rule = _rule("versa", "critical")
    await engine_under_test._create_incident(rule, _alert(rule, status=status))
    (inc,) = await _incidents(factory)
    assert inc.severity == "high"
    assert inc.title.startswith("HIGH:")
    assert f"answered {status}" in inc.description


@pytest.mark.parametrize("status", [200, 204, None])
async def test_no_downgrade_on_2xx_or_missing_status(factory, engine_under_test, status):
    rule = _rule("versa", "critical")
    await engine_under_test._create_incident(rule, _alert(rule, status=status))
    (inc,) = await _incidents(factory)
    assert inc.severity == "critical"


def test_never_below_low():
    assert iq.apply_probe_evidence(_alert(_rule("a"), status=404), "low", "d") == ("low", "d")
    assert iq.downgrade_severity("medium") == "low"


def test_edr_host_incident_is_never_downgraded():
    alert = {"source": "correlation_engine", "host": "ws-a.example.com",
             "triggering_event": {"source": "edr", "hostname": "ws-a.example.com", "response_status": 404}}
    assert iq.apply_probe_evidence(alert, "critical", "d") == ("critical", "d")


async def test_a_404_match_cannot_lower_a_merged_incident(factory, engine_under_test):
    ok, miss = _rule("real", "high"), _rule("miss", "critical")
    await engine_under_test._create_incident(ok, _alert(ok, status=200))
    await engine_under_test._create_incident(miss, _alert(miss, status=404))  # critical -> high via 404
    (inc,) = await _incidents(factory)
    assert inc.severity == "high"
