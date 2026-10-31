"""Block permanence: confirmed attacks are never released, ambiguous ones expire.

Documentation IPs only (RFC 5737).
"""
import re
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.models.action import Action
from app.models.asset import Asset
from app.models.audit_log import AuditLog
from app.models.base import Base
from app.models.client import Client
from app.models.incident import Incident
from app.services import block_policy as bp
from app.services import retention
from app.services.ai_engine import ai_engine
from app.services.ip_investigator import ip_investigator

IP_A = "192.0.2.10"
IP_B = "198.51.100.20"
IP_C = "203.0.113.30"


@pytest_asyncio.fixture
async def factory(monkeypatch):
    for var in ("AEGIS_BLOCKS_PERMANENT", "AEGIS_BLOCK_ESCALATE_AFTER"):
        monkeypatch.delenv(var, raising=False)
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    tables = [Client, Asset, Incident, Action, AuditLog]
    async with engine.begin() as conn:
        await conn.run_sync(lambda c: Base.metadata.create_all(c, tables=[m.__table__ for m in tables]))
    f = async_sessionmaker(engine, expire_on_commit=False)
    async with f() as db:
        db.add(Client(id="c1", name="t", slug="t", api_key="k"))
        await db.commit()
    monkeypatch.setattr(retention, "DRY_RUN", False)
    monkeypatch.setattr(retention, "_audit", lambda e: None)
    yield f
    await engine.dispose()


async def _block(factory, ip, alert, threat_type="unknown", severity="medium"):
    async with factory() as db:
        client = await db.get(Client, "c1")
        return await ai_engine._create_pending_block(
            client=client, target=ip, ai_reasoning="test", db=db,
            alert_data=alert, severity=severity, threat_type=threat_type,
        )


async def _expire(factory):
    """Run retention with the Pi/local unblock mocked; return (summary, mocks)."""
    fw = MagicMock(unblock_ip=AsyncMock(return_value={"success": True}))
    local = MagicMock()
    with patch.object(retention, "async_session", factory), \
            patch("app.core.firewall_client.firewall_client", fw), \
            patch("app.core.ip_blocker.ip_blocker_service", local):
        summary = await retention.expire_provisional_blocks()
    return summary, fw, local


async def _age(factory, action_id):
    """Push an action's expiry into the past."""
    async with factory() as db:
        a = await db.get(Action, action_id)
        a.parameters = {**a.parameters, "expires_at": (datetime.utcnow() - timedelta(minutes=1)).isoformat()}
        await db.commit()


# --- classification --------------------------------------------------------

@pytest.mark.parametrize("reason", [
    "sql_injection (high)", "command_injection (critical)", "path_traversal (high)",
    "ssrf (high)", "breadcrumb_credential_used (critical)",
    "aegis_auto_block: sql_injection (high)",
])
def test_attack_detector_reasons_are_confirmed(reason):
    assert bp.classify(reason).kind == bp.CONFIRMED


@pytest.mark.parametrize("rule_id", [
    "sigma_cve_versa_concerto_2025_34026", "web_shell_activity",
    "sigma_web_file_upload", "sigma_web_sensitive_file_probe",
    "sigma_cloud_metadata_ssrf", "sigma_ai_langflow_build_public_rce",
    "ssh_honeypot_attempt", "ssh_honeypot_brute",
])
def test_rule_ids_are_confirmed(rule_id):
    assert bp.classify(rule_ids=[rule_id]).kind == bp.CONFIRMED


@pytest.mark.parametrize("reason", [
    "brute_force (5 attempts)", "scanner User-Agent: nmap", "http_auth_brute",
    "high_request_rate", "port_scan", "dos:rate_limit", "firewall_rule:custom",
    "some_brand_new_rule_nobody_classified",
])
def test_ambiguous_and_unknown_reasons_are_ambiguous(reason):
    assert bp.classify(reason).kind == bp.AMBIGUOUS
    assert bp.classify(rule_ids=[reason]).kind == bp.AMBIGUOUS


def test_one_confirmed_signal_outweighs_soft_ones():
    cls = bp.classify("high_request_rate", rule_ids=["sigma_cve_x_2026_1"])
    assert cls.kind == bp.CONFIRMED


def test_every_web_rule_has_been_decided():
    """A new sigma_web_* rule must be put on one side deliberately."""
    rules = Path(__file__).resolve().parents[2] / "app" / "rules"
    ids = set()
    for f in rules.rglob("*.yaml"):
        m = re.search(r"^id:\s*(\S+)", f.read_text(), re.M)
        if m and m.group(1).startswith("sigma_web_"):
            ids.add(m.group(1))
    undecided = ids - bp.CONFIRMED_IDS - bp.AMBIGUOUS_KNOWN
    assert not undecided, f"classify these in block_policy: {sorted(undecided)}"


# --- permanence / escalation ----------------------------------------------

@pytest.mark.asyncio
async def test_confirmed_reason_makes_permanent_block_retention_never_lifts(factory):
    a = await _block(factory, IP_A, {"pattern": "web_shell_activity"})
    assert a.status == "approved"
    assert "provisional" not in a.parameters and "expires_at" not in a.parameters
    assert a.parameters["permanent"] is True and a.parameters["block_class"] == "confirmed"
    summary, fw, _ = await _expire(factory)
    assert summary["scanned"] == 0
    fw.unblock_ip.assert_not_called()


@pytest.mark.asyncio
async def test_ambiguous_reason_still_expires(factory):
    a = await _block(factory, IP_A, {"pattern": "http_auth_brute"}, threat_type="brute_force")
    assert a.parameters["provisional"] is True and a.parameters["expires_at"]
    await _age(factory, a.id)
    summary, fw, _ = await _expire(factory)
    assert summary["expired"] == 1
    fw.unblock_ip.assert_awaited_once_with(IP_A)


@pytest.mark.asyncio
async def test_unknown_reason_behaves_as_ambiguous(factory):
    a = await _block(factory, IP_A, {"pattern": "brand_new_unclassified_rule"})
    assert a.parameters["provisional"] is True


@pytest.mark.asyncio
async def test_repeat_block_escalates_to_permanent(factory):
    first = await _block(factory, IP_A, {"pattern": "port_scan"})
    assert first.parameters["provisional"] is True
    await _age(factory, first.id)
    await _expire(factory)                       # first block lapses
    second = await _block(factory, IP_A, {"pattern": "port_scan"})
    assert second.parameters.get("permanent") is True
    assert "expires_at" not in second.parameters
    assert second.parameters["block_class_reason"].startswith("escalated")


@pytest.mark.asyncio
async def test_released_false_positive_does_not_count_as_prior_offence(factory):
    first = await _block(factory, IP_A, {"pattern": "port_scan"})
    async with factory() as db:                  # operator rolled it back
        (await db.get(Action, first.id)).status = "rolled_back"
        await db.commit()
    again = await _block(factory, IP_A, {"pattern": "port_scan"})
    assert again.parameters.get("provisional") is True


@pytest.mark.asyncio
async def test_duplicate_request_folds_into_one_action(factory):
    first = await _block(factory, IP_A, {"pattern": "port_scan"})
    second = await _block(factory, IP_A, {"pattern": "sigma_cve_versa_concerto_2025_34026"})
    assert second.id == first.id
    async with factory() as db:
        rows = (await db.execute(select(Action).where(Action.target == IP_A))).scalars().all()
    assert len(rows) == 1
    assert rows[0].parameters["permanent"] is True and "expires_at" not in rows[0].parameters


# --- stale action cannot lift a live block ---------------------------------

@pytest.mark.asyncio
async def test_expired_action_does_not_lift_ip_covered_by_another_live_action(factory):
    async with factory() as db:
        past = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        future = (datetime.utcnow() + timedelta(days=20)).isoformat()
        db.add(Action(id="old", incident_id="", client_id="c1", action_type="block_ip", target=IP_B,
                      status="executed", parameters={"provisional": True, "expires_at": past}))
        db.add(Action(id="new", incident_id="", client_id="c1", action_type="block_ip", target=IP_B,
                      status="executed", parameters={"provisional": True, "expires_at": future}))
        await db.commit()
    summary, fw, local = await _expire(factory)
    fw.unblock_ip.assert_not_called()
    local.unblock_ip.assert_not_called()
    assert summary["covered"] == 1
    async with factory() as db:
        assert (await db.get(Action, "old")).status == "expired"
        assert (await db.get(Action, "new")).status == "executed"


@pytest.mark.asyncio
async def test_legacy_provisional_block_with_exploit_evidence_is_promoted_not_lifted(factory):
    async with factory() as db:
        db.add(Incident(id="i1", client_id="c1", title="x", severity="high", source_ip=IP_C,
                        raw_alert={"pattern": "sigma_cve_versa_concerto_2025_34026"}))
        db.add(Action(id="a1", incident_id="i1", client_id="c1", action_type="block_ip", target=IP_C,
                      status="executed", parameters={
                          "provisional": True,
                          "expires_at": (datetime.utcnow() - timedelta(hours=1)).isoformat()}))
        await db.commit()
    summary, fw, _ = await _expire(factory)
    fw.unblock_ip.assert_not_called()
    assert summary["promoted"] == 1
    async with factory() as db:
        a = await db.get(Action, "a1")
        assert a.status == "executed" and a.parameters["permanent"] is True
        assert "expires_at" not in a.parameters


# --- env override ----------------------------------------------------------

@pytest.mark.asyncio
async def test_env_override_makes_everything_permanent(factory, monkeypatch):
    monkeypatch.setenv("AEGIS_BLOCKS_PERMANENT", "1")
    a = await _block(factory, IP_A, {"pattern": "port_scan"})
    assert a.parameters["permanent"] is True and "expires_at" not in a.parameters
    assert a.parameters["block_class_reason"] == "AEGIS_BLOCKS_PERMANENT"


@pytest.mark.asyncio
async def test_env_override_disables_retention_for_existing_rows(factory, monkeypatch):
    a = await _block(factory, IP_A, {"pattern": "port_scan"})
    await _age(factory, a.id)
    monkeypatch.setenv("AEGIS_BLOCKS_PERMANENT", "1")
    summary, fw, _ = await _expire(factory)
    assert summary.get("disabled") is True
    fw.unblock_ip.assert_not_called()


# --- investigator ----------------------------------------------------------

def _investigator_env(factory, verdict):
    """Patch the AI to say 'legitimate' and capture unblocks."""
    unblock = AsyncMock()
    return unblock, [
        patch.object(ip_investigator, "_query_ai", AsyncMock(return_value=verdict)),
        patch.object(ip_investigator, "_unblock_ip", unblock),
        patch.object(ip_investigator, "_log_investigation", AsyncMock()),
        patch("app.database.async_session", factory),
    ]


LEGIT = {"verdict": "legitimate", "confidence": 0.99, "reasoning": "looks fine"}


async def _investigate(factory, ip, reason):
    unblock, patches = _investigator_env(factory, LEGIT)
    for p in patches:
        p.start()
    try:
        result = await ip_investigator.investigate_blocked_ip(ip, reason)
    finally:
        patch.stopall()
    return result, unblock


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", [
    "web_shell_activity", "sigma_cve_versa_concerto_2025_34026",
    "sigma_web_file_upload", "sigma_web_sensitive_file_probe", "sql_injection (high)",
])
async def test_investigator_never_touches_confirmed_blocks(factory, reason):
    result, unblock = await _investigate(factory, IP_A, reason)
    assert result["action_taken"] == "block_confirmed"
    unblock.assert_not_called()


@pytest.mark.asyncio
async def test_investigator_can_still_release_ambiguous_false_positive(factory):
    result, unblock = await _investigate(factory, IP_A, "brute_force (5 attempts)")
    assert result["action_taken"] == "auto_unblocked"
    unblock.assert_awaited_once_with(IP_A)


@pytest.mark.asyncio
async def test_investigator_refuses_release_when_probe_evidence_on_record(factory):
    async with factory() as db:
        db.add(Incident(id="i1", client_id="c1", title="Probe", severity="high", source_ip=IP_B,
                        raw_alert={"request_path": "/.env"}))
        await db.commit()
    result, unblock = await _investigate(factory, IP_B, "brute_force (5 attempts)")
    assert result["action_taken"] == "block_confirmed"
    unblock.assert_not_called()


@pytest.mark.asyncio
async def test_investigator_never_releases_when_env_override_set(factory, monkeypatch):
    monkeypatch.setenv("AEGIS_BLOCKS_PERMANENT", "1")
    result, unblock = await _investigate(factory, IP_A, "brute_force (5 attempts)")
    assert result["action_taken"] == "block_confirmed"
    unblock.assert_not_called()
