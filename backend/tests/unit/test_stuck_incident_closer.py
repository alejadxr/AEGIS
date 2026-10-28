"""Stuck-incident closer: closes on inactivity, never on threat-feed membership."""
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.models.base import Base
from app.models.client import Client
from app.models.incident import Incident
from app.models.action import Action
from app.models.audit_log import AuditLog
from app.models.asset import Asset
from app.services import retention


def _ago(days):
    return datetime.utcnow() - timedelta(days=days)


@pytest_asyncio.fixture
async def factory(monkeypatch):
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
    monkeypatch.setattr(retention, "AUTOCLOSE_DAYS", 7)
    monkeypatch.setattr(retention, "AUTOCLOSE_CRITICAL_DAYS", 14)
    yield f
    await engine.dispose()


def _inc(id, status="open", severity="high", age=30, ip=None, raw=None, analysis=None):
    return Incident(id=id, client_id="c1", title="x", severity=severity, status=status,
                    source_ip=ip, raw_alert=raw, ai_analysis=analysis, detected_at=_ago(age))


async def _run(factory):
    with patch.object(retention, "async_session", factory):
        summary = await retention.hourly_stuck_incident_closer()
    async with factory() as db:
        rows = {i.id: i for i in (await db.execute(select(Incident))).scalars().all()}
    return summary, rows


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["open", "investigating", "auto_responded"])
async def test_old_inactive_incident_is_auto_closed(factory, status):
    async with factory() as db:
        db.add(_inc("a", status=status, ip="192.0.2.10"))
        await db.commit()
    summary, rows = await _run(factory)
    assert summary["closed"] == 1
    assert rows["a"].status == "auto_closed" and len(rows["a"].status) <= 20
    note = rows["a"].ai_analysis["auto_close"]
    assert "inactivity" in note["reason"] and note["previous_status"] == status
    assert rows["a"].resolved_at is not None


@pytest.mark.asyncio
async def test_recent_activity_keeps_incident_open(factory):
    async with factory() as db:
        db.add_all([
            _inc("newer_same_ip", ip="192.0.2.11", age=30),
            _inc("recent", ip="192.0.2.11", age=1, status="resolved"),
            _inc("dedup", ip="192.0.2.12", age=30,
                 analysis={"dedup": {"count": 5, "last_seen": _ago(1).isoformat()}}),
            _inc("host_a", age=30, raw={"host": "pc1.example.com"}),
            _inc("host_b", age=1, raw={"host": "pc1.example.com"}),
            _inc("has_action", ip="198.51.100.5", age=30),
        ])
        await db.flush()
        db.add(Action(incident_id="has_action", client_id="c1", action_type="block_ip",
                      target="198.51.100.5", created_at=_ago(2)))
        await db.commit()
    summary, rows = await _run(factory)
    for kept in ("newer_same_ip", "dedup", "host_a", "has_action"):
        assert rows[kept].status == "open", kept
    assert summary["closed"] == 0


@pytest.mark.asyncio
async def test_human_decisions_are_untouched(factory):
    async with factory() as db:
        db.add_all([_inc("r", status="resolved"), _inc("fp", status="false_positive")])
        await db.commit()
    summary, rows = await _run(factory)
    assert summary["closed"] == 0
    assert rows["r"].status == "resolved" and rows["fp"].status == "false_positive"


@pytest.mark.asyncio
async def test_critical_with_ongoing_activity_is_untouched(factory):
    async with factory() as db:
        db.add_all([
            _inc("crit_active", severity="critical", status="investigating", ip="203.0.113.9", age=40),
            _inc("crit_hit", severity="high", ip="203.0.113.9", age=3, status="open"),
            # quiet for 10 days: past the 7-day window but inside the critical 14-day one
            _inc("crit_quiet", severity="critical", status="open", ip="203.0.113.10", age=10),
        ])
        await db.commit()
    _, rows = await _run(factory)
    assert rows["crit_active"].status == "investigating"
    assert rows["crit_quiet"].status == "open"


@pytest.mark.asyncio
async def test_env_window_changes_outcome(factory, monkeypatch):
    async with factory() as db:
        db.add(_inc("a", age=10, ip="192.0.2.20"))
        await db.commit()
    monkeypatch.setattr(retention, "AUTOCLOSE_DAYS", 30)
    summary, rows = await _run(factory)
    assert summary["closed"] == 0 and rows["a"].status == "open"
    monkeypatch.setattr(retention, "AUTOCLOSE_DAYS", 3)
    summary, rows = await _run(factory)
    assert summary["closed"] == 1 and rows["a"].status == "auto_closed"
