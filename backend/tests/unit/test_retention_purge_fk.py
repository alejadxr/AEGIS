"""Nightly purge must delete FK children of incidents before the incidents."""
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
import pytest_asyncio
from sqlalchemy import event, select, func
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.models.base import Base
from app.models.client import Client
from app.models.incident import Incident
from app.models.action import Action
from app.models.audit_log import AuditLog
from app.models.attacker_profile import AttackerProfile
from app.models.honeypot import Honeypot, HoneypotInteraction
from app.models.asset import Asset
from app.services import retention


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    @event.listens_for(engine.sync_engine, "connect")
    def _fk_on(dbapi_conn, _rec):  # enforce FKs like Postgres does
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    tables = [Client, Asset, Incident, Action, AuditLog, AttackerProfile, Honeypot, HoneypotInteraction]
    async with engine.begin() as conn:
        await conn.run_sync(
            lambda c: Base.metadata.create_all(c, tables=[m.__table__ for m in tables])
        )
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


async def _seed(factory, n_old=3):
    old = datetime.utcnow() - timedelta(days=retention.RETENTION_DAYS + 5)
    async with factory() as db:
        db.add(Client(id="c1", name="t", slug="t", api_key="k"))
        await db.flush()
        for i in range(n_old):
            db.add(Incident(id=f"old{i}", client_id="c1", title="x", severity="high",
                            status="resolved", detected_at=old))
        db.add(Incident(id="fresh", client_id="c1", title="x", severity="high",
                        status="resolved", detected_at=datetime.utcnow()))
        await db.flush()
        for i in range(n_old):
            db.add(Action(incident_id=f"old{i}", client_id="c1", action_type="block_ip",
                          target="203.0.113.7"))
            db.add(AuditLog(client_id="c1", incident_id=f"old{i}", action="triage"))
        db.add(Action(incident_id="fresh", client_id="c1", action_type="block_ip",
                      target="203.0.113.8"))
        await db.commit()


@pytest.mark.asyncio
async def test_purge_deletes_incidents_with_actions_and_audit(session_factory, monkeypatch):
    await _seed(session_factory)
    monkeypatch.setattr(retention, "DRY_RUN", False)
    monkeypatch.setattr(retention, "PURGE_BATCH_SIZE", 2)  # force multiple batches
    monkeypatch.setattr(retention, "_audit", lambda e: None)
    with patch.object(retention, "async_session", session_factory):
        summary = await retention.nightly_retention_purge()

    assert summary["incidents"] == 3
    async with session_factory() as db:
        ids = {r[0] for r in (await db.execute(select(Incident.id))).all()}
        assert ids == {"fresh"}
        assert (await db.execute(select(func.count(Action.id)))).scalar() == 1
        # audit trail is kept, detached from the purged incident
        logs = (await db.execute(select(AuditLog))).scalars().all()
        assert len(logs) == 3 and all(l.incident_id is None for l in logs)


@pytest.mark.asyncio
async def test_purge_dry_run_changes_nothing(session_factory, monkeypatch):
    await _seed(session_factory)
    monkeypatch.setattr(retention, "DRY_RUN", True)
    monkeypatch.setattr(retention, "_audit", lambda e: None)
    with patch.object(retention, "async_session", session_factory):
        summary = await retention.nightly_retention_purge()
    assert summary["incidents"] == 3
    async with session_factory() as db:
        assert (await db.execute(select(func.count(Incident.id)))).scalar() == 4
