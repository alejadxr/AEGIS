"""actions.status must fit every value written; one bad action must not lose the incident."""
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.models.action import Action
from app.models.base import Base
from app.models.client import Client
from app.models.incident import Incident
from app.services.ai_engine import ai_engine


@pytest_asyncio.fixture
async def factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(
            lambda c: Base.metadata.create_all(
                c, tables=[Client.__table__, Incident.__table__, Action.__table__]
            )
        )
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def test_status_column_fits_longest_status():
    assert Action.__table__.c.status.type.length >= len("skipped_not_applicable")


@pytest.mark.asyncio
async def test_long_status_action_persists(factory):
    async with factory() as db:
        db.add(Client(id="c1", name="t", slug="t", api_key="k"))
        db.add(Incident(id="i1", client_id="c1", title="x", severity="high", status="open"))
        await db.commit()
        client = await db.get(Client, "c1")
        a = await ai_engine._create_unsupported_action(
            client=client, action_type="isolate_host", reason="no host",
            threat_type="rce", db=db, incident_id="i1",
        )
        assert a.status == "skipped_not_applicable"
    async with factory() as db:
        row = (await db.execute(select(Action))).scalar_one()
        assert row.status == "skipped_not_applicable"


@pytest.mark.asyncio
async def test_failing_action_does_not_lose_incident(factory):
    async with factory() as db:
        db.add(Client(id="c1", name="t", slug="t", api_key="k"))
        await db.commit()
        client = await db.get(Client, "c1")
        alert = {"title": "x", "severity": "critical", "threat_type": "rce",
                 "source_ip": "8.8.4.4"}
        triage = {"severity": "critical", "threat_type": "rce", "summary": "s", "confidence": 0.9}
        boom = AsyncMock(side_effect=RuntimeError("StringDataRightTruncationError"))
        with patch.object(ai_engine, "_triage", AsyncMock(return_value=triage)), \
             patch.object(ai_engine, "_classify", AsyncMock(return_value={})), \
             patch.object(ai_engine, "_log_audit", AsyncMock()), \
             patch.object(ai_engine, "_create_unsupported_action", boom), \
             patch("app.services.ai_engine.guardrail_engine.evaluate_action", boom):
            result = await ai_engine.process_alert(alert, client, db)
        assert result["stage"] == "completed"
        assert result["actions_taken"]
        assert all(a["status"] == "persist_failed" for a in result["actions_taken"])
    async with factory() as db:
        assert (await db.execute(select(Incident))).scalars().all()
