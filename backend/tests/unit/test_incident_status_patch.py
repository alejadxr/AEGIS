"""PATCH /response/incidents/{id}: human verdicts, never confused with auto_closed."""
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.api import response as resp_api
from app.models.action import Action
from app.models.incident import Incident
from app.services import incident_triage, retention
from tests.unit.conftest import make_auth

IP = "203.0.113.60"


def _inc(id="i1", status="open", age=30, ip=IP, analysis=None):
    return Incident(id=id, client_id="c1", title="t", severity="high", status=status, source_ip=ip,
                    ai_analysis=analysis, detected_at=datetime.utcnow() - timedelta(days=age))


async def _patch(db, id="i1", **body):
    return await resp_api.patch_incident(id, resp_api.IncidentPatch(**body), auth=make_auth("analyst"), db=db)


def test_every_human_status_fits_the_column():
    assert all(len(s) <= 20 for s in incident_triage.HUMAN_STATUSES)
    assert "auto_closed" not in incident_triage.HUMAN_STATUSES


@pytest.mark.asyncio
async def test_sets_status_and_records_who_when_why(ops_env, db_factory):
    async with db_factory() as db:
        db.add(_inc(analysis={"keep": 1}))
        await db.commit()
        out = await _patch(db, status="false_positive", note="our monitoring agent")
        inc = await db.get(Incident, "i1")
    assert out.status == "false_positive" and inc.resolved_at is not None
    rec = inc.ai_analysis["human_triage"]
    assert rec["by"] == "op@example.com" and rec["note"] == "our monitoring agent"
    assert rec["previous_status"] == "open" and rec["at"]
    assert inc.ai_analysis["keep"] == 1                      # existing analysis untouched


@pytest.mark.asyncio
async def test_reopening_clears_resolved_at_and_keeps_history(ops_env, db_factory):
    async with db_factory() as db:
        db.add(_inc())
        await db.commit()
        await _patch(db, status="resolved")
        await _patch(db, status="investigating")
        inc = await db.get(Incident, "i1")
    assert inc.status == "investigating" and inc.resolved_at is None
    assert [h["to"] for h in inc.ai_analysis["human_triage"]["history"]] == ["resolved", "investigating"]


@pytest.mark.asyncio
async def test_rejects_machine_statuses_and_foreign_tenants(ops_env, db_factory):
    with pytest.raises(Exception):
        resp_api.IncidentPatch(status="auto_closed")
    async with db_factory() as db:
        db.add(_inc(id="other"))
        db.add(Incident(id="theirs", client_id="c2", title="t", severity="low", status="open"))
        await db.commit()
        with pytest.raises(HTTPException) as e:
            await _patch(db, id="theirs", status="resolved")
        assert e.value.status_code == 404
        with pytest.raises(HTTPException) as e:
            await _patch(db, id="other", status="resolved", unblock_source_ip=True)
        assert e.value.status_code == 400


@pytest.mark.asyncio
async def test_unblock_is_offered_not_forced(ops_env, db_factory):
    ops_env.blocker.block_ip(IP, force=True)
    async with db_factory() as db:
        db.add(_inc())
        db.add(Action(incident_id="i1", client_id="c1", action_type="block_ip", target=IP,
                      parameters={"permanent": True}, status="executed"))
        await db.commit()
        await _patch(db, status="false_positive")                       # no flag: stays blocked
        assert ops_env.blocker.is_blocked(IP)
        ops_env.pi_unblock.assert_not_awaited()
        await _patch(db, status="false_positive", unblock_source_ip=True)
        act = (await db.execute(select(Action))).scalar_one()
        inc = await db.get(Incident, "i1")
    assert not ops_env.blocker.is_blocked(IP)
    ops_env.pi_unblock.assert_awaited_with(IP)
    assert act.status == "rolled_back"                                  # no phantom "live" block left
    assert inc.ai_analysis["human_triage"]["unblock"]["done"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["open", "investigating", "resolved", "false_positive"])
async def test_retention_closer_never_touches_a_human_status(ops_env, db_factory, status, monkeypatch):
    monkeypatch.setattr(retention, "DRY_RUN", False)
    monkeypatch.setattr(retention, "_audit", lambda e: None)
    async with db_factory() as db:
        db.add(_inc(id="human", status="open", age=60))
        db.add(_inc(id="machine", status="open", age=60, ip="203.0.113.61"))
        await db.commit()
        await _patch(db, id="human", status=status)
    with patch.object(retention, "async_session", db_factory):
        summary = await retention.hourly_stuck_incident_closer()
    async with db_factory() as db:
        rows = {i.id: i for i in (await db.execute(select(Incident))).scalars().all()}
    assert rows["human"].status == status                               # the human verdict stands
    assert "auto_close" not in rows["human"].ai_analysis
    assert rows["machine"].status == "auto_closed" and summary["closed"] == 1
