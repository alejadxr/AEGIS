"""An explicitly time-boxed block expires as asked; AEGIS's own provisional guess is still promotable."""
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from sqlalchemy import select

from app.api import firewall as fw_api
from app.models.action import Action
from app.models.incident import Incident
from app.services import assistant_actions as aa
from app.services import retention
from tests.unit.conftest import make_auth

IP = "203.0.113.90"


async def _seed_probe_history(db, ip=IP):
    # request-path evidence that makes block_policy.probe_evidence() fire
    db.add(Incident(id="probe", client_id="c1", title="p", severity="high", source_ip=ip,
                    raw_alert={"request_path": "/.env"}))
    await db.commit()


async def _age(db):
    for a in (await db.execute(select(Action))).scalars().all():
        a.parameters = {**a.parameters, "expires_at": (datetime.utcnow() - timedelta(minutes=1)).isoformat()}
    await db.commit()


async def _expire(db_factory, monkeypatch):
    monkeypatch.setattr(retention, "DRY_RUN", False)
    monkeypatch.setattr(retention, "_audit", lambda e: None)
    with patch.object(retention, "async_session", db_factory):
        return await retention.expire_provisional_blocks()


@pytest.mark.asyncio
async def test_operator_time_boxed_block_expires_despite_probe_history(ops_env, db_factory, monkeypatch):
    async with db_factory() as db:
        await _seed_probe_history(db)
        await fw_api.block_ip(fw_api.BlockRequest(ip=IP, reason="24h please", duration_s=86400),
                              auth=make_auth(), db=db)
        act = (await db.execute(select(Action))).scalar_one()
        assert act.parameters["duration_explicit"] is True and act.parameters["requested_by"] == "op@example.com"
        await _age(db)
    summary = await _expire(db_factory, monkeypatch)
    async with db_factory() as db:
        act = (await db.execute(select(Action))).scalar_one()
    assert act.status == "expired" and not act.parameters.get("permanent")
    assert summary["expired"] == 1 and not summary.get("promoted")
    ops_env.pi_unblock.assert_awaited_with(IP)


@pytest.mark.asyncio
async def test_aegis_own_provisional_on_same_ip_is_still_promoted(ops_env, db_factory, monkeypatch):
    async with db_factory() as db:
        await _seed_probe_history(db)
        db.add(Action(incident_id="probe", client_id="c1", action_type="block_ip", target=IP, status="approved",
                      parameters={"provisional": True, "block_class": "ambiguous",
                                  "expires_at": (datetime.utcnow() - timedelta(minutes=1)).isoformat()}))
        await db.commit()
    summary = await _expire(db_factory, monkeypatch)
    async with db_factory() as db:
        act = (await db.execute(select(Action))).scalar_one()
    assert summary["promoted"] == 1 and act.parameters["permanent"] is True and "provisional" not in act.parameters


@pytest.mark.asyncio
async def test_assistant_24h_block_cannot_become_permanent(ops_env, db_factory, monkeypatch):
    async with db_factory() as db:
        await _seed_probe_history(db)
        taken, _ = await aa.process(db, auth=make_auth(), message=f"block {IP}",
                                    items=[{"kind": "block_ip", "ip": IP, "reason": "x"}])
        assert taken[0]["status"] == "executed" and not taken[0]["permanent"]
        act = (await db.execute(select(Action))).scalar_one()
        assert act.parameters["duration_explicit"] is True
        await _age(db)
    await _expire(db_factory, monkeypatch)
    async with db_factory() as db:
        act = (await db.execute(select(Action))).scalar_one()
    assert act.status == "expired" and not act.parameters.get("permanent")
