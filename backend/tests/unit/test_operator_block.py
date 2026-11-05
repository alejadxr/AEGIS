"""POST /firewall/blocked: operator block through the detector's own execution path."""
from datetime import datetime

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.api import firewall as fw_api
from app.core import safelist_store as store
from app.models.action import Action
from app.models.incident import Incident
from tests.unit.conftest import make_auth

IP = "203.0.113.77"


def _req(ip=IP, **kw):
    return fw_api.BlockRequest(ip=ip, reason=kw.pop("reason", "confirmed scanner, per operator"), **kw)


async def _block(db, **kw):
    return await fw_api.block_ip(_req(**kw), auth=make_auth(), db=db)


@pytest.mark.asyncio
async def test_operator_block_is_permanent_and_reaches_every_layer(ops_env, db_factory):
    async with db_factory() as db:
        out = await _block(db, threat_type="scanner", severity="high")
        assert out["blocked"] and out["permanent"] and out["expires_at"] is None
        act = (await db.execute(select(Action))).scalar_one()
    # Pi agent: force=true (operator evidence), with the reason it will show later
    _, kw = ops_env.pi_block.await_args
    assert ops_env.pi_block.await_args.args[0] == IP
    assert kw["force"] is True and "per operator" in kw["reason"]
    assert kw["threat_type"] == "scanner" and kw["severity"] == "high"
    # 403 blocklist (+ file) and the system firewall layer
    assert ops_env.blocker.is_blocked(IP) and IP in (ops_env.tmp / "blocked_ips.txt").read_text()
    assert ("block", IP) in ops_env.sysfw.calls
    # Recorded like every other permanent block, so retention never releases it
    assert act.status == "executed" and act.parameters["permanent"] is True
    assert "provisional" not in act.parameters and "expires_at" not in act.parameters
    assert act.approved_by == "op@example.com"


@pytest.mark.asyncio
async def test_duration_makes_it_provisional_so_retention_expires_it(ops_env, db_factory):
    async with db_factory() as db:
        out = await _block(db, duration_s=3600)
        act = (await db.execute(select(Action))).scalar_one()
    assert not out["permanent"] and out["expires_at"]
    assert act.parameters["provisional"] is True
    assert datetime.fromisoformat(act.parameters["expires_at"]) > datetime.utcnow()


@pytest.mark.asyncio
async def test_blocks_permanent_env_overrides_duration(ops_env, db_factory, monkeypatch):
    monkeypatch.setenv("AEGIS_BLOCKS_PERMANENT", "1")
    async with db_factory() as db:
        out = await _block(db, duration_s=3600)
    assert out["permanent"] and "AEGIS_BLOCKS_PERMANENT" in out["message"]


@pytest.mark.asyncio
async def test_attaches_to_existing_incident_or_makes_a_closed_stub(ops_env, db_factory):
    async with db_factory() as db:
        db.add(Incident(id="inc1", client_id="c1", title="x", severity="high", source_ip=IP))
        await db.commit()
        out = await _block(db, incident_id="inc1")
        assert out["incident_id"] == "inc1"
        out2 = await _block(db, ip="203.0.113.78")
        stub = await db.get(Incident, out2["incident_id"])
        assert stub.status == "resolved" and stub.source == "operator"
        with pytest.raises(HTTPException) as e:
            await _block(db, ip="203.0.113.79", incident_id="nope")
        assert e.value.status_code == 404


@pytest.mark.asyncio
async def test_refuses_safelisted_runtime_entry(ops_env, db_factory):
    store.add("safe", IP, False, "t")
    async with db_factory() as db:
        with pytest.raises(HTTPException) as e:
            await _block(db)
    assert e.value.status_code == 409 and e.value.detail["code"] == "safelisted"
    ops_env.pi_block.assert_not_awaited()
    assert not ops_env.blocker.is_blocked(IP)


@pytest.mark.asyncio
async def test_refuses_the_owners_own_addresses(ops_env, db_factory, monkeypatch):
    monkeypatch.setattr(ops_env.ad, "_internal_ips_literals", {"198.51.100.20"})
    store.add("internal", "198.51.100.0/24", True, "t")
    async with db_factory() as db:
        for ip, code in (("198.51.100.20", "internal"), ("198.51.100.99", "internal"),
                         ("10.1.2.3", "protected_range"), ("192.168.1.5", "protected_range"),
                         ("127.0.0.2", "invalid_ip")):
            with pytest.raises(HTTPException) as e:
                await _block(db, ip=ip)
            assert e.value.detail["code"] == code, ip
    ops_env.pi_block.assert_not_awaited()


@pytest.mark.asyncio
async def test_refuses_shared_consumer_egress(ops_env, db_factory):
    async with db_factory() as db:
        for ip in ("104.28.4.4",):   # built-in WARP range
            with pytest.raises(HTTPException) as e:
                await _block(db, ip=ip)
            assert e.value.status_code == 409 and e.value.detail["code"] == "shared_egress"
        store.add("shared_egress", "192.0.2.0/24", True, "t")
        with pytest.raises(HTTPException) as e:
            await _block(db, ip="192.0.2.5")
        assert e.value.detail["code"] == "shared_egress"
    ops_env.pi_block.assert_not_awaited()


@pytest.mark.parametrize("bad,code", [("203.0.113.0/24", "cidr_unsupported"), ("999.1.1.1", "invalid_ip"),
                                      ("0.0.0.0", "invalid_ip"), ("224.0.0.1", "invalid_ip"), ("abc", "invalid_ip")])
@pytest.mark.asyncio
async def test_only_single_routable_addresses(ops_env, db_factory, bad, code):
    async with db_factory() as db:
        with pytest.raises(HTTPException) as e:
            await _block(db, ip=bad)
    assert e.value.status_code == 400 and e.value.detail["code"] == code


@pytest.mark.asyncio
async def test_reports_failure_when_no_layer_took_it(ops_env, db_factory, monkeypatch):
    ops_env.pi_block.return_value = {"success": False, "error": "down"}
    ops_env.sysfw.block = lambda ip: False
    monkeypatch.setattr(ops_env.blocker, "block_ip", lambda ip, force=False: {"success": False})
    async with db_factory() as db:
        with pytest.raises(HTTPException) as e:
            await _block(db)
    assert e.value.status_code == 502 and e.value.detail["code"] == "block_failed"


def test_reason_is_required():
    with pytest.raises(Exception):
        fw_api.BlockRequest(ip=IP)
    with pytest.raises(Exception):
        fw_api.BlockRequest(ip=IP, reason="")
