"""A block must be lifted on every layer or not reported as lifted (audit A4, A5, M2, M4, B4)."""
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.models.action import Action
from app.models.incident import Incident

IP = "203.0.113.77"


async def _incident(db):
    # Ambiguous class (brute force) so the block stays provisional.
    db.add(Incident(id="inc1", client_id="c1", title="brute force", severity="medium",
                    source_ip=IP, raw_alert={"threat_type": "brute_force"}))


def _provisional(action_id="a1", status="executed", hours_ago=1):
    return Action(
        id=action_id, client_id="c1", incident_id="inc1", action_type="block_ip", target=IP, status=status,
        parameters={"provisional": True,
                    "expires_at": (datetime.utcnow() - timedelta(hours=hours_ago)).isoformat()},
    )


# --- A4: rollback -----------------------------------------------------------

async def test_rollback_lifts_pi_local_and_system_firewall(ops_env, db_factory):
    from app.modules.response.responder import active_responder
    ops_env.blocker.block_ip(IP, force=True)
    async with db_factory() as db:
        await _incident(db)
        action = _provisional()
        db.add(action)
        await db.commit()
        result = await active_responder.rollback_action(action, db)
    assert result["success"] is True
    ops_env.pi_unblock.assert_awaited_once_with(IP)
    assert IP not in ops_env.blocker.list_blocked()
    assert ("unblock", IP) in ops_env.sysfw.calls
    assert action.status == "rolled_back"


async def test_rollback_fails_closed_when_the_pi_refuses(ops_env, db_factory):
    from app.modules.response.responder import active_responder
    ops_env.blocker.block_ip(IP, force=True)
    ops_env.pi_unblock.return_value = {"success": False, "error": "timeout"}
    async with db_factory() as db:
        await _incident(db)
        action = _provisional()
        db.add(action)
        await db.commit()
        result = await active_responder.rollback_action(action, db)
    assert result["success"] is False
    # Still executed => retention can still expire it; still blocked locally.
    assert action.status == "executed"
    assert IP in ops_env.blocker.list_blocked()


async def test_unimplemented_and_unknown_actions_do_not_claim_success():
    from app.modules.response.responder import active_responder
    for fn in (active_responder._add_firewall_rule, active_responder._generic_action,
               active_responder._remove_firewall_rule, active_responder._unisolate_host):
        assert (await fn("203.0.113.1", {}))["success"] is False


# --- A5: expiry ---------------------------------------------------------------

@pytest.fixture
def retention_env(ops_env, db_factory, monkeypatch):
    from app.services import retention
    monkeypatch.setattr(retention, "async_session", db_factory)
    monkeypatch.setattr(retention, "DRY_RUN", False)
    monkeypatch.setattr(retention, "firewall_client",
                        SimpleNamespace(unblock_ip=ops_env.pi_unblock), raising=False)
    monkeypatch.setattr(retention, "ip_blocker_service", ops_env.blocker, raising=False)
    from app.services import block_policy
    monkeypatch.setattr(block_policy, "probe_evidence", AsyncMock(return_value=None))
    return retention


async def _status(db_factory, action_id="a1"):
    async with db_factory() as db:
        return (await db.get(Action, action_id)).status


async def test_expiry_keeps_the_block_when_the_pi_does_not_lift_it(ops_env, db_factory, retention_env):
    ops_env.blocker.block_ip(IP, force=True)
    ops_env.pi_unblock.return_value = {"success": False, "error": "connection refused"}
    async with db_factory() as db:
        await _incident(db)
        db.add(_provisional())
        await db.commit()
    summary = await retention_env.expire_provisional_blocks()
    assert summary["expired"] == 0 and summary["failed"] == 1
    assert await _status(db_factory) == "executed"        # retried next cycle
    assert IP in ops_env.blocker.list_blocked()           # not half-lifted


async def test_expiry_lifts_everything_when_the_pi_confirms(ops_env, db_factory, retention_env):
    ops_env.blocker.block_ip(IP, force=True)
    async with db_factory() as db:
        await _incident(db)
        db.add(_provisional())
        await db.commit()
    summary = await retention_env.expire_provisional_blocks()
    assert summary["expired"] == 1
    assert await _status(db_factory) == "expired"
    assert IP not in ops_env.blocker.list_blocked()


# --- M2 / M4: sync with the Pi -----------------------------------------------

async def test_unreadable_pi_is_not_an_empty_blocklist(monkeypatch):
    import httpx
    from app.core import firewall_client as fc

    class Boom:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): raise httpx.ConnectError("down")
        async def __aexit__(self, *a): return False

    monkeypatch.setattr(fc.httpx, "AsyncClient", Boom)
    assert await fc.firewall_client.get_blocked_strict() is None
    assert await fc.firewall_client.get_blocked() == []


async def test_pull_evicts_nothing_while_the_pi_is_unreadable(ops_env, monkeypatch):
    from app.services import firewall_sync
    ops_env.blocker.block_ip(IP, force=True)
    monkeypatch.setattr(firewall_sync, "ip_blocker_service", ops_env.blocker)
    monkeypatch.setattr(firewall_sync, "_STALE_LOCAL_EVICT_HOURS", 0)
    monkeypatch.setattr(firewall_sync, "_LOCAL_ONLY_FIRST_SEEN", {IP: datetime.utcnow() - timedelta(days=3)})
    monkeypatch.setattr(firewall_sync.firewall_client, "get_blocked_strict", AsyncMock(return_value=None))
    result = await firewall_sync._pull_blocklist_from_pi()
    assert result["skipped"] == "pi_unreachable" and result["evicted"] == 0
    assert IP in ops_env.blocker.list_blocked()


async def test_live_block_missing_on_the_pi_is_repushed_not_evicted(ops_env, db_factory, monkeypatch):
    from app.services import firewall_sync
    ops_env.blocker.block_ip(IP, force=True)
    monkeypatch.setattr(firewall_sync, "ip_blocker_service", ops_env.blocker)
    monkeypatch.setattr(firewall_sync, "_STALE_LOCAL_EVICT_HOURS", 0)
    monkeypatch.setattr(firewall_sync, "_LOCAL_ONLY_FIRST_SEEN", {IP: datetime.utcnow() - timedelta(days=3)})
    monkeypatch.setattr(firewall_sync.firewall_client, "get_blocked_strict", AsyncMock(return_value=[]))
    async with db_factory() as db:
        await _incident(db)
        db.add(Action(id="p1", client_id="c1", incident_id="inc1", action_type="block_ip", target=IP,
                      status="executed", parameters={"permanent": True}))
        await db.commit()
        result = await firewall_sync._pull_blocklist_from_pi(db)
    assert result["repushed"] == 1 and result["evicted"] == 0
    assert IP in ops_env.blocker.list_blocked()
    assert ops_env.pi_block.await_args.args[0] == IP
    assert ops_env.pi_block.await_args.kwargs.get("force") is True
