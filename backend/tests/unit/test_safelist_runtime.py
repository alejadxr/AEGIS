"""Runtime safelist: live without a restart, persisted, env entries pinned."""
import json

import pytest
from fastapi import HTTPException

from app.api import firewall as fw_api
from app.core import attack_detector as ad
from app.core import safelist_store as store
from app.services import safelist as svc
from tests.unit.conftest import make_auth

IP = "203.0.113.50"


@pytest.mark.asyncio
async def test_addition_takes_effect_without_restart(ops_env, db_factory):
    assert not ad._is_safe_ip(IP)
    async with db_factory() as db:
        out = await fw_api.add_safelist_entry("internal", fw_api.SafelistAdd(value=IP, note="office"),
                                              auth=make_auth(), db=db)
    assert out["created"] and out["value"] == IP
    assert ad._is_safe_ip(IP)                      # same process, no reload call
    assert not ad._is_safe_ip("203.0.113.51")


@pytest.mark.asyncio
async def test_cidr_and_shared_egress_categories(ops_env, db_factory):
    async with db_factory() as db:
        await fw_api.add_safelist_entry("safe", fw_api.SafelistAdd(value="198.51.100.0/24"), auth=make_auth(), db=db)
        await fw_api.add_safelist_entry("shared_egress", fw_api.SafelistAdd(value="192.0.2.0/25"), auth=make_auth(), db=db)
    assert ad._is_safe_ip("198.51.100.77")
    assert ad.is_shared_egress("192.0.2.9") and not ad.is_shared_egress("192.0.2.200")
    assert not ad._is_safe_ip("192.0.2.9")          # shared egress is NOT "safe": still detected


@pytest.mark.asyncio
async def test_survives_a_restart(ops_env, db_factory):
    async with db_factory() as db:
        await fw_api.add_safelist_entry("internal", fw_api.SafelistAdd(value=IP), auth=make_auth(), db=db)
    doc = json.loads(ops_env.safelist_file.read_text())
    assert doc["internal"][0]["value"] == IP and doc["internal"][0]["added_by"] == "op@example.com"
    # A restart = module state gone, file still there.
    store._snapshot = store._Snapshot(store._empty())
    store._next_check = float("inf")               # no mtime-triggered refresh: only load() can restore it
    assert not ad._is_safe_ip(IP)
    store.load()
    assert ad._is_safe_ip(IP)


def test_change_by_another_worker_is_picked_up(ops_env, monkeypatch):
    """Two API workers: B must see what A wrote, via the throttled mtime check."""
    assert not ad._is_safe_ip(IP)
    ops_env.safelist_file.write_text(json.dumps({"version": 1, "safe": [{"value": IP}]}))
    monkeypatch.setattr(store, "_next_check", 0.0)
    assert ad._is_safe_ip(IP)


@pytest.mark.asyncio
async def test_env_pinned_entry_cannot_be_removed(ops_env, db_factory, monkeypatch):
    monkeypatch.setattr(ad, "_internal_ips_literals", {"198.51.100.9"})
    async with db_factory() as db:
        with pytest.raises(HTTPException) as e:
            await fw_api.remove_safelist_entry("internal", value="198.51.100.9", auth=make_auth(), db=db)
    assert e.value.status_code == 409
    assert e.value.detail["code"] == "env_pinned" and e.value.detail["var"] == "AEGIS_INTERNAL_IPS"
    assert "restart" in e.value.detail["message"]


@pytest.mark.asyncio
async def test_runtime_entry_can_be_removed_and_reports_env_overlap(ops_env, db_factory, monkeypatch):
    async with db_factory() as db:
        await fw_api.add_safelist_entry("safe", fw_api.SafelistAdd(value=IP), auth=make_auth(), db=db)
        out = await fw_api.remove_safelist_entry("safe", value=IP, auth=make_auth(), db=db)
        assert out["removed"] and not ad._is_safe_ip(IP)
        with pytest.raises(HTTPException) as e:
            await fw_api.remove_safelist_entry("safe", value=IP, auth=make_auth(), db=db)
        assert e.value.status_code == 404
        # Same value in both layers: runtime copy goes, env copy is reported.
        monkeypatch.setattr(ad, "_safe_ips_literals", {IP})
        await fw_api.add_safelist_entry("safe", fw_api.SafelistAdd(value=IP), auth=make_auth(), db=db)
        out = await fw_api.remove_safelist_entry("safe", value=IP, auth=make_auth(), db=db)
        assert out["still_in_env"] and "AEGIS_SAFE_IPS" in out["message"]


def test_listing_tags_each_entry_with_its_source(ops_env, monkeypatch):
    monkeypatch.setattr(ad, "_safe_ips_literals", {"198.51.100.9"})
    store.add("safe", IP, False, "tester")
    entries = {e["value"]: e["source"] for e in svc.list_category("safe")}
    assert entries == {"198.51.100.9": "env", IP: "runtime"}


@pytest.mark.parametrize("bad", ["0.0.0.0/0", "10.0.0.0/8", "::/0", "not-an-ip", "", "localhost", "203.0.113.1/33"])
@pytest.mark.asyncio
async def test_dangerous_or_malformed_values_are_refused(ops_env, db_factory, bad):
    async with db_factory() as db:
        with pytest.raises(HTTPException) as e:
            await fw_api.add_safelist_entry("safe", fw_api.SafelistAdd(value=bad or " x"), auth=make_auth(), db=db)
    assert e.value.status_code == 400
    assert not ops_env.safelist_file.exists()


@pytest.mark.asyncio
async def test_adding_does_not_unblock_unless_asked(ops_env, db_factory):
    ops_env.blocker.block_ip(IP, force=True)
    async with db_factory() as db:
        out = await fw_api.add_safelist_entry("internal", fw_api.SafelistAdd(value=IP), auth=make_auth(), db=db)
        assert out["currently_blocked"] == [IP] and out["unblocked"] == []
        assert "still blocked" in out["message"] and ops_env.blocker.is_blocked(IP)
        out = await fw_api.add_safelist_entry("internal", fw_api.SafelistAdd(value=IP, unblock_if_blocked=True),
                                              auth=make_auth(), db=db)
    assert not ops_env.blocker.is_blocked(IP)
    ops_env.pi_unblock.assert_awaited_with(IP)
    assert ("unblock", IP) in ops_env.sysfw.calls
