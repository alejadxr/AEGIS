"""Shared consumer egress (WARP / Private Relay): detected and alerted on, never
auto-blocked.

Documentation addresses are used everywhere except where a REAL published range
has to be asserted (104.28.x for Cloudflare WARP, Apple's relay list).
"""
import asyncio
import importlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

import app.core.attack_detector as ad

# Documentation-range stand-ins for "a shared egress address" and "a normal one".
EGRESS = "198.51.100.77"
NORMAL = "203.0.113.50"
EGRESS_V6 = "2001:db8:ee::7"
# The five addresses AEGIS wrongly blocked on 2026-10-28 (real WARP egress).
REAL_WARP = ["104.28.201.73", "104.28.201.80", "104.28.222.16", "104.28.222.18", "104.28.222.43"]


@pytest.fixture
def egress(monkeypatch):
    """Register the documentation IPs as shared egress without touching real ranges."""
    monkeypatch.setattr(ad, "_shared_egress_literals", {EGRESS, EGRESS_V6})
    monkeypatch.setattr(
        ad, "_SHARED_EGRESS_NETWORKS",
        list(ad._SHARED_EGRESS_NETWORKS) + [ad._ipaddress.ip_network("192.0.2.0/25")],
    )


def _run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------- #
# Predicate
# --------------------------------------------------------------------------- #
def test_real_warp_addresses_are_shared_egress():
    for ip in REAL_WARP:
        assert ad.is_shared_egress(ip), ip


def test_private_relay_list_is_loaded_and_matches():
    assert ad._SHARED_EGRESS_V4 and ad._SHARED_EGRESS_V6
    first4 = ad._SHARED_EGRESS_V4[0][0]
    first6 = ad._SHARED_EGRESS_V6[0][0]
    assert ad.is_shared_egress(str(ad._ipaddress.ip_address(first4)))
    assert ad.is_shared_egress(str(ad._ipaddress.ip_address(first6)))
    # the address just past a range that is not adjacent to the next one must miss
    for (_, last), (nxt, _) in zip(ad._SHARED_EGRESS_V4, ad._SHARED_EGRESS_V4[1:]):
        if nxt > last + 1 and not any(
            ad._ipaddress.ip_address(last + 1) in n for n in ad._SHARED_EGRESS_NETWORKS
        ):
            assert not ad.is_shared_egress(str(ad._ipaddress.ip_address(last + 1)))
            break


def test_ordinary_and_malformed_inputs_are_not_shared_egress():
    for ip in (NORMAL, "8.8.8.8", "2001:db8::1", "", None, "not-an-ip", "104.28.300.1", 42):
        assert ad.is_shared_egress(ip) is False


def test_predicate_matches_registered_literals_and_cidrs(egress):
    assert ad.is_shared_egress(EGRESS)
    assert ad.is_shared_egress(EGRESS_V6)
    assert ad.is_shared_egress("192.0.2.9")
    assert not ad.is_shared_egress("192.0.2.200")


def test_shared_egress_is_not_folded_into_the_safe_gate(egress):
    """It must stay detectable: _is_safe_ip also suppresses incidents."""
    assert ad.is_shared_egress(EGRESS)
    assert ad._is_safe_ip(EGRESS) is False
    for ip in REAL_WARP:
        assert ad._is_safe_ip(ip) is False


def test_env_override_extends_the_list(monkeypatch):
    monkeypatch.setenv("AEGIS_SHARED_EGRESS_IPS", f"{EGRESS}, 192.0.2.0/25 ,bogus/xx")
    try:
        importlib.reload(ad)
        assert ad.is_shared_egress(EGRESS)
        assert ad.is_shared_egress("192.0.2.5")
        assert not ad.is_shared_egress(NORMAL)
        assert ad.is_shared_egress(REAL_WARP[0])  # built-ins survive the override
    finally:
        monkeypatch.delenv("AEGIS_SHARED_EGRESS_IPS")
        importlib.reload(ad)
    assert not ad.is_shared_egress(EGRESS)


# --------------------------------------------------------------------------- #
# attack_detector._block_ip: no block, incident still raised
# --------------------------------------------------------------------------- #
@pytest.fixture
def detector(monkeypatch, tmp_path):
    import app.core.ip_blocker as ipb
    monkeypatch.setattr(ad, "BLOCKED_IPS_FILE", tmp_path / "ad_blocked.txt")
    monkeypatch.setattr(ipb, "BLOCKED_IPS_FILE", tmp_path / "ipb_blocked.txt")
    monkeypatch.setattr(ipb.ip_blocker_service, "_blocked", set())
    monkeypatch.setattr(ad, "_blocked_ips", set())
    monkeypatch.setattr(ad, "_shared_egress_incident_at", {})
    spies = SimpleNamespace(
        incident=AsyncMock(), notify=AsyncMock(), mongo=AsyncMock(),
        investigate=AsyncMock(), ipb=ipb,
    )
    monkeypatch.setattr(ad, "_create_block_incident", spies.incident)
    monkeypatch.setattr(ad, "_notify_firewall", spies.notify)
    monkeypatch.setattr(ad, "_share_to_mongo", spies.mongo)
    import app.services.ip_investigator as inv
    monkeypatch.setattr(inv.ip_investigator, "investigate_blocked_ip", spies.investigate)
    return spies


async def _block_and_drain(ip, reason="sqli (high)"):
    await ad._block_ip(ip, reason)
    await asyncio.sleep(0)  # let the fire-and-forget tasks run


def test_detector_does_not_block_shared_egress_but_raises_incident(egress, detector, tmp_path):
    _run(_block_and_drain(EGRESS))
    assert EGRESS not in ad._blocked_ips
    assert not (tmp_path / "ad_blocked.txt").exists()
    assert not detector.ipb.ip_blocker_service.is_blocked(EGRESS)
    detector.notify.assert_not_called()
    detector.mongo.assert_not_called()
    detector.investigate.assert_not_called()
    detector.incident.assert_awaited_once_with(EGRESS, "sqli (high)", blocked=False)


def test_detector_dedups_shared_egress_incidents(egress, detector):
    async def go():
        for _ in range(5):
            await _block_and_drain(EGRESS)
    _run(go())
    assert detector.incident.await_count == 1


def test_detector_still_blocks_a_normal_ip(egress, detector):
    _run(_block_and_drain(NORMAL))
    assert NORMAL in ad._blocked_ips
    assert detector.ipb.ip_blocker_service.is_blocked(NORMAL)
    detector.notify.assert_awaited_once()
    detector.incident.assert_awaited_once_with(NORMAL, "sqli (high)")


def test_incident_text_says_plainly_it_was_not_blocked():
    title, desc = ad._block_incident_text(EGRESS, "sqli (high)", blocked=False)
    assert "NOT blocked" in title
    assert "NOT blocked" in desc and "shared consumer egress" in desc
    title, desc = ad._block_incident_text(NORMAL, "sqli (high)", blocked=True)
    assert "Auto-blocked" in title and "shared" not in desc


def test_incident_row_is_created_for_shared_egress(egress, monkeypatch):
    """The real _create_block_incident writes an open critical incident."""
    added = []

    class _Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def execute(self, _q):
            return SimpleNamespace(scalar_one_or_none=lambda: SimpleNamespace(id="client-1"))

        def add(self, obj):
            added.append(obj)

        async def commit(self):
            pass

    import app.database as database
    monkeypatch.setattr(database, "async_session", lambda: _Session())
    _run(ad._create_block_incident(EGRESS, "scanner UA", blocked=False))
    assert len(added) == 1
    inc = added[0]
    assert inc.source_ip == EGRESS and inc.severity == "critical" and inc.status == "open"
    assert "NOT blocked" in inc.description


# --------------------------------------------------------------------------- #
# ip_blocker chokepoint (dos_shield local, playbooks, log_watcher, hub sync, ...)
# --------------------------------------------------------------------------- #
def test_ip_blocker_refuses_shared_egress_unless_forced(egress, detector):
    svc = detector.ipb.ip_blocker_service
    r = svc.block_ip(EGRESS)
    assert r["success"] is False and r["skipped"] == "shared_egress"
    assert not svc.is_blocked(EGRESS)
    assert svc.block_ip(EGRESS, force=True)["success"] is True
    assert svc.is_blocked(EGRESS)


def test_ip_blocker_still_blocks_normal_ip(egress, detector):
    assert detector.ipb.ip_blocker_service.block_ip(NORMAL)["success"] is True


# --------------------------------------------------------------------------- #
# guardrails
# --------------------------------------------------------------------------- #
def _db():
    db = MagicMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    return db


def _eval(action_type, target, guardrails=None):
    from app.core.guardrails import GuardrailEngine
    client = SimpleNamespace(id="c1", guardrails=guardrails)
    return _run(GuardrailEngine().evaluate_action(
        client=client, action_type=action_type, target=target,
        ai_reasoning="probe", db=_db(), incident_id="i1",
    ))


def test_guardrail_requires_approval_for_shared_egress_block(egress):
    for action_type in ("block_ip", "firewall_rule"):
        a = _eval(action_type, EGRESS)
        assert a.status == "pending" and a.requires_approval is True
        assert "shared consumer egress" in a.ai_reasoning


def test_guardrail_still_auto_approves_normal_ip(egress):
    a = _eval("block_ip", NORMAL)
    assert a.status == "approved" and a.requires_approval is False


def test_guardrail_leaves_non_blocking_actions_alone(egress):
    a = _eval("intel_lookup", EGRESS)
    assert a.status == "approved"


# --------------------------------------------------------------------------- #
# responder: auto path refuses, operator-approved path blocks
# --------------------------------------------------------------------------- #
def _action(target, approved_by=None):
    return SimpleNamespace(
        id="a1", status="approved", action_type="block_ip", target=target,
        parameters={}, ai_reasoning="probe", approved_by=approved_by,
        client_id=None, incident_id="i1", result=None, executed_at=None,
    )


@pytest.fixture
def responder(monkeypatch, detector):
    from app.modules.response import responder as rmod
    fw = AsyncMock(return_value={"success": True})
    monkeypatch.setattr(rmod.firewall_client, "block_ip", fw)
    monkeypatch.setattr(rmod.firewall_local, "get_firewall", lambda: SimpleNamespace(block=lambda ip: True))
    db = SimpleNamespace(commit=AsyncMock())
    return SimpleNamespace(r=rmod.ActiveResponder(), fw=fw, db=db, ipb=detector.ipb)


def test_responder_refuses_unapproved_shared_egress(egress, responder):
    res = _run(responder.r.execute_action(_action(EGRESS), responder.db))
    assert res["success"] is False and res["skipped"] == "shared_egress"
    responder.fw.assert_not_called()
    assert not responder.ipb.ip_blocker_service.is_blocked(EGRESS)


def test_responder_blocks_shared_egress_when_operator_approved(egress, responder):
    res = _run(responder.r.execute_action(_action(EGRESS, approved_by="operator"), responder.db))
    assert res["success"] is True
    responder.fw.assert_awaited_once()
    assert responder.ipb.ip_blocker_service.is_blocked(EGRESS)


def test_responder_still_blocks_normal_ip(egress, responder):
    res = _run(responder.r.execute_action(_action(NORMAL), responder.db))
    assert res["success"] is True
    responder.fw.assert_awaited_once()
    assert responder.ipb.ip_blocker_service.is_blocked(NORMAL)


# --------------------------------------------------------------------------- #
# playbooks and dos_shield
# --------------------------------------------------------------------------- #
def test_playbook_block_paths_skip_shared_egress(egress, monkeypatch, detector):
    from app.services.playbook_engine import PlaybookEngine
    import app.core.firewall_client as fwc
    fw = AsyncMock(return_value={"success": True})
    monkeypatch.setattr(fwc.firewall_client, "block_ip", fw)
    eng = PlaybookEngine.__new__(PlaybookEngine)
    assert _run(eng._block_via_firewall(EGRESS, {"name": "pb"}))["status"] == "skipped_shared_egress"
    assert eng._block_via_local(EGRESS)["status"] == "skipped_shared_egress"
    fw.assert_not_called()
    assert not detector.ipb.ip_blocker_service.is_blocked(EGRESS)
    # normal IP unaffected
    assert _run(eng._block_via_firewall(NORMAL, {"name": "pb"}))["status"] == "success"
    assert eng._block_via_local(NORMAL)["status"] == "success"


def test_dos_escalate_skips_shared_egress(egress, monkeypatch, detector):
    from tests.test_dos_shield import _make_shield
    import app.core.firewall_client as fwc
    shield, _ = _make_shield(monkeypatch, AEGIS_DOS_MODE="active")
    fw = AsyncMock(return_value={"success": True})
    monkeypatch.setattr(fwc.firewall_client, "block_ip", fw)
    res = _run(shield.escalate(EGRESS, "per_ip_rate"))
    assert res["blocked"] is False and res["reason"] == "shared_egress"
    fw.assert_not_called()
    assert not detector.ipb.ip_blocker_service.is_blocked(EGRESS)
    res = _run(shield.escalate(NORMAL, "per_ip_rate"))
    assert res["blocked"] is True
    fw.assert_awaited_once()


# --------------------------------------------------------------------------- #
# Pi honeypot (standalone script, mirrors the predicate)
# --------------------------------------------------------------------------- #
HONEYPOT = Path(__file__).resolve().parents[3] / "pi-deploy" / "aegis_honeypot.py"


def _load_honeypot(monkeypatch, tmp_path, **env):
    monkeypatch.setenv("HONEYPOT_LOG", str(tmp_path / "hp.log"))
    monkeypatch.setenv("AEGIS_SHARED_EGRESS_FILE", str(tmp_path / "none.txt"))
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    spec = importlib.util.spec_from_file_location("aegis_honeypot_se", HONEYPOT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_pi_honeypot_does_not_block_shared_egress(monkeypatch, tmp_path):
    mod = _load_honeypot(monkeypatch, tmp_path, AEGIS_SHARED_EGRESS_IPS=f"{EGRESS},192.0.2.0/25")
    posted = []
    monkeypatch.setattr(mod.urllib.request, "urlopen", lambda *a, **k: posted.append(a))
    mod._block_ip(EGRESS, "GET /.env")
    mod._block_ip("192.0.2.9", "GET /.env")
    mod._block_ip(REAL_WARP[0], "GET /.env")
    assert posted == []
    assert mod._is_shared_egress(REAL_WARP[1]) and not mod._is_shared_egress(NORMAL)


def test_pi_honeypot_still_blocks_normal_ip(monkeypatch, tmp_path):
    mod = _load_honeypot(monkeypatch, tmp_path)
    posted = []

    class _R:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(mod.urllib.request, "urlopen", lambda *a, **k: posted.append(a) or _R())
    mod._block_ip(NORMAL, "GET /.env")
    assert len(posted) == 1
