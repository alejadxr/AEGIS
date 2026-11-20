"""Audit M3, M11, M13: inline block records, endpoint-reported peers, host-level guards."""
import os
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

from app.config import settings

PEER = "203.0.113.66"


# --- M11 ---------------------------------------------------------------------

def _edr_alert(peer=PEER):
    return {"source_ip": peer, "host": "PC-01",
            "triggering_event": {"agent_id": "node-1", "_gate_ip": peer, "remote_ip": peer}}


def test_endpoint_named_address_is_recognised(monkeypatch):
    from app.core.guardrails import endpoint_reported_peer
    monkeypatch.setattr(settings, "AEGIS_EDR_NETWORK_AUTOBLOCK", False)
    assert endpoint_reported_peer(_edr_alert(), PEER) is True
    assert endpoint_reported_peer(_edr_alert(), "198.51.100.1") is False       # a different target
    assert endpoint_reported_peer({"source_ip": PEER}, PEER) is False           # seen by AEGIS itself
    assert endpoint_reported_peer(None, PEER) is False
    monkeypatch.setattr(settings, "AEGIS_EDR_NETWORK_AUTOBLOCK", True)
    assert endpoint_reported_peer(_edr_alert(), PEER) is False                  # operator opted in


async def test_block_of_an_endpoint_reported_peer_waits_for_approval(db_factory, monkeypatch):
    from app.core.guardrails import guardrail_engine
    from app.models.client import Client
    from app.models.incident import Incident
    monkeypatch.setattr(settings, "AEGIS_EDR_NETWORK_AUTOBLOCK", False)
    client = Client(id="c1", name="Test Org", slug="t", api_key="k", guardrails={"block_ip": "auto_approve"})
    async with db_factory() as db:
        db.add(Incident(id="i1", client_id="c1", title="c2", severity="high", source_ip=PEER))
        await db.commit()
        held = await guardrail_engine.evaluate_action(
            client=client, action_type="block_ip", target=PEER, ai_reasoning="c2 beacon",
            db=db, incident_id="i1", alert_data=_edr_alert())
        direct = await guardrail_engine.evaluate_action(
            client=client, action_type="block_ip", target="203.0.113.67", ai_reasoning="sqli",
            db=db, incident_id="i1", alert_data={"source_ip": "203.0.113.67"})
    assert held.status == "pending" and held.requires_approval is True
    assert direct.status == "approved"


# --- M13 ---------------------------------------------------------------------

def test_the_api_and_its_ancestors_cannot_be_killed():
    from app.api.edr import _protected_process_reason
    me = psutil.Process(os.getpid())
    assert _protected_process_reason(me)
    for parent in me.parents()[:2]:
        assert _protected_process_reason(parent)
    assert _protected_process_reason(SimpleNamespace(pid=1, name=lambda: "launchd"))
    assert _protected_process_reason(SimpleNamespace(pid=4242, name=lambda: "postgres"))
    assert _protected_process_reason(SimpleNamespace(pid=4242, name=lambda: "PM2 v5.3.0: God Daemon"))
    assert _protected_process_reason(SimpleNamespace(pid=4242, name=lambda: "evil.exe")) is None


def test_platform_and_system_files_cannot_be_quarantined(tmp_path, monkeypatch):
    from app.api import edr
    repo_file = Path(edr.__file__).resolve().parents[3] / "README.md"
    assert edr._protected_path_reason(Path(edr.__file__))
    if repo_file.exists():
        assert edr._protected_path_reason(repo_file)
    assert edr._protected_path_reason(Path("/etc/hosts"))

    sample = tmp_path / "malware.bin"
    sample.write_bytes(b"x")
    assert edr._protected_path_reason(sample) is None

    env_file = tmp_path / ".env.production"
    env_file.write_text("SECRET=1")
    assert edr._protected_path_reason(env_file)

    # A symlink does not launder a protected target.
    link = tmp_path / "innocent.txt"
    link.symlink_to("/etc/hosts")
    assert edr._protected_path_reason(link)
    assert edr._protected_path_reason(tmp_path / "missing.bin")


# --- M3 ----------------------------------------------------------------------

async def _actions(db_factory):
    from sqlalchemy import select
    from app.models.action import Action
    async with db_factory() as db:
        return list((await db.execute(select(Action))).scalars())


async def test_inline_ambiguous_block_gets_an_expiring_action(db_factory, monkeypatch):
    from app.core import attack_detector as ad
    from app.models.incident import Incident
    monkeypatch.delenv("AEGIS_BLOCKS_PERMANENT", raising=False)
    async with db_factory() as db:
        db.add(Incident(id="i1", client_id="c1", title="t", severity="critical", source_ip=PEER))
        await ad._record_inline_block_action(db, "c1", "i1", PEER, "scanner_user_agent")
        await db.commit()
        # A second detection of the same IP folds into the live action.
        await ad._record_inline_block_action(db, "c1", "i1", PEER, "scanner_user_agent")
        await db.commit()
    rows = await _actions(db_factory)
    assert len(rows) == 1
    a = rows[0]
    assert a.status == "executed" and a.parameters["provisional"] is True and a.parameters["expires_at"]
    assert a.parameters["origin"] == "attack_detector"


async def test_inline_confirmed_block_is_recorded_as_permanent(db_factory, monkeypatch):
    from app.core import attack_detector as ad
    from app.models.incident import Incident
    from app.services import block_policy
    confirmed = next(r for r in sorted(block_policy.CONFIRMED_IDS)
                     if block_policy.classify(r).kind == block_policy.CONFIRMED)
    async with db_factory() as db:
        db.add(Incident(id="i1", client_id="c1", title="t", severity="critical", source_ip=PEER))
        await ad._record_inline_block_action(db, "c1", "i1", PEER, confirmed)
        await db.commit()
    a = (await _actions(db_factory))[0]
    assert a.parameters.get("permanent") is True and "expires_at" not in a.parameters


def test_firewall_url_falls_back_to_settings(monkeypatch):
    from app.core import attack_detector as ad
    monkeypatch.delenv("AEGIS_FIREWALL_URL", raising=False)
    monkeypatch.setattr(settings, "AEGIS_FIREWALL_URL", "http://pi.example.com:8765/", raising=False)
    assert ad._firewall_url() == "http://pi.example.com:8765"
    monkeypatch.setenv("AEGIS_FIREWALL_URL", "http://env.example.com:8765")
    assert ad._firewall_url() == "http://env.example.com:8765"
