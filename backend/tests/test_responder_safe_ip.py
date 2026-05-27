"""
Tests for the SAFE-IP guardrail in the responder + guardrails pipeline.

Regression test for the 2026-05-27 false positive where AEGIS auto-blocked
Googlebot IP 66.249.69.68 despite AEGIS_SAFE_IPS=...,66.249.0.0/16,...

The guard must short-circuit IP-targeted actions for any IP that matches
AEGIS_SAFE_IPS — even when the guardrail policy is auto_approve.
"""

import os
import importlib
import uuid

import pytest

from app.models.action import Action
from app.models.incident import Incident


# Re-import attack_detector after env var is set so SAFE_IPS picks up the CIDR.
@pytest.fixture(autouse=True, scope="module")
def _safe_ips_env():
    os.environ["AEGIS_SAFE_IPS"] = (
        "127.0.0.1,::1,66.249.0.0/16,74.244.193.0/24,192.168.100.0/24"
    )
    import app.core.attack_detector as ad
    importlib.reload(ad)
    # Also reload modules that capture _is_safe_ip at import time.
    import app.core.guardrails as gr
    import app.modules.response.responder as rp
    importlib.reload(gr)
    importlib.reload(rp)
    yield


@pytest.mark.asyncio
async def test_guardrail_short_circuits_safe_ip_block(db_session, test_client_a):
    """Guardrail must create a skipped_safe_ip Action for IPs in AEGIS_SAFE_IPS."""
    from app.core.guardrails import GuardrailEngine

    engine = GuardrailEngine()
    action = await engine.evaluate_action(
        client=test_client_a,
        action_type="block_ip",
        target="66.249.69.68",  # Googlebot, in 66.249.0.0/16
        ai_reasoning="scanner_detect on /wp-login",
        db=db_session,
        incident_id=None,
    )
    assert action.status == "skipped_safe_ip"
    assert action.requires_approval is False
    assert "safe-IP guardrail" in (action.ai_reasoning or "")


@pytest.mark.asyncio
async def test_guardrail_allows_non_safe_ip(db_session, test_client_a):
    """Guardrail must auto-approve non-safe IPs as before."""
    from app.core.guardrails import GuardrailEngine

    engine = GuardrailEngine()
    action = await engine.evaluate_action(
        client=test_client_a,
        action_type="block_ip",
        target="185.220.101.250",  # Tor exit, NOT in safe list
        ai_reasoning="brute_force",
        db=db_session,
        incident_id=None,
    )
    assert action.status == "approved"


@pytest.mark.asyncio
async def test_responder_refuses_safe_ip_execution(db_session, test_client_a):
    """Even if an Action somehow becomes approved for a safe IP, the responder must refuse."""
    from app.modules.response.responder import ActiveResponder

    # Manually craft an "approved" action targeting a safe IP (bypass guardrails).
    action = Action(
        incident_id="",
        client_id=test_client_a.id,
        action_type="block_ip",
        target="66.249.69.99",  # also in 66.249.0.0/16
        parameters={},
        status="approved",
        requires_approval=False,
        ai_reasoning="forced for test",
    )
    db_session.add(action)
    await db_session.commit()
    await db_session.refresh(action)

    responder = ActiveResponder()
    result = await responder.execute_action(action, db_session)

    assert result["success"] is False
    assert result.get("skipped") == "safe_ip"
    await db_session.refresh(action)
    assert action.status == "skipped_safe_ip"


@pytest.mark.asyncio
async def test_block_ip_executor_refuses_safe_ip(db_session, test_client_a):
    """The low-level _block_ip executor must also refuse safe IPs (defense in depth)."""
    from app.modules.response.responder import ActiveResponder

    responder = ActiveResponder()
    result = await responder._block_ip("66.249.69.50", {})
    assert result["success"] is False
    assert result.get("skipped") == "safe_ip"


@pytest.mark.asyncio
async def test_safe_ip_check_recognizes_cidr():
    """Sanity: _is_safe_ip must match IPs inside configured CIDR ranges."""
    from app.core.attack_detector import _is_safe_ip
    assert _is_safe_ip("66.249.69.68") is True
    assert _is_safe_ip("66.249.69.99") is True
    assert _is_safe_ip("74.244.193.5") is True
    assert _is_safe_ip("185.220.101.250") is False
