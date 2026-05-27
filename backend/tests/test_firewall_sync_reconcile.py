"""
Unit tests for firewall_sync._reconcile_incidents.

Uses the shared conftest.py SQLite in-memory DB + async session fixtures.
Mocks firewall_client.get_blocked() and settings.AEGIS_AUTO_RECONCILE_INCIDENTS.

Tests:
  1. Incident older than grace period with block_ip action, IP NOT in Pi list → resolved.
  2. Incident younger than grace period (< 10 min) → left alone (grace-period guard).
  3. Incident whose IP IS still in Pi blocklist → left alone.
  4. Opt-in guard: when AEGIS_AUTO_RECONCILE_INCIDENTS=False, reconcile is never called.
"""

import uuid
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.models.action import Action
from app.services.firewall_sync import _reconcile_incidents, run_sync

ATTACKER_IP = "203.0.113.42"
SAFE_IP_STILL_BLOCKED = "198.51.100.7"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_incident(
    client_id: str,
    source_ip: str,
    status: str = "investigating",
    age_minutes: int = 20,
) -> Incident:
    return Incident(
        id=str(uuid.uuid4()),
        client_id=client_id,
        title=f"Attack from {source_ip}",
        description="Detected attack",
        severity="high",
        status=status,
        source="log_watcher",
        source_ip=source_ip,
        detected_at=datetime.utcnow() - timedelta(minutes=age_minutes),
    )


def _make_block_action(incident: Incident, client_id: str) -> Action:
    return Action(
        id=str(uuid.uuid4()),
        incident_id=incident.id,
        client_id=client_id,
        action_type="block_ip",
        target=incident.source_ip,
        status="completed",
    )


# ---------------------------------------------------------------------------
# Test 1: Incident eligible for auto-resolution (old, no longer blocked)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reconcile_resolves_unblocked_incident(
    db_session: AsyncSession, test_client_a
):
    """
    An incident older than 10 min, with a block_ip action, whose IP is NOT
    in the Pi blocklist → should be auto-resolved.
    """
    incident = _make_incident(test_client_a.id, ATTACKER_IP, status="investigating", age_minutes=20)
    db_session.add(incident)
    await db_session.flush()

    action = _make_block_action(incident, test_client_a.id)
    db_session.add(action)
    await db_session.commit()

    # Pi blocklist does NOT contain ATTACKER_IP
    pi_blocked_set = {"1.2.3.4", "5.6.7.8"}

    count = await _reconcile_incidents(db_session, pi_blocked_set)

    assert count == 1
    await db_session.refresh(incident)
    assert incident.status == "resolved"
    assert incident.resolved_at is not None
    assert "resolution_note" in (incident.ai_analysis or {})
    assert "no longer in firewall blocklist" in incident.ai_analysis["resolution_note"]


# ---------------------------------------------------------------------------
# Test 2: Grace period — incident is too young (< 10 min)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reconcile_respects_grace_period(
    db_session: AsyncSession, test_client_a
):
    """
    An incident created 3 minutes ago (within grace period) should NOT be
    auto-resolved even if the IP is gone from the Pi blocklist.
    """
    incident = _make_incident(test_client_a.id, ATTACKER_IP, status="open", age_minutes=3)
    db_session.add(incident)
    await db_session.flush()

    action = _make_block_action(incident, test_client_a.id)
    db_session.add(action)
    await db_session.commit()

    # Pi blocklist does NOT contain ATTACKER_IP (IP is gone) but incident is young
    pi_blocked_set: set = set()

    count = await _reconcile_incidents(db_session, pi_blocked_set)

    assert count == 0
    await db_session.refresh(incident)
    assert incident.status == "open"  # unchanged
    assert incident.resolved_at is None


# ---------------------------------------------------------------------------
# Test 3: IP is still in the Pi blocklist → leave incident alone
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reconcile_leaves_still_blocked_ip_alone(
    db_session: AsyncSession, test_client_a
):
    """
    An incident whose source_ip is still present in the Pi blocklist should
    NOT be auto-resolved, regardless of age.
    """
    incident = _make_incident(
        test_client_a.id, SAFE_IP_STILL_BLOCKED, status="investigating", age_minutes=60
    )
    db_session.add(incident)
    await db_session.flush()

    action = _make_block_action(incident, test_client_a.id)
    db_session.add(action)
    await db_session.commit()

    # IP IS in the Pi blocklist
    pi_blocked_set = {SAFE_IP_STILL_BLOCKED, "10.0.0.1"}

    count = await _reconcile_incidents(db_session, pi_blocked_set)

    assert count == 0
    await db_session.refresh(incident)
    assert incident.status == "investigating"  # unchanged
    assert incident.resolved_at is None


# ---------------------------------------------------------------------------
# Test 4: Opt-in guard — when AEGIS_AUTO_RECONCILE_INCIDENTS=False, skip
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_sync_skips_reconcile_when_opt_in_off():
    """
    When settings.AEGIS_AUTO_RECONCILE_INCIDENTS is False (default),
    _reconcile_incidents must never be called.
    """
    mock_client_id = str(uuid.uuid4())

    with (
        patch("app.services.firewall_sync.async_session") as mock_session_ctx,
        patch("app.services.firewall_sync.settings") as mock_settings,
        patch("app.services.firewall_sync._get_demo_client_id", new_callable=AsyncMock, return_value=mock_client_id),
        patch("app.services.firewall_sync._sync_attackers", new_callable=AsyncMock, return_value=0),
        patch("app.services.firewall_sync._sync_blocked_ips", new_callable=AsyncMock, return_value=0),
        patch("app.services.firewall_sync._sync_auto_response_events", new_callable=AsyncMock, return_value=0),
        patch("app.services.firewall_sync._reconcile_incidents", new_callable=AsyncMock) as mock_reconcile,
        patch("app.services.firewall_sync.firewall_client") as mock_fw,
    ):
        # Opt-in flag is OFF
        mock_settings.AEGIS_AUTO_RECONCILE_INCIDENTS = False

        # Set up the async context manager for async_session
        mock_db = AsyncMock(spec=AsyncSession)
        mock_session_ctx.return_value.__aenter__ = AsyncMock(return_value=mock_db)
        mock_session_ctx.return_value.__aexit__ = AsyncMock(return_value=False)

        await run_sync()

        mock_reconcile.assert_not_called()
        mock_fw.get_blocked.assert_not_called()
