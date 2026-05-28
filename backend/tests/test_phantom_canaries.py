"""
Tests for GET /api/v1/phantom/canaries endpoint.

Covers:
- Returns 200 with envelope {items, count, total}
- Filters by ip (source_ip)
- Respects limit parameter
"""

import uuid
from datetime import datetime

import pytest

from app.models.honeypot_canary import HoneypotCanary
from tests.conftest import api_key_headers


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_canary(source_ip: str, **kwargs) -> HoneypotCanary:
    return HoneypotCanary(
        id=str(uuid.uuid4()),
        source_ip=source_ip,
        real_ip_webrtc=kwargs.get("real_ip_webrtc"),
        fingerprint_hash=kwargs.get("fingerprint_hash", "abc123"),
        headless_detected=kwargs.get("headless_detected", False),
        browser_meta=kwargs.get("browser_meta", {}),
        honeypot_source=kwargs.get("honeypot_source", "mac_http_8888"),
        captured_at=kwargs.get("captured_at", datetime.utcnow()),
        client_id=None,
    )


# ---------------------------------------------------------------------------
# Test: returns 200 with correct envelope
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_canaries_returns_200_envelope(client, test_client_a, db_session):
    """GET /phantom/canaries returns {items, count, total} with status 200."""
    canary = _make_canary("203.0.113.10")
    db_session.add(canary)
    await db_session.commit()

    headers = api_key_headers(test_client_a)
    resp = await client.get("/api/v1/phantom/canaries", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "count" in data
    assert "total" in data
    assert data["count"] == len(data["items"])
    assert data["count"] >= 1
    item = data["items"][0]
    assert "source_ip" in item
    assert "captured_at" in item
    assert "headless_detected" in item


# ---------------------------------------------------------------------------
# Test: filters by ip
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_canaries_filter_by_ip(client, test_client_a, db_session):
    """ip= filter restricts results to matching source_ip."""
    canary_a = _make_canary("203.0.113.50")
    canary_b = _make_canary("198.51.100.77")
    db_session.add_all([canary_a, canary_b])
    await db_session.commit()

    headers = api_key_headers(test_client_a)
    resp = await client.get(
        "/api/v1/phantom/canaries?ip=203.0.113.50&hours=8760",
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert all(item["source_ip"] == "203.0.113.50" for item in data["items"])
    assert data["count"] >= 1


# ---------------------------------------------------------------------------
# Test: respects limit parameter
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_canaries_respects_limit(client, test_client_a, db_session):
    """limit= caps the items returned."""
    canaries = [_make_canary(f"10.{i}.0.1") for i in range(10)]
    db_session.add_all(canaries)
    await db_session.commit()

    headers = api_key_headers(test_client_a)
    resp = await client.get(
        "/api/v1/phantom/canaries?limit=3&hours=8760",
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] <= 3
    assert len(data["items"]) <= 3
