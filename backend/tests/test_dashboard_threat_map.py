"""Tests for Bug 3 fix: dashboard threat-map country shape."""

import uuid
from datetime import datetime
from unittest.mock import patch

import pytest
import pytest_asyncio

from app.models.honeypot import Honeypot, HoneypotInteraction
from app.models.incident import Incident
from tests.conftest import api_key_headers


@pytest_asyncio.fixture
async def sample_honeypot(db_session, test_client_a):
    h = Honeypot(
        id=str(uuid.uuid4()),
        client_id=test_client_a.id,
        name="HTTP Trap",
        honeypot_type="http",
        status="running",
        port=8888,
        interactions_count=0,
        config={},
    )
    db_session.add(h)
    await db_session.commit()
    await db_session.refresh(h)
    return h


@pytest_asyncio.fixture
async def hp_interactions(db_session, test_client_a, sample_honeypot):
    """Three interactions: 2 from 'CN' IP, 1 from 'RU' IP."""
    rows = [
        HoneypotInteraction(
            id=str(uuid.uuid4()),
            client_id=test_client_a.id,
            honeypot_id=sample_honeypot.id,
            source_ip="1.2.3.4",  # will resolve to CN
            protocol="http",
            commands=[],
            credentials_tried=[],
            timestamp=datetime.utcnow(),
        ),
        HoneypotInteraction(
            id=str(uuid.uuid4()),
            client_id=test_client_a.id,
            honeypot_id=sample_honeypot.id,
            source_ip="1.2.3.4",  # same IP again
            protocol="http",
            commands=[],
            credentials_tried=[],
            timestamp=datetime.utcnow(),
        ),
        HoneypotInteraction(
            id=str(uuid.uuid4()),
            client_id=test_client_a.id,
            honeypot_id=sample_honeypot.id,
            source_ip="5.6.7.8",  # will resolve to RU
            protocol="http",
            commands=[],
            credentials_tried=[],
            timestamp=datetime.utcnow(),
        ),
    ]
    for r in rows:
        db_session.add(r)
    await db_session.commit()
    return rows


def _fake_lookup(ip: str):
    mapping = {
        "1.2.3.4": {"country": "CN", "source": "dbip_offline"},
        "5.6.7.8": {"country": "RU", "source": "dbip_offline"},
    }
    return mapping.get(ip)


@pytest.mark.asyncio
async def test_threat_map_returns_country_shape(
    client, test_client_a, hp_interactions
):
    """Bug 3: /dashboard/threat-map must return {country, country_code, count}."""
    headers = api_key_headers(test_client_a)

    with patch("app.services.offline_geoip.lookup", side_effect=_fake_lookup):
        resp = await client.get("/api/v1/dashboard/threat-map", headers=headers)

    assert resp.status_code == 200, resp.text
    data = resp.json()

    # Should have entries (at least CN and RU)
    assert isinstance(data, list)
    assert len(data) >= 1

    # Every entry must have the required shape
    for entry in data:
        assert "country" in entry, f"Missing 'country' in {entry}"
        assert "country_code" in entry, f"Missing 'country_code' in {entry}"
        assert "count" in entry, f"Missing 'count' in {entry}"
        assert isinstance(entry["count"], int)

    # CN should have count=2, RU count=1
    by_code = {e["country_code"]: e for e in data}
    if "CN" in by_code:
        assert by_code["CN"]["country"] == "China"
        assert by_code["CN"]["count"] == 2
    if "RU" in by_code:
        assert by_code["RU"]["country"] == "Russia"
        assert by_code["RU"]["count"] == 1


@pytest.mark.asyncio
async def test_threat_map_unknown_ip_uses_fallback(
    client, test_client_a, hp_interactions
):
    """IPs that offline_geoip cannot resolve appear as country_code='??', country='Unknown'."""
    headers = api_key_headers(test_client_a)

    # All lookups return None → unknown IPs
    with patch("app.services.offline_geoip.lookup", return_value=None):
        resp = await client.get("/api/v1/dashboard/threat-map", headers=headers)

    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    if data:
        # All entries must fall back to '??' / 'Unknown'
        for entry in data:
            assert entry["country_code"] == "??"
            assert entry["country"] == "Unknown"


@pytest.mark.asyncio
async def test_threat_map_empty_returns_empty_list(client, test_client_a):
    """No data → empty list (no crash)."""
    headers = api_key_headers(test_client_a)
    with patch("app.services.offline_geoip.lookup", return_value=None):
        resp = await client.get("/api/v1/dashboard/threat-map", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []
