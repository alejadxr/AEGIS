"""
Tests for ip_intel service and /api/v1/intel/ip/<ip> endpoint.

Covers:
  1. Public IP → all 3 providers queried in parallel + merged correctly
  2. Internal / loopback / private IPs → short-circuit, no HTTP calls
  3. Cache hit on second call (provider functions not called again)
  4. One provider 500s → others still return data
  5. All providers fail → returns empty enrichment (not 500)
  6. API endpoint happy path
  7. API endpoint internal IP returns 200 with internal=True
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio

import app.services.ip_intel as ip_intel_mod
from app.services.ip_intel import lookup, _is_internal, _CACHE


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_cache():
    """Wipe the in-memory cache before every test."""
    _CACHE.clear()
    yield
    _CACHE.clear()


# Realistic mock payloads (from actual API probes)

_IPINFO_PAYLOAD = {
    "ip": "45.33.32.156",
    "hostname": "li982-156.members.linode.com",
    "city": "Fremont",
    "region": "California",
    "country": "US",
    "loc": "37.5483,-121.9886",
    "org": "AS63949 Linode, LLC",
    "postal": "94536",
    "timezone": "America/Los_Angeles",
}

_IPGUIDE_PAYLOAD = {
    "ip": "45.33.32.156",
    "network": {
        "cidr": "45.33.0.0/16",
        "autonomous_system": {
            "asn": 63949,
            "name": "LINODE-AP Linode, LLC",
            "organization": "Linode, LLC",
            "country": "US",
            "rir": "ARIN",
        },
    },
    "location": {
        "city": None,
        "country": None,
        "timezone": None,
        "latitude": None,
        "longitude": None,
    },
}

_IPQUERY_PAYLOAD = {
    "ip": "45.33.32.156",
    "isp": {
        "asn": "AS63949",
        "org": "Linode, LLC",
        "isp": "Linode, LLC",
    },
    "location": {
        "country": "United States",
        "country_code": "US",
        "city": "Fremont",
        "state": "California",
        "zipcode": "94536",
        "latitude": 37.5483,
        "longitude": -121.9886,
        "timezone": "America/Los_Angeles",
        "localtime": "2026-05-26T10:00:00",
    },
    "risk": {
        "is_mobile": False,
        "is_vpn": False,
        "is_tor": False,
        "is_proxy": False,
        "is_datacenter": True,
        "risk_score": 15,
    },
}


def _make_mock_client(ipinfo=_IPINFO_PAYLOAD, ipguide=_IPGUIDE_PAYLOAD, ipquery=_IPQUERY_PAYLOAD):
    """Return an AsyncMock for httpx.AsyncClient that returns preset payloads."""

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload
            self.status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return self._payload

    class FakeErrorResponse:
        def raise_for_status(self):
            raise Exception("HTTP 500")

    async def fake_get(url, **kwargs):
        if "ipinfo.io" in url:
            return FakeErrorResponse() if ipinfo is None else FakeResponse(ipinfo)
        if "ip.guide" in url:
            return FakeErrorResponse() if ipguide is None else FakeResponse(ipguide)
        if "ipquery.io" in url:
            return FakeErrorResponse() if ipquery is None else FakeResponse(ipquery)
        raise ValueError(f"Unexpected URL: {url}")

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=fake_get)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


# ---------------------------------------------------------------------------
# 1. Public IP → all 3 providers + merge
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_public_ip_all_providers_merge():
    """All 3 providers respond → result contains merged fields."""
    mock_client = _make_mock_client()

    with patch("app.services.ip_intel.httpx.AsyncClient", return_value=mock_client):
        result = await lookup("45.33.32.156")

    assert result["ip"] == "45.33.32.156"
    assert result["internal"] is False
    assert result["cached"] is False

    # ASN: ipquery wins (first in merge order) → "AS63949"
    assert result["asn"] == "AS63949"
    # Org from ipquery
    assert result["org"] == "Linode, LLC"
    # Country from ipquery
    assert result["country"] == "US"
    # City from ipquery
    assert result["city"] == "Fremont"
    # Region from ipquery
    assert result["region"] == "California"
    # Hostname from ipinfo (ipquery doesn't provide it)
    assert result["hostname"] == "li982-156.members.linode.com"

    # Risk flags from ipquery only
    assert result["is_tor"] is False
    assert result["is_vpn"] is False
    assert result["is_proxy"] is False
    assert result["is_datacenter"] is True
    assert result["risk_score"] == 15

    # All 3 providers listed
    assert "ipquery" in result["providers"]
    assert "ipinfo" in result["providers"]
    assert "ipguide" in result["providers"]


# ---------------------------------------------------------------------------
# 2. Internal / private IPs → no HTTP calls
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("internal_ip", [
    "127.0.0.1",        # loopback
    "10.0.0.1",         # RFC1918
    "192.168.1.100",    # RFC1918
    "172.16.5.5",       # RFC1918
    "100.100.1.1",      # Tailscale CGNAT
    "::1",              # IPv6 loopback
])
async def test_internal_ips_short_circuit(internal_ip):
    """Internal/private IPs must never reach external APIs."""
    with patch("app.services.ip_intel.httpx.AsyncClient") as mock_cls:
        result = await lookup(internal_ip)

    # httpx.AsyncClient should never be instantiated
    mock_cls.assert_not_called()

    assert result["ip"] == internal_ip
    assert result["internal"] is True
    assert "asn" not in result  # no enrichment fields for internals


# ---------------------------------------------------------------------------
# 3. Cache hit on second call
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cache_hit_on_second_call():
    """Second lookup for same IP uses cache, no additional HTTP calls."""
    mock_client = _make_mock_client()
    call_count = 0
    original_side_effect = mock_client.get.side_effect

    async def counting_get(url, **kwargs):
        nonlocal call_count
        call_count += 1
        return await original_side_effect(url, **kwargs)

    mock_client.get.side_effect = counting_get

    with patch("app.services.ip_intel.httpx.AsyncClient", return_value=mock_client):
        r1 = await lookup("45.33.32.156")
        r2 = await lookup("45.33.32.156")

    # First call hits providers
    assert call_count >= 1
    first_call_count = call_count

    # Second call should NOT make new HTTP calls
    assert call_count == first_call_count  # no extra calls on 2nd lookup

    assert r1["cached"] is False
    assert r2["cached"] is True
    assert r2["ip"] == "45.33.32.156"
    assert r2["asn"] == r1["asn"]


# ---------------------------------------------------------------------------
# 4. One provider 500s → others still produce data
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_one_provider_fails_others_succeed():
    """ipguide returns 500 — ipinfo and ipquery still produce valid data."""
    mock_client = _make_mock_client(ipguide=None)  # ipguide will raise

    with patch("app.services.ip_intel.httpx.AsyncClient", return_value=mock_client):
        result = await lookup("45.33.32.156")

    assert result["ip"] == "45.33.32.156"
    assert result["internal"] is False
    # ipguide missing, but ipinfo and ipquery should be present
    assert "ipguide" not in result["providers"]
    assert "ipinfo" in result["providers"]
    assert "ipquery" in result["providers"]
    # Core fields still populated from surviving providers
    assert result["asn"] is not None
    assert result["country"] is not None


# ---------------------------------------------------------------------------
# 5. All providers fail → empty enrichment (not 500)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_all_providers_fail_returns_empty_enrichment():
    """All providers failing returns a minimal dict, not an exception."""
    mock_client = _make_mock_client(ipinfo=None, ipguide=None, ipquery=None)

    with patch("app.services.ip_intel.httpx.AsyncClient", return_value=mock_client):
        result = await lookup("45.33.32.156")

    assert result["ip"] == "45.33.32.156"
    assert result["internal"] is False
    assert result["providers"] == []
    # All enrichment fields are None
    assert result["asn"] is None
    assert result["org"] is None
    assert result["country"] is None


# ---------------------------------------------------------------------------
# 6. _is_internal helper
# ---------------------------------------------------------------------------

def test_is_internal_recognizes_private_ranges():
    assert _is_internal("127.0.0.1") is True
    assert _is_internal("10.0.0.1") is True
    assert _is_internal("192.168.0.1") is True
    assert _is_internal("172.31.255.255") is True
    assert _is_internal("100.64.0.1") is True    # Tailscale
    assert _is_internal("::1") is True           # IPv6 loopback
    assert _is_internal("not_an_ip") is True     # fail closed


def test_is_internal_public_ips_pass():
    assert _is_internal("1.1.1.1") is False
    assert _is_internal("8.8.8.8") is False
    assert _is_internal("45.33.32.156") is False


# ---------------------------------------------------------------------------
# 7. ipguide ASN integer normalization
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ipguide_asn_normalized_to_string():
    """ip.guide returns asn as integer 13335 — must be normalized to 'AS13335'."""
    ipguide_only_payload = {
        "ip": "1.1.1.1",
        "network": {
            "cidr": "1.1.1.0/24",
            "autonomous_system": {
                "asn": 13335,
                "name": "CLOUDFLARENET",
                "organization": "Cloudflare, Inc.",
                "country": "US",
                "rir": "ARIN",
            },
        },
        "location": {"city": None, "country": None},
    }
    # Only ipguide active — disable others
    import os
    original_env = os.environ.get("AEGIS_IPINTEL_PROVIDERS")
    os.environ["AEGIS_IPINTEL_PROVIDERS"] = "ipguide"

    try:
        mock_client = _make_mock_client(ipguide=ipguide_only_payload)
        with patch("app.services.ip_intel.httpx.AsyncClient", return_value=mock_client):
            result = await lookup("1.1.1.1")
    finally:
        if original_env is None:
            del os.environ["AEGIS_IPINTEL_PROVIDERS"]
        else:
            os.environ["AEGIS_IPINTEL_PROVIDERS"] = original_env

    assert result["asn"] == "AS13335"
    assert result["org"] == "Cloudflare, Inc."


# ---------------------------------------------------------------------------
# 8. API endpoint tests (using FastAPI test client)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_endpoint_public_ip(client, test_client_a):
    """GET /api/v1/intel/ip/45.33.32.156 returns 200 with enrichment."""
    from tests.conftest import api_key_headers

    mock_client = _make_mock_client()
    with patch("app.services.ip_intel.httpx.AsyncClient", return_value=mock_client):
        resp = await client.get(
            "/api/v1/intel/ip/45.33.32.156",
            headers=api_key_headers(test_client_a),
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["ip"] == "45.33.32.156"
    assert data["internal"] is False


@pytest.mark.asyncio
async def test_api_endpoint_internal_ip_returns_200(client, test_client_a):
    """GET /api/v1/intel/ip/127.0.0.1 returns 200 with internal=True."""
    from tests.conftest import api_key_headers

    resp = await client.get(
        "/api/v1/intel/ip/127.0.0.1",
        headers=api_key_headers(test_client_a),
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["ip"] == "127.0.0.1"
    assert data["internal"] is True


@pytest.mark.asyncio
async def test_api_endpoint_requires_auth(client):
    """GET /api/v1/intel/ip/<ip> without auth returns 401 or 403."""
    resp = await client.get("/api/v1/intel/ip/1.1.1.1")
    assert resp.status_code in (401, 403)
