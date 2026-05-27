"""
Tests for the deep-mode ip_intel enrichment (AEGIS v1.7).

Covers:
  - new free providers (greynoise, ipapi, geojs) mocked
  - deep providers (shodan, abuseipdb) mocked
  - classification logic across known patterns
  - confidence aggregation (tor ground truth dominates)
  - behavioral fingerprint from a sample feed
  - hostname heuristics
  - ASN reputation lookup
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

import app.services.ip_intel as ip_intel_mod
from app.services.ip_intel import (
    _CACHE,
    _DEEP_CACHE,
    _asn_reputation,
    _behavioral_for_ip,
    _classify,
    _hostname_flags,
    _load_tor_exits,
    lookup,
)


@pytest.fixture(autouse=True)
def _clear_caches():
    _CACHE.clear()
    _DEEP_CACHE.clear()
    # also reset the module-level tor cache so each test sees a fresh state
    ip_intel_mod._TOR_EXITS = set()
    ip_intel_mod._TOR_EXITS_LOADED_AT = 0.0
    ip_intel_mod._SPAMHAUS_NETS = []
    ip_intel_mod._SPAMHAUS_LOADED_AT = 0.0
    yield
    _CACHE.clear()
    _DEEP_CACHE.clear()


# ---------------------------------------------------------------------------
# Mock payloads — captured from real provider probes
# ---------------------------------------------------------------------------

_GREYNOISE_TOR = {
    "ip": "185.220.101.42", "noise": True, "riot": False,
    "classification": "malicious", "name": "unknown",
    "link": "https://viz.greynoise.io/ip/185.220.101.42",
    "last_seen": "2026-05-27", "message": "Success",
}
_GREYNOISE_GOOG = {
    "ip": "8.8.8.8", "noise": False, "riot": True,
    "classification": "benign", "name": "Google Public DNS",
    "link": "https://viz.greynoise.io/ip/8.8.8.8",
    "last_seen": "2026-05-27", "message": "Success",
}
_IPAPI_TOR = {
    "status": "success", "countryCode": "DE", "regionName": "Brandenburg",
    "city": "Brandenburg", "reverse": "tor-exit-42.for-privacy.net",
    "isp": "Stiftung Erneuerbare Freiheit", "org": "ForPrivacyNET",
    "as": "AS60729 Stiftung Erneuerbare Freiheit",
    "proxy": True, "hosting": False, "mobile": False,
}
_GEOJS_TOR = {
    "ip": "185.220.101.42", "country_code": "DE",
    "city": "Brandenburg an der Havel", "region": "Brandenburg",
    "asn": 60729, "organization_name": "Stiftung Erneuerbare Freiheit",
}
_SHODAN_TOR = {
    "cpes": [], "hostnames": ["tor-exit-42.for-privacy.net"],
    "ip": "185.220.101.42", "ports": [80], "tags": ["tor"], "vulns": [],
}
_IPQUERY_TOR = {
    "ip": "185.220.101.42",
    "isp": {"asn": "AS60729", "org": "Stiftung Erneuerbare Freiheit", "isp": "ForPrivacyNET"},
    "location": {"country_code": "DE", "city": "Brandenburg", "state": "Brandenburg"},
    "risk": {"is_vpn": False, "is_tor": True, "is_proxy": True, "is_datacenter": False, "risk_score": 80},
}
_IPINFO_TOR = {
    "ip": "185.220.101.42", "hostname": "tor-exit-42.for-privacy.net",
    "city": "Brandenburg", "region": "Brandenburg", "country": "DE",
    "org": "AS60729 Stiftung Erneuerbare Freiheit",
}


def _make_url_router(routes: dict):
    """Build an AsyncClient mock that dispatches based on URL substrings."""

    class FakeResponse:
        def __init__(self, payload, status=200):
            self._payload = payload
            self.status_code = status
            self.text = json.dumps(payload) if isinstance(payload, (dict, list)) else str(payload)

        def raise_for_status(self):
            if self.status_code >= 400 and self.status_code != 404:
                raise Exception(f"HTTP {self.status_code}")

        def json(self):
            return self._payload

    async def fake_get(url, **kwargs):
        for needle, payload in routes.items():
            if needle in url:
                if payload is None:
                    return FakeResponse({"error": "no data"}, status=500)
                if isinstance(payload, tuple):
                    return FakeResponse(payload[0], status=payload[1])
                return FakeResponse(payload)
        # unknown URL → 500 (will be caught)
        return FakeResponse({"error": "unmocked"}, status=500)

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=fake_get)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return mock_client


# ---------------------------------------------------------------------------
# Provider tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_greynoise_malicious_flag_for_tor():
    """GreyNoise 'malicious' classification should mark is_malicious."""
    routes = {
        "ipinfo.io": _IPINFO_TOR,
        "ip.guide": {"ip": "185.220.101.42", "network": {"autonomous_system": {"asn": 60729, "organization": "TorOrg"}}, "location": {}},
        "ipquery.io": _IPQUERY_TOR,
        "greynoise.io": _GREYNOISE_TOR,
        "ip-api.com": _IPAPI_TOR,
        "geojs.io": _GEOJS_TOR,
    }
    client = _make_url_router(routes)
    with patch("app.services.ip_intel.httpx.AsyncClient", return_value=client):
        result = await lookup("185.220.101.42", deep=False)

    assert result["is_tor"] is True
    assert result["is_malicious"] is True
    assert result["greynoise_classification"] == "malicious"
    assert result["greynoise_noise"] is True
    assert "greynoise" in result["providers"]
    assert "ipapi" in result["providers"]
    assert "geojs" in result["providers"]


@pytest.mark.asyncio
async def test_greynoise_benign_known_service_for_google():
    """GreyNoise 'benign' + riot=True should populate greynoise_name and is_known_service."""
    routes = {
        "ipinfo.io": {"ip": "8.8.8.8", "hostname": "dns.google", "country": "US", "org": "AS15169 Google LLC"},
        "ip.guide": {"network": {"autonomous_system": {"asn": 15169, "organization": "Google LLC"}}, "location": {}},
        "ipquery.io": {"isp": {"asn": "AS15169", "org": "Google LLC"}, "location": {"country_code": "US"}, "risk": {"is_datacenter": True, "risk_score": 0}},
        "greynoise.io": _GREYNOISE_GOOG,
        "ip-api.com": {"status": "success", "countryCode": "US", "as": "AS15169 Google LLC", "isp": "Google LLC", "hosting": True, "proxy": False},
        "geojs.io": {"country_code": "US", "asn": 15169, "organization_name": "Google LLC"},
    }
    client = _make_url_router(routes)
    with patch("app.services.ip_intel.httpx.AsyncClient", return_value=client):
        result = await lookup("8.8.8.8", deep=False)

    assert result["greynoise_classification"] == "benign"
    assert result["greynoise_riot"] is True
    assert result.get("is_known_service") is True
    assert result["classification"] in ("known_crawler", "known_service")


# ---------------------------------------------------------------------------
# Classification + confidence
# ---------------------------------------------------------------------------

def test_classify_tor_with_ground_truth():
    merged = {
        "providers": ["ipinfo", "ipquery"],
        "is_tor": True,
        "hostname": "tor-exit-42.for-privacy.net",
        "asn": "AS60729",
    }
    label, conf = _classify(merged, tor_match=True, spamhaus_match=False,
                            asn_rep={"asn_reputation_tag": "tor"})
    assert label == "tor_exit"
    assert conf["tor"] >= 0.9


def test_classify_known_crawler_googlebot():
    merged = {
        "providers": ["ipinfo", "ipquery"],
        "asn": "AS15169",
        "is_datacenter": True,
    }
    label, conf = _classify(merged, tor_match=False, spamhaus_match=False,
                            asn_rep={"asn_reputation_tag": "crawler",
                                     "asn_reputation_name": "Google"})
    assert label == "known_crawler"


def test_classify_known_attacker_via_spamhaus():
    merged = {"providers": ["ipinfo"], "asn": "AS9999"}
    label, conf = _classify(merged, tor_match=False, spamhaus_match=True, asn_rep={})
    assert label == "known_attacker"
    assert conf["attacker"] >= 0.6


def test_classify_unknown_consumer():
    merged = {"providers": ["ipinfo", "geojs"], "asn": "AS7922", "country": "US"}
    label, conf = _classify(merged, tor_match=False, spamhaus_match=False, asn_rep={})
    assert label == "unknown"
    assert conf["tor"] == 0.0


# ---------------------------------------------------------------------------
# Hostname heuristics
# ---------------------------------------------------------------------------

def test_hostname_flags_detects_tor_vpn_dc():
    assert _hostname_flags("tor-exit-1.example.org").get("host_tor_hint") is True
    assert _hostname_flags("nordvpn-fr-12.nord.com").get("host_vpn_hint") is True
    assert _hostname_flags("ec2-1-2-3-4.compute.amazonaws.com").get("host_dc_hint") is True
    assert _hostname_flags("plain-isp.example.net") == {}
    assert _hostname_flags(None) == {}


# ---------------------------------------------------------------------------
# ASN reputation
# ---------------------------------------------------------------------------

def test_asn_reputation_known_table():
    assert _asn_reputation("AS15169")["asn_reputation_tag"] == "crawler"
    assert _asn_reputation("AS13335")["asn_reputation_tag"] == "cloud"
    assert _asn_reputation("AS60729")["asn_reputation_tag"] == "tor"
    assert _asn_reputation("AS99999") == {}
    assert _asn_reputation(None) == {}


# ---------------------------------------------------------------------------
# Behavioral fingerprint
# ---------------------------------------------------------------------------

def test_behavioral_fingerprint_from_sample_feed(monkeypatch):
    """Synthesize a feed file with 5 hits from the target IP."""
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
        for i in range(5):
            fh.write(json.dumps({
                "ts": 1700000000 + i * 10,
                "ip": "1.2.3.4",
                "app": "sable",
                "path": f"/login?attempt={i}",
                "user_agent": "Mozilla/5.0 (X11; Linux)",
            }) + "\n")
        # decoy hits from another IP
        fh.write(json.dumps({"ts": 1700000050, "ip": "5.6.7.8", "app": "sable", "path": "/health", "user_agent": "kube-probe"}) + "\n")
        path = fh.name

    monkeypatch.setenv("AEGIS_FEED_PATH", path)
    fp = _behavioral_for_ip("1.2.3.4")
    assert fp["hits"] == 5
    assert fp["distinct_apps"] == 1
    assert fp["distinct_uas"] == 1
    assert fp["distinct_paths"] == 5
    assert fp["request_interval_mean_sec"] == 10.0
    assert len(fp["session_fingerprint"]) == 16


def test_behavioral_empty_when_no_feed(monkeypatch):
    monkeypatch.setenv("AEGIS_FEED_PATH", "/nonexistent/path/feed.jsonl")
    fp = _behavioral_for_ip("9.9.9.9")
    assert fp == {"hits": 0}


# ---------------------------------------------------------------------------
# Tor list cache
# ---------------------------------------------------------------------------

def test_load_tor_exits_reads_local_file(monkeypatch, tmp_path):
    f = tmp_path / "tor.txt"
    f.write_text("# comment\n185.220.101.42\n185.220.101.43\nbad-line\nExitAddress 185.220.101.44 2026-05-27\n")
    monkeypatch.setattr(ip_intel_mod, "_TOR_EXIT_FILE", f)
    ip_intel_mod._TOR_EXITS = set()
    ip_intel_mod._TOR_EXITS_LOADED_AT = 0.0
    ips = _load_tor_exits()
    assert "185.220.101.42" in ips
    assert "185.220.101.43" in ips
    assert "185.220.101.44" in ips
    assert "bad-line" not in ips


# ---------------------------------------------------------------------------
# Deep lookup integration (Shodan added)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_deep_lookup_adds_shodan_and_classification(monkeypatch, tmp_path):
    tor_file = tmp_path / "tor.txt"
    tor_file.write_text("185.220.101.42\n")
    monkeypatch.setattr(ip_intel_mod, "_TOR_EXIT_FILE", tor_file)
    ip_intel_mod._TOR_EXITS = set()
    ip_intel_mod._TOR_EXITS_LOADED_AT = 0.0
    # empty spamhaus
    sh = tmp_path / "sh.txt"
    sh.write_text(";empty\n")
    monkeypatch.setattr(ip_intel_mod, "_SPAMHAUS_FILE", sh)
    ip_intel_mod._SPAMHAUS_NETS = []
    ip_intel_mod._SPAMHAUS_LOADED_AT = 0.0
    monkeypatch.setenv("AEGIS_FEED_PATH", "/nonexistent/feed.jsonl")

    routes = {
        "ipinfo.io": _IPINFO_TOR,
        "ip.guide": {"network": {"autonomous_system": {"asn": 60729, "organization": "Tor"}}, "location": {}},
        "ipquery.io": _IPQUERY_TOR,
        "greynoise.io": _GREYNOISE_TOR,
        "ip-api.com": _IPAPI_TOR,
        "geojs.io": _GEOJS_TOR,
        "internetdb.shodan.io": _SHODAN_TOR,
    }
    client = _make_url_router(routes)
    with patch("app.services.ip_intel.httpx.AsyncClient", return_value=client):
        result = await lookup("185.220.101.42", deep=True)

    assert result["deep"] is True
    assert result["tor_list_match"] is True
    assert result["is_tor"] is True
    assert result["classification"] == "tor_exit"
    assert result["confidence"]["tor"] >= 0.9
    assert result["shodan_seen"] is True
    assert "tor" in [t.lower() for t in result.get("shodan_tags") or []]
    assert result["asn_reputation_tag"] == "tor"
    assert result["behavioral"]["hits"] == 0
    assert result["correlated_sessions"] == []


@pytest.mark.asyncio
async def test_deep_spamhaus_match_marks_attacker(monkeypatch, tmp_path):
    tor_file = tmp_path / "tor.txt"
    tor_file.write_text("\n")
    monkeypatch.setattr(ip_intel_mod, "_TOR_EXIT_FILE", tor_file)
    sh = tmp_path / "sh.txt"
    sh.write_text("1.10.16.0/20 ; SBL256894\n")
    monkeypatch.setattr(ip_intel_mod, "_SPAMHAUS_FILE", sh)
    ip_intel_mod._SPAMHAUS_NETS = []
    ip_intel_mod._SPAMHAUS_LOADED_AT = 0.0
    ip_intel_mod._TOR_EXITS = set()
    ip_intel_mod._TOR_EXITS_LOADED_AT = 0.0
    monkeypatch.setenv("AEGIS_FEED_PATH", "/nonexistent/feed.jsonl")

    routes = {
        "ipinfo.io": {"ip": "1.10.16.5", "country": "??", "org": "AS9999 Unknown"},
        "ip.guide": {"network": {"autonomous_system": {"asn": 9999, "organization": "Unk"}}, "location": {}},
        "ipquery.io": {"isp": {"asn": "AS9999", "org": "Unk"}, "location": {}, "risk": {}},
        "greynoise.io": {"classification": "unknown", "noise": False, "riot": False},
        "ip-api.com": {"status": "success", "countryCode": "XX", "as": "AS9999 Unknown", "isp": "Unknown"},
        "geojs.io": {"country_code": "XX", "asn": 9999},
        "internetdb.shodan.io": ({}, 404),
    }
    client = _make_url_router(routes)
    with patch("app.services.ip_intel.httpx.AsyncClient", return_value=client):
        result = await lookup("1.10.16.5", deep=True)

    assert result["spamhaus_match"] is True
    assert result["is_malicious"] is True
    assert result["classification"] == "known_attacker"
    assert result["confidence"]["attacker"] >= 0.6


@pytest.mark.asyncio
async def test_one_new_provider_failure_does_not_block_others():
    """If GreyNoise dies, other providers still return data."""
    routes = {
        "ipinfo.io": {"ip": "8.8.8.8", "country": "US", "org": "AS15169 Google LLC"},
        "ip.guide": {"network": {"autonomous_system": {"asn": 15169, "organization": "Google"}}, "location": {}},
        "ipquery.io": {"isp": {"asn": "AS15169", "org": "Google"}, "location": {"country_code": "US"}, "risk": {"is_datacenter": True}},
        "greynoise.io": None,  # → 500
        "ip-api.com": {"status": "success", "countryCode": "US", "as": "AS15169 Google LLC", "isp": "Google LLC", "hosting": True},
        "geojs.io": {"country_code": "US", "asn": 15169},
    }
    client = _make_url_router(routes)
    with patch("app.services.ip_intel.httpx.AsyncClient", return_value=client):
        result = await lookup("8.8.8.8", deep=False)
    assert "greynoise" not in (result.get("providers") or [])
    assert result["asn"] == "AS15169"
    assert result["classification"] is not None


@pytest.mark.asyncio
async def test_deep_response_includes_required_keys():
    """Deep lookup must always carry behavioral + correlated_sessions + classification + confidence."""
    routes = {
        "ipinfo.io": {"country": "US", "org": "AS15169 Google LLC"},
        "ip.guide": {"network": {"autonomous_system": {"asn": 15169, "organization": "Google"}}, "location": {}},
        "ipquery.io": {"isp": {"asn": "AS15169", "org": "Google"}, "location": {}, "risk": {}},
        "greynoise.io": _GREYNOISE_GOOG,
        "ip-api.com": {"status": "success", "as": "AS15169 Google LLC", "isp": "Google LLC", "hosting": True, "countryCode": "US"},
        "geojs.io": {"country_code": "US"},
        "internetdb.shodan.io": ({}, 404),
    }
    client = _make_url_router(routes)
    with patch("app.services.ip_intel.httpx.AsyncClient", return_value=client):
        result = await lookup("8.8.8.8", deep=True)
    for k in ("classification", "confidence", "behavioral", "correlated_sessions",
              "tor_list_match", "spamhaus_match", "deep"):
        assert k in result, f"missing key {k}"
