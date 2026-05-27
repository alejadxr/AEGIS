"""Tests for the incident enrichment SQLAlchemy listener."""

from __future__ import annotations

from unittest.mock import patch

from app.services.incident_enrichment import _enabled, _is_lookupable


def test_enabled_default_on(monkeypatch):
    monkeypatch.delenv("AEGIS_INCIDENT_ENRICH", raising=False)
    assert _enabled() is True


def test_enabled_off_explicit(monkeypatch):
    for v in ("0", "false", "FALSE", "no", "off"):
        monkeypatch.setenv("AEGIS_INCIDENT_ENRICH", v)
        assert _enabled() is False, f"value {v!r} should disable"


def test_enabled_on_explicit(monkeypatch):
    for v in ("1", "true", "yes", "on", "anything-else"):
        monkeypatch.setenv("AEGIS_INCIDENT_ENRICH", v)
        assert _enabled() is True, f"value {v!r} should enable"


def test_is_lookupable_public_ip():
    assert _is_lookupable("185.220.101.42") is True
    assert _is_lookupable("8.8.8.8") is True


def test_is_lookupable_internal_skips():
    for ip in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "100.88.0.85"):
        assert _is_lookupable(ip) is False, f"{ip} should be skipped"


def test_is_lookupable_none_and_invalid():
    assert _is_lookupable(None) is False
    assert _is_lookupable("") is False
    assert _is_lookupable("not-an-ip") is False
