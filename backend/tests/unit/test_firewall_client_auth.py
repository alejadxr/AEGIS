# Unit tests conftest — no app startup or DB required.
"""Tests for app.core.firewall_client._auth_headers (B5 / P0-12)."""
import app.core.firewall_client as fc


def test_client_attaches_shared_secret(monkeypatch):
    monkeypatch.setenv("AEGIS_FIREWALL_SECRET", "s3cr3t")
    headers = fc._auth_headers()
    assert headers.get("X-AEGIS-FW-Auth") == "s3cr3t"


def test_client_sends_empty_header_when_secret_unset(monkeypatch):
    monkeypatch.delenv("AEGIS_FIREWALL_SECRET", raising=False)
    headers = fc._auth_headers()
    assert headers.get("X-AEGIS-FW-Auth") == ""
