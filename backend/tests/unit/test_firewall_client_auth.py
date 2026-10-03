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


def test_secret_read_from_settings_first(monkeypatch):
    """backend/.env values land in Settings, not os.environ."""
    monkeypatch.delenv("AEGIS_FIREWALL_SECRET", raising=False)
    monkeypatch.setattr(fc.settings, "AEGIS_FIREWALL_SECRET", "from-settings", raising=False)
    assert fc.firewall_auth_headers()["X-AEGIS-FW-Auth"] == "from-settings"


def test_settings_wins_over_environ(monkeypatch):
    monkeypatch.setenv("AEGIS_FIREWALL_SECRET", "from-env")
    monkeypatch.setattr(fc.settings, "AEGIS_FIREWALL_SECRET", "from-settings", raising=False)
    assert fc.firewall_auth_headers()["X-AEGIS-FW-Auth"] == "from-settings"


def test_every_pi_caller_uses_the_shared_helper():
    """Guard: no module posts to the Pi agent without firewall_auth_headers."""
    import pathlib
    root = pathlib.Path(fc.__file__).resolve().parents[1]
    for rel in ("api/firewall.py", "core/attack_detector.py",
                "modules/phantom/processor.py", "services/ip_investigator.py"):
        assert "firewall_auth_headers" in (root / rel).read_text(), rel
