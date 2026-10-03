"""Shared cloud ranges must not be unconditionally safe on the Pi agent."""
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import main  # noqa: E402


def _reload(monkeypatch, safe):
    monkeypatch.setenv("AEGIS_SAFE_IPS", safe)
    return importlib.reload(main)


def test_broad_gcp_range_in_env_is_ignored(monkeypatch):
    m = _reload(monkeypatch, "34.64.0.0/10,35.190.0.0/17,13.66.0.0/17")
    try:
        assert not m._is_safe_ip("34.100.50.20")
        assert not m._is_safe_ip("13.66.10.10")
        assert not m._is_safe_ip("35.190.1.1")
    finally:
        monkeypatch.delenv("AEGIS_SAFE_IPS")
        importlib.reload(main)


def test_narrow_pin_and_precise_range_still_honored(monkeypatch):
    m = _reload(monkeypatch, "34.100.50.0/24,66.249.0.0/16")
    try:
        assert m._is_safe_ip("34.100.50.20")
        assert m._is_safe_ip("66.249.66.1")
        assert not m._is_safe_ip("34.100.51.20")
    finally:
        monkeypatch.delenv("AEGIS_SAFE_IPS")
        importlib.reload(main)


def test_shared_cloud_crawler_only_exempt_for_behavioural_threats(monkeypatch):
    import asyncio
    monkeypatch.setattr(main, "_crawler_nets", [(main.ipaddress.ip_network("34.100.50.0/24"), "googlebot")])
    assert asyncio.run(main._verify_crawler("34.100.50.7", "high_request_rate")) == "googlebot"
    assert asyncio.run(main._verify_crawler("34.100.50.7", "sql_injection")) is None
