"""Firewall contract fixes: deferred blocks are not success, and the
false-positive auto-unblock goes through firewall_client (DELETE /block/{ip})."""
import logging

import pytest

from app.core import firewall_client as fc
from app.services.ip_investigator import ip_investigator

IP = "192.0.2.55"


class _Resp:
    def __init__(self, body, status=200):
        self._body, self.status_code = body, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._body


def _fake_httpx(monkeypatch, resp):
    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None):
            return resp

        async def delete(self, url):
            return resp

    monkeypatch.setattr(fc.httpx, "AsyncClient", _Client)


async def test_deferred_block_is_not_success(monkeypatch):
    body = {"success": False, "ip": IP, "blocked": False, "deferred": True,
            "detail": "no exploit signature and only 1 sighting(s)"}
    _fake_httpx(monkeypatch, _Resp(body))
    result = await fc.FirewallClient().block_ip(IP, reason="404")
    assert result["success"] is False
    assert result["deferred"] is True
    assert "no exploit signature" in result["error"]


async def test_enforced_block_is_success(monkeypatch):
    _fake_httpx(monkeypatch, _Resp({"success": True, "ip": IP}))
    assert (await fc.FirewallClient().block_ip(IP, force=True))["success"] is True


async def test_body_without_blocked_key_stays_success(monkeypatch):
    # Older agent builds never sent `blocked`; that must keep meaning success.
    _fake_httpx(monkeypatch, _Resp({"success": True}))
    assert (await fc.FirewallClient().block_ip(IP))["success"] is True


async def test_false_positive_unblock_uses_client(monkeypatch):
    calls = []

    async def fake_unblock(ip):
        calls.append(ip)
        return {"success": True}

    monkeypatch.setenv("AEGIS_FIREWALL_URL", "http://fw.example.com:8765")
    monkeypatch.setattr(fc.firewall_client, "unblock_ip", fake_unblock)
    await ip_investigator._unblock_ip(IP)
    assert calls == [IP]


async def test_false_positive_unblock_failure_warns(monkeypatch, caplog):
    async def fake_unblock(ip):
        return {"success": False, "error": "HTTP 404"}

    monkeypatch.setenv("AEGIS_FIREWALL_URL", "http://fw.example.com:8765")
    monkeypatch.setattr(fc.firewall_client, "unblock_ip", fake_unblock)
    with caplog.at_level(logging.WARNING):
        await ip_investigator._unblock_ip(IP)
    assert any(r.levelno == logging.WARNING and IP in r.getMessage()
               and "FAILED" in r.getMessage() for r in caplog.records)


async def test_notify_firewall_logs_deferral_distinctly(monkeypatch, caplog):
    import aiohttp
    from app.core import attack_detector as ad

    class _R:
        status = 200

        async def json(self, content_type=None):
            return {"blocked": False, "deferred": True, "detail": "needs repeat sighting"}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    class _S:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def post(self, *a, **k):
            return _R()

    monkeypatch.setattr(ad, "FIREWALL_URL", "http://fw.example.com:8765")
    monkeypatch.setattr(aiohttp, "ClientSession", _S)
    with caplog.at_level(logging.INFO):
        await ad._notify_firewall(IP, "scanner")
    msgs = [r.getMessage() for r in caplog.records]
    assert any("DEFERRED" in m for m in msgs)
    assert not any("Firewall notified to block" in m for m in msgs)
