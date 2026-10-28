"""block_ip passes reason/severity/force so the Pi evidence gate does not defer
blocks AEGIS already decided."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import app.core.firewall_client as fc


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _FakeResp:
    def raise_for_status(self):
        pass

    def json(self):
        return {"success": True}


def _capture(monkeypatch):
    sent = {}

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None):
            sent["url"], sent["json"] = url, json
            return _FakeResp()

    monkeypatch.setattr(fc.httpx, "AsyncClient", _Client)
    return sent


def test_positional_ip_only_is_backward_compatible(monkeypatch):
    sent = _capture(monkeypatch)
    _run(fc.firewall_client.block_ip("203.0.113.9"))
    assert sent["json"] == {"ip": "203.0.113.9"}


def test_sends_non_none_fields(monkeypatch):
    sent = _capture(monkeypatch)
    _run(fc.firewall_client.block_ip("203.0.113.9", reason="r", threat_type="dos", severity="high", force=True))
    assert sent["json"] == {
        "ip": "203.0.113.9", "reason": "r", "threat_type": "dos", "severity": "high", "force": True,
    }


def test_force_false_not_sent(monkeypatch):
    sent = _capture(monkeypatch)
    _run(fc.firewall_client.block_ip("203.0.113.9", reason="r"))
    assert "force" not in sent["json"] and "severity" not in sent["json"]


def test_responder_forces_with_reason(monkeypatch):
    from app.modules.response import responder as rmod
    mock = AsyncMock(return_value={"success": True})
    monkeypatch.setattr(rmod.firewall_client, "block_ip", mock)
    monkeypatch.setattr(rmod, "_is_safe_ip", lambda ip: False)
    monkeypatch.setattr(rmod.ip_blocker_service, "block_ip", lambda ip, **kw: {"success": True})
    r = rmod.ActiveResponder() if hasattr(rmod, "ActiveResponder") else None
    if r is None:
        r = next(v for v in vars(rmod).values() if isinstance(v, type) and hasattr(v, "_block_ip"))()
    _run(r._block_ip("198.51.100.7", {"reason": "sqli on /login", "severity": "high"}))
    args, kw = mock.call_args
    assert args == ("198.51.100.7",)
    assert kw["force"] is True and kw["reason"] == "sqli on /login" and kw["severity"] == "high"


def test_playbook_forces_with_name(monkeypatch):
    from app.services.playbook_engine import PlaybookEngine
    mock = AsyncMock(return_value={"success": True})
    monkeypatch.setattr(fc.firewall_client, "block_ip", mock)
    eng = PlaybookEngine.__new__(PlaybookEngine)
    _run(eng._block_via_firewall("198.51.100.7", {"id": "pb1", "name": "SSH brute", "severity": "high"}))
    _, kw = mock.call_args
    assert kw["force"] is True and kw["reason"] == "playbook: SSH brute" and kw["severity"] == "high"


def test_dos_shield_forces_with_dos_type(monkeypatch):
    from app.services import dos_shield
    mock = AsyncMock(return_value={"success": True})
    monkeypatch.setattr(fc.firewall_client, "block_ip", mock)
    shield = dos_shield.DoSShield()
    try:
        _run(shield.escalate("198.51.100.7", "flood"))
    except Exception:
        pass
    _, kw = mock.call_args
    assert kw == {"reason": "dos:flood", "threat_type": "dos", "force": True}
