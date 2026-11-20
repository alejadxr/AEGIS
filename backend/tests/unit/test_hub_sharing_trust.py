"""An anonymous hub submission is a tip, not a block order (audit A3, M14)."""
import pytest
from starlette.requests import Request

from app.api import threats
from app.config import settings


def _request(ip="203.0.113.9"):
    return Request({"type": "http", "method": "POST", "path": "/", "headers": [],
                    "client": (ip, 1), "query_string": b""})


@pytest.fixture
def hub(monkeypatch):
    captured = []

    async def fake_share(doc):
        captured.append(doc)
        return {"status": "ok", "upserted": True}

    monkeypatch.setattr(threats, "mongo_connected", lambda: True)
    # The validator refuses documentation ranges; these tests are about trust,
    # not address validation, so pass the value through.
    monkeypatch.setattr(threats, "validate_ioc", lambda **k: {
        "ioc_type": k["ioc_type"], "ioc_value": k["ioc_value"],
        "threat_type": k["threat_type"], "confidence": k["confidence"]})
    monkeypatch.setattr(threats.threat_intel_hub, "share_ioc", fake_share)
    monkeypatch.setattr(settings, "AEGIS_HUB_SHARED_KEY", "hub-key")
    monkeypatch.setattr(settings, "AEGIS_HUB_UNTRUSTED_MAX_CONFIDENCE", 0.6)
    return captured


async def _share(value, confidence=1.0, key=None):
    body = threats.SharedIOCSubmit(ioc_type="ip", ioc_value=value, threat_type="c2", confidence=confidence)
    return await threats.share_ioc_public.__wrapped__(_request(), body, key)


async def test_anonymous_confidence_is_capped_below_auto_block(hub):
    out = await _share("198.51.100.7", confidence=1.0)
    assert out["status"] == "accepted"
    assert hub[0]["confidence"] <= 0.6 < 0.8


async def test_a_node_with_the_hub_key_keeps_its_confidence(hub):
    await _share("198.51.100.7", confidence=0.95, key="hub-key")
    assert hub[0]["confidence"] == 0.95
    await _share("198.51.100.8", confidence=0.95, key="wrong")
    assert hub[1]["confidence"] <= 0.6


async def test_empty_configured_key_never_matches(hub, monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_HUB_SHARED_KEY", "")
    await _share("198.51.100.7", confidence=0.95, key="")
    assert hub[0]["confidence"] <= 0.6


async def test_safelisted_address_is_refused_by_the_hub(hub, monkeypatch):
    from app.core import attack_detector
    monkeypatch.setattr(attack_detector, "_is_safe_ip", lambda ip: ip == "198.51.100.99")
    out = await _share("198.51.100.99", key="hub-key")
    assert out["status"] == "rejected" and hub == []


async def test_subscriber_never_blocks_its_own_safelist(monkeypatch):
    from app.core import attack_detector, ip_blocker
    from app.services.hub_sync_client import HubSyncClient

    calls = []
    monkeypatch.setattr(ip_blocker.ip_blocker_service, "block_ip",
                        lambda ip, **k: calls.append(ip) or {"success": True})
    monkeypatch.setattr(attack_detector, "_is_safe_ip", lambda ip: ip == "198.51.100.99")
    client = HubSyncClient()
    await client._auto_block_ip("198.51.100.99", "shared")
    await client._auto_block_ip("not-an-ip; rm -rf /", "shared")
    await client._auto_block_ip("198.51.100.7", "shared")
    assert calls == ["198.51.100.7"]


async def test_auto_sharer_does_not_publish_safe_addresses(monkeypatch):
    from app.core import attack_detector
    from app.services import auto_sharer as mod

    pushed = []
    monkeypatch.setattr(mod, "fire_and_forget", lambda coro: (pushed.append(1), coro.close()))
    monkeypatch.setattr(attack_detector, "_is_safe_ip", lambda ip: ip == "198.51.100.99")
    sharer = mod.AutoSharer() if hasattr(mod, "AutoSharer") else type(mod.auto_sharer)()
    await sharer._share_ip("198.51.100.99", "honeypot_probe", 0.9, "honeypot")
    assert pushed == []


async def test_sharing_node_registry_is_bounded(monkeypatch):
    monkeypatch.setattr(threats, "_sharing_nodes", {})
    monkeypatch.setattr(threats, "_MAX_SHARING_NODES", 3)
    for i in range(6):
        await threats.register_sharing_node.__wrapped__(
            _request(), threats.SharingNodeRegister(node_id=f"n{i}"))
    assert len(threats._sharing_nodes) == 3
