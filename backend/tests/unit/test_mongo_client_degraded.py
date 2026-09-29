"""An unreachable MongoDB hub must degrade to a quiet, single INFO 'disabled' state."""
import asyncio
import logging

import pytest

from app.core import mongo_client


class _FailingAdmin:
    async def command(self, *_a, **_kw):
        raise RuntimeError("The DNS query name does not exist: _mongodb._tcp.example.invalid.")


class _FailingClient:
    closed = False

    def __init__(self, *_a, **_kw):
        self.admin = _FailingAdmin()

    def close(self):
        _FailingClient.closed = True


@pytest.fixture(autouse=True)
def _reset_state():
    mongo_client._client = None
    mongo_client._db = None
    yield
    mongo_client._client = None
    mongo_client._db = None


def test_unreachable_hub_is_info_not_error(monkeypatch, caplog):
    monkeypatch.setattr(mongo_client.settings, "AEGIS_MONGODB_URI", "mongodb+srv://u:p@example.invalid/")
    monkeypatch.setattr(mongo_client, "AsyncIOMotorClient", _FailingClient)
    with caplog.at_level(logging.DEBUG, logger="cayde6.mongo"):
        assert asyncio.run(mongo_client.connect_mongo()) is False

    records = [r for r in caplog.records if r.name == "cayde6.mongo"]
    assert len(records) == 1
    assert records[0].levelno == logging.INFO
    assert "hub disabled" in records[0].getMessage()
    assert "example.invalid" not in records[0].getMessage()
    assert _FailingClient.closed is True


def test_dependents_degrade_when_disconnected():
    from app.services.threat_intel_hub import threat_intel_hub

    assert mongo_client.is_connected() is False
    assert mongo_client.get_aegis_collection() is None
    assert mongo_client.get_external_collection() is None
    assert asyncio.run(threat_intel_hub.share_ioc({"ioc_type": "ip", "ioc_value": "203.0.113.5"}))["status"] == "error"
    assert asyncio.run(threat_intel_hub.push_external("abuseipdb", [])) == 0
    assert asyncio.run(threat_intel_hub.pull_external()) == []


def test_not_configured_is_info(monkeypatch, caplog):
    monkeypatch.setattr(mongo_client.settings, "AEGIS_MONGODB_URI", "")
    with caplog.at_level(logging.DEBUG, logger="cayde6.mongo"):
        assert asyncio.run(mongo_client.connect_mongo()) is False
    assert all(r.levelno == logging.INFO for r in caplog.records if r.name == "cayde6.mongo")
