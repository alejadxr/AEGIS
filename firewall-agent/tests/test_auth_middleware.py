"""Shared-secret middleware tests. Run: cd firewall-agent && python3 -m pytest tests -q"""
import logging
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import main  # noqa: E402

SECRET = "test-secret-value"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main, "AEGIS_FIREWALL_SECRET", SECRET)
    monkeypatch.setattr(main, "_PUBLIC_READ_PATHS", frozenset({"/blocked"}))
    main._reject_last_logged.clear()
    # No context manager: skip lifespan (iptables setup).
    return TestClient(main.app, raise_server_exceptions=False)


def test_compat_mode_accepts_everything(monkeypatch):
    monkeypatch.setattr(main, "AEGIS_FIREWALL_SECRET", "")
    c = TestClient(main.app, raise_server_exceptions=False)
    assert c.get("/health").status_code != 401
    assert c.post("/block", json={"ip": "8.8.8.8"}).status_code != 401


def test_health_is_open(client):
    assert client.get("/health").status_code != 401


def test_public_read_allowed_without_header(client):
    assert client.get("/blocked").status_code != 401
    assert client.get("/blocked/").status_code != 401


@pytest.mark.parametrize("method,path", [
    ("post", "/block"), ("delete", "/block/1.2.3.4"), ("post", "/dos/harden"),
    ("post", "/dos/revert"), ("post", "/ai/chat"), ("get", "/attackers"),
    ("get", "/status"),
])
def test_everything_else_needs_secret(client, method, path):
    r = getattr(client, method)(path)
    assert r.status_code == 401


def test_mutating_method_on_public_path_is_not_public(client):
    assert client.post("/blocked").status_code == 401
    assert client.delete("/blocked").status_code == 401


def test_wrong_secret_rejected_right_secret_accepted(client):
    assert client.get("/attackers", headers={"X-AEGIS-FW-Auth": "nope"}).status_code == 401
    r = client.get("/attackers", headers={"X-AEGIS-FW-Auth": SECRET})
    assert r.status_code != 401


def test_public_read_env_is_configurable(client, monkeypatch):
    monkeypatch.setattr(main, "_PUBLIC_READ_PATHS", frozenset({"/status"}))
    assert client.get("/status").status_code != 401
    assert client.get("/blocked").status_code == 401


def test_rejections_logged_once_and_without_secret(client, caplog):
    with caplog.at_level(logging.WARNING, logger="aegis-firewall"):
        client.post("/block", json={"ip": "8.8.8.8"}, headers={"X-AEGIS-FW-Auth": "guess"})
        client.post("/block", json={"ip": "8.8.8.8"}, headers={"X-AEGIS-FW-Auth": "guess"})
    msgs = [r.getMessage() for r in caplog.records if "auth rejected" in r.getMessage()]
    assert len(msgs) == 1
    assert "POST /block" in msgs[0]
    assert "guess" not in msgs[0] and SECRET not in msgs[0]
