"""The IP-block 403 must carry CORS headers for allowed origins.

CORSMiddleware has to be the OUTERMOST middleware; otherwise the browser sees
only "No 'Access-Control-Allow-Origin' header" for a blocked client and the
real cause (the block) is hidden.
"""
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.cors import CORSMiddleware

from app.core import attack_detector
from app.core.attack_detector import AttackDetectorMiddleware

BLOCKED_IP = "192.0.2.10"
ALLOWED = "https://dash.example.com"
DENIED = "https://evil.example.com"

MAIN_PY = Path(__file__).resolve().parents[2] / "app" / "main.py"


def _with_client_addr(app, addr):
    """Force scope["client"]; TestClient(client=...) needs newer Starlette than CI pins."""
    async def wrapper(scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            scope = {**scope, "client": addr}
        await app(scope, receive, send)

    return wrapper


@pytest.fixture
def client(monkeypatch):
    # Same registration order as app/main.py: CORS added last = outermost.
    app = FastAPI()

    @app.get("/api/v1/health")
    def health():
        return {"ok": True}

    app.add_middleware(AttackDetectorMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[ALLOWED],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    monkeypatch.setattr(attack_detector, "_blocked_ips", {BLOCKED_IP})
    return TestClient(_with_client_addr(app, (BLOCKED_IP, 50000)))


def test_main_registers_cors_last():
    src = MAIN_PY.read_text()
    cors = src.index("app.add_middleware(\n    CORSMiddleware")
    for other in (
        "app.add_middleware(AttackDetectorMiddleware)",
        "app.add_middleware(BodySizeLimitMiddleware)",
        "app.add_middleware(DoSShieldMiddleware)",
    ):
        assert src.index(other) < cors, f"{other} must be registered before CORS"


def test_blocked_get_has_acao_for_allowed_origin(client):
    r = client.get("/api/v1/health", headers={"Origin": ALLOWED})
    assert r.status_code == 403
    assert r.json() == {"detail": "blocked"}
    assert r.headers["access-control-allow-origin"] == ALLOWED


def test_blocked_get_has_no_acao_for_disallowed_origin(client):
    r = client.get("/api/v1/health", headers={"Origin": DENIED})
    assert r.status_code == 403
    assert r.json() == {"detail": "blocked"}
    assert "access-control-allow-origin" not in r.headers


def test_blocked_preflight_allowed_origin(client):
    r = client.options(
        "/api/v1/health",
        headers={"Origin": ALLOWED, "Access-Control-Request-Method": "GET"},
    )
    assert r.headers["access-control-allow-origin"] == ALLOWED


def test_blocked_preflight_disallowed_origin(client):
    r = client.options(
        "/api/v1/health",
        headers={"Origin": DENIED, "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in r.headers
