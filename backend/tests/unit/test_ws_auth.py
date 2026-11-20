"""The live-event socket must not stream to an unauthenticated caller (audit A1)."""
import asyncio
import json

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core import ws_auth
from app.core.auth import create_user_jwt_token
from app.core.ws_push import WSPushManager
from app.models.base import Base
from app.models.client import Client
from app.models.user import User, UserRole


class FakeWS:
    def __init__(self, frames=(), peer="203.0.113.5", headers=None, hang=False):
        self._frames = list(frames)
        self._hang = hang
        self.client = type("C", (), {"host": peer})()
        self.headers = headers or {}
        self.closed_with = None
        self.sent = []

    async def receive_text(self):
        if self._hang or not self._frames:
            await asyncio.sleep(3600)
        return self._frames.pop(0)

    async def close(self, code=1000):
        self.closed_with = code

    async def send_json(self, msg):
        self.sent.append(msg)


@pytest_asyncio.fixture
async def factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(lambda c: Base.metadata.create_all(c, tables=[Client.__table__, User.__table__]))
    f = async_sessionmaker(engine, expire_on_commit=False)
    async with f() as db:
        db.add(Client(id="c1", name="Org", slug="org", api_key="dummy-good-key"))
        db.add(User(id="u1", email="a@example.com", password_hash="x", name="A",
                    role=UserRole.viewer, client_id="c1", is_active=True))
        db.add(User(id="u2", email="b@example.com", password_hash="x", name="B",
                    role=UserRole.admin, client_id="c1", is_active=False))
        await db.commit()
    yield f
    await engine.dispose()


async def test_no_auth_frame_is_closed_4401(factory, monkeypatch):
    monkeypatch.setattr(ws_auth, "AUTH_TIMEOUT_SECONDS", 0.05)
    ws = FakeWS(hang=True)
    assert await ws_auth.authenticate_websocket(ws, factory) is None
    assert ws.closed_with == ws_auth.CLOSE_UNAUTHORIZED


@pytest.mark.parametrize("frame", [
    "not json",
    json.dumps({"type": "subscribe", "topics": ["*"]}),
    json.dumps({"type": "auth"}),
    json.dumps({"type": "auth", "api_key": "wrong"}),
    json.dumps({"type": "auth", "token": "garbage.jwt.value"}),
    json.dumps({"type": "auth", "api_key": {"$ne": ""}}),
])
async def test_bad_first_frame_is_rejected(factory, frame):
    ws = FakeWS([frame])
    assert await ws_auth.authenticate_websocket(ws, factory) is None
    assert ws.closed_with == ws_auth.CLOSE_UNAUTHORIZED


async def test_api_key_and_user_jwt_authenticate(factory):
    ident = await ws_auth.authenticate_websocket(
        FakeWS([json.dumps({"type": "auth", "api_key": "dummy-good-key"})]), factory)
    assert ident.tenant_id == "c1" and ident.role == "admin"

    token = create_user_jwt_token("u1", "a@example.com", "viewer", "c1")
    ident = await ws_auth.authenticate_websocket(
        FakeWS([json.dumps({"type": "auth", "token": token})]), factory)
    assert ident.tenant_id == "c1" and ident.role == "viewer"


async def test_inactive_user_token_is_rejected(factory):
    token = create_user_jwt_token("u2", "b@example.com", "admin", "c1")
    ws = FakeWS([json.dumps({"type": "auth", "token": token})])
    assert await ws_auth.authenticate_websocket(ws, factory) is None


def test_blocklist_applies_to_the_websocket_scope(monkeypatch):
    from app.core import attack_detector
    monkeypatch.setattr(attack_detector, "_blocked_ips", {"203.0.113.5"})
    assert ws_auth.websocket_ip_is_blocked(FakeWS(peer="203.0.113.5")) is True
    assert ws_auth.websocket_ip_is_blocked(FakeWS(peer="203.0.113.6")) is False
    # Through the tunnel the real client is in CF-Connecting-IP.
    via_tunnel = FakeWS(peer="127.0.0.1", headers={"cf-connecting-ip": "203.0.113.5"})
    assert ws_auth.websocket_ip_is_blocked(via_tunnel) is True


async def test_events_naming_another_tenant_are_not_delivered():
    mgr = WSPushManager()
    mine, other = FakeWS(), FakeWS()
    await mgr.register(mine, "a", tenant_id="c1")
    await mgr.register(other, "b", tenant_id="c2")
    await mgr.broadcast({"type": "alert_processed", "client_id": "c1", "title": "x"})
    await mgr.broadcast({"type": "log_line", "line": "global"})
    assert [m["type"] for m in mine.sent] == ["alert_processed", "log_line"]
    assert [m["type"] for m in other.sent] == ["log_line"]
