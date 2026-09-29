"""Per-node upload tokens for the endpoint agent.

Builds a small FastAPI app from the real routers over an in-memory SQLite
database and drives it over ASGI, so the auth dependencies, the enrollment
handshake and the three upload routes are exercised exactly as served.
Tokens are generated at runtime; nothing here is a real credential.
"""
from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.api import agents as agents_api
from app.api import antivirus as av_api
from app.api import edr as edr_api
from app.api import nodes as nodes_api
from app.core.auth import hash_node_token, get_current_client
from app.database import get_db
from app.models import Base, Client
from app.models.endpoint_agent import EndpointAgent

NODE_SECRET = "unit-test-node-secret"
EDR = {"events_dropped_total": 0, "events": []}


@pytest.fixture
async def env(monkeypatch):
    monkeypatch.setenv("AEGIS_NODE_SECRET", NODE_SECRET)
    nodes_api._pending_enrollments.clear()
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async with factory() as s:
        s.add_all([
            Client(name="A", slug="tn-a", api_key="key-a"),
            Client(name="B", slug="tn-b", api_key="key-b"),
        ])
        await s.commit()

    app = FastAPI()
    for r in (nodes_api.router, edr_api.router, agents_api.router, av_api.router):
        app.include_router(r)

    @app.get("/plain-client")
    async def plain(client=Depends(get_current_client)):
        return {"client": client.slug}

    async def _db():
        async with factory() as s:
            yield s

    app.dependency_overrides[get_db] = _db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as http:
        yield http, factory
    await engine.dispose()


NODE_AUTH = {"X-AEGIS-Node-Auth": NODE_SECRET}


async def enroll(http, api_key="key-a", hostname="host-1"):
    """Full handshake: agent announces, manager enrolls, agent polls status."""
    code = "C6-AAAA-BBBB"
    await http.post("/nodes/announce", headers=NODE_AUTH,
                    json={"enroll_code": code, "hostname": hostname})
    r = await http.post("/nodes/enroll", headers={"X-API-Key": api_key},
                        json={"code": code})
    assert r.status_code == 200, r.text
    st = await http.get(f"/nodes/status/{code}", headers=NODE_AUTH)
    return code, r.json()["node_id"], st.json()


def node_headers(node_id, token):
    return {"X-AEGIS-Node-Id": node_id, "X-AEGIS-Node-Token": token}


def av_body(node_id):
    return {"agent_id": node_id, "path": "/tmp/x", "sha256": "0" * 64,
            "rule": "r", "engine": "yara", "quarantined": True}


def post_upload(http, route, node_id, headers):
    if route == "edr":
        return http.post("/edr/events", headers=headers, json={"agent_id": node_id, **EDR})
    if route == "agents":
        return http.post("/agents/events", headers=headers, json={"agent_id": node_id, "events": []})
    return http.post("/antivirus/detections", headers=headers, json=av_body(node_id))


ROUTES = ["edr", "agents", "av"]


async def test_token_minted_once_and_only_hash_stored(env):
    http, factory = env
    code, node_id, status = await enroll(http)
    token = status["node_token"]
    assert status["status"] == "active" and status["node_id"] == node_id
    assert len(token) >= 40

    async with factory() as s:
        row = await s.get(EndpointAgent, node_id)
    assert row.node_token_hash == hash_node_token(token)
    assert token not in (row.node_token_hash, str(row.config))

    again = (await http.get(f"/nodes/status/{code}", headers=NODE_AUTH)).json()
    assert again["status"] == "active" and "node_token" not in again
    announce = (await http.post("/nodes/announce", headers=NODE_AUTH,
                                json={"enroll_code": code, "hostname": "h"})).json()
    assert "node_token" not in announce


@pytest.mark.parametrize("route", ROUTES)
async def test_valid_token_accepted(env, route):
    http, _ = env
    _, node_id, status = await enroll(http)
    r = await post_upload(http, route, node_id, node_headers(node_id, status["node_token"]))
    assert r.status_code == 200, r.text


@pytest.mark.parametrize("route", ROUTES)
async def test_tenant_api_key_still_accepted(env, route):
    http, _ = env
    _, node_id, _ = await enroll(http)
    r = await post_upload(http, route, node_id, {"X-API-Key": "key-a"})
    assert r.status_code == 200, r.text


@pytest.mark.parametrize("route", ROUTES)
async def test_wrong_missing_token_rejected(env, route):
    http, _ = env
    _, node_id, status = await enroll(http)
    assert (await post_upload(http, route, node_id, {})).status_code == 401
    bad = node_headers(node_id, "x" * 43)
    assert (await post_upload(http, route, node_id, bad)).status_code == 401
    no_id = {"X-AEGIS-Node-Token": status["node_token"]}
    assert (await post_upload(http, route, node_id, no_id)).status_code == 401
    # a bad node token is not rescued by a valid tenant key on the same request
    mixed = {**bad, "X-API-Key": "key-a"}
    assert (await post_upload(http, route, node_id, mixed)).status_code == 401


@pytest.mark.parametrize("route", ROUTES)
async def test_revoked_token_rejected(env, route):
    http, _ = env
    _, node_id, status = await enroll(http)
    r = await http.post(f"/nodes/{node_id}/token/revoke", headers={"X-API-Key": "key-a"})
    assert r.status_code == 204
    r = await post_upload(http, route, node_id, node_headers(node_id, status["node_token"]))
    assert r.status_code == 401


async def test_revoke_is_tenant_scoped(env):
    http, _ = env
    _, node_id, status = await enroll(http)
    r = await http.post(f"/nodes/{node_id}/token/revoke", headers={"X-API-Key": "key-b"})
    assert r.status_code == 404
    r = await post_upload(http, "edr", node_id, node_headers(node_id, status["node_token"]))
    assert r.status_code == 200


@pytest.mark.parametrize("route", ROUTES)
async def test_token_for_node_a_cannot_post_as_node_b(env, route):
    http, factory = env
    _, node_a, status = await enroll(http, hostname="host-a")
    async with factory() as s:
        client_a = (await s.execute(select(Client).where(Client.slug == "tn-a"))).scalar_one()
        s.add(EndpointAgent(id="node-other", client_id=client_a.id, hostname="host-b"))
        await s.commit()
    r = await post_upload(http, route, "node-other", node_headers(node_a, status["node_token"]))
    assert r.status_code == 403


async def test_node_token_rejected_by_plain_client_route(env):
    http, _ = env
    _, node_id, status = await enroll(http)
    r = await http.get("/plain-client", headers=node_headers(node_id, status["node_token"]))
    assert r.status_code == 401
    assert (await http.get("/plain-client", headers={"X-API-Key": "key-a"})).status_code == 200


async def _legacy_node(factory):
    async with factory() as s:
        client_a = (await s.execute(select(Client).where(Client.slug == "tn-a"))).scalar_one()
        s.add(EndpointAgent(id="node-legacy", client_id=client_a.id, hostname="old"))
        await s.commit()
    return "node-legacy"


async def test_reissue_for_legacy_node_requires_the_shared_secret(env):
    http, factory = env
    node_id = await _legacy_node(factory)
    body = {"node_id": node_id}
    assert (await http.post("/nodes/token/reissue", json=body)).status_code == 401
    wrong = {"X-AEGIS-Node-Auth": "nope"}
    assert (await http.post("/nodes/token/reissue", json=body, headers=wrong)).status_code == 401
    # a tenant key is not a substitute for the node secret
    assert (await http.post("/nodes/token/reissue", json=body,
                            headers={"X-API-Key": "key-a"})).status_code == 401

    r = await http.post("/nodes/token/reissue", json=body, headers=NODE_AUTH)
    assert r.status_code == 200
    token = r.json()["node_token"]
    up = await post_upload(http, "edr", node_id, node_headers(node_id, token))
    assert up.status_code == 200


async def test_reissue_is_one_shot_and_cannot_replace_or_unrevoke(env):
    http, factory = env
    node_id = await _legacy_node(factory)
    body = {"node_id": node_id}
    assert (await http.post("/nodes/token/reissue", json=body, headers=NODE_AUTH)).status_code == 200
    assert (await http.post("/nodes/token/reissue", json=body, headers=NODE_AUTH)).status_code == 409

    await http.post(f"/nodes/{node_id}/token/revoke", headers={"X-API-Key": "key-a"})
    assert (await http.post("/nodes/token/reissue", json=body, headers=NODE_AUTH)).status_code == 409

    # an enrolled node (has a token) cannot be re-minted either
    _, enrolled, _ = await enroll(http, hostname="fresh")
    r = await http.post("/nodes/token/reissue", json={"node_id": enrolled}, headers=NODE_AUTH)
    assert r.status_code == 409
    r = await http.post("/nodes/token/reissue", json={"node_id": "node-missing"}, headers=NODE_AUTH)
    assert r.status_code == 404


async def test_reissue_disabled_without_a_configured_secret(env, monkeypatch):
    http, factory = env
    node_id = await _legacy_node(factory)
    monkeypatch.delenv("AEGIS_NODE_SECRET")
    r = await http.post("/nodes/token/reissue", json={"node_id": node_id})
    assert r.status_code == 403
    r = await http.post("/nodes/token/reissue", json={"node_id": node_id},
                        headers={"X-AEGIS-Node-Auth": ""})
    assert r.status_code == 403


async def test_rotate_lets_the_agent_claim_a_new_token(env):
    http, _ = env
    _, node_id, status = await enroll(http)
    old = status["node_token"]
    assert (await http.post(f"/nodes/{node_id}/token/rotate",
                            headers={"X-API-Key": "key-a"})).status_code == 204
    assert (await post_upload(http, "edr", node_id, node_headers(node_id, old))).status_code == 401
    new = (await http.post("/nodes/token/reissue", json={"node_id": node_id},
                           headers=NODE_AUTH)).json()["node_token"]
    assert new != old
    assert (await post_upload(http, "edr", node_id, node_headers(node_id, new))).status_code == 200
