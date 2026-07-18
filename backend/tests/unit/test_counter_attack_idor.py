"""
Unit tests for the IDOR fix on GET /response/counter-attack/{incident_id}
(P0-11): a client could read the cached counter-attack analysis of an
incident belonging to a DIFFERENT client, because the handler fetched the
analysis straight from the in-memory cache without checking that the
incident_id belonged to the caller's tenant.

Why this lives in tests/unit/ (not tests/integration/ or a top-level
test_response.py-style test):

- tests/test_response.py imports `from tests.conftest import
  api_key_headers, jwt_headers`, but no tests/conftest.py exists in this
  checkout — that harness is not currently runnable here.
- tests/integration/conftest.py explicitly hits a LIVE backend over HTTP and
  is gated behind AEGIS_LIVEFIRE=1 (no server is running in this sandbox).
- tests/unit/conftest.py provides no app/DB fixtures at all ("no app startup
  or DB required").

So these tests build their own throwaway in-memory SQLite AsyncSession,
seed two tenants (Client A / Client B) plus one incident owned by Client B,
and call the route function `get_counter_attack_analysis` directly
(bypassing FastAPI's HTTP/Depends plumbing, but exercising the exact same
SQLAlchemy ownership-check code added in app/api/response.py). This proves
the ownership filter actually runs and rejects cross-tenant reads with 404.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.response import get_counter_attack_analysis
from app.core.auth import AuthContext
from app.models import Base, Client, Incident
from app.services.counter_attack import counter_attack_engine


@pytest.fixture
async def sqlite_session():
    """Fresh in-memory SQLite AsyncSession with all AEGIS tables created."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.fixture
async def two_tenants(sqlite_session):
    """Two clients (A, B) and one incident owned exclusively by client B."""
    client_a = Client(name="Tenant A", slug="tenant-a-idor", api_key="key-a-idor")
    client_b = Client(name="Tenant B", slug="tenant-b-idor", api_key="key-b-idor")
    sqlite_session.add_all([client_a, client_b])
    await sqlite_session.commit()
    await sqlite_session.refresh(client_a)
    await sqlite_session.refresh(client_b)

    incident_b = Incident(
        client_id=client_b.id,
        title="SSH Brute Force from 45.33.32.156",
        severity="high",
        status="open",
        source_ip="45.33.32.156",
    )
    sqlite_session.add(incident_b)
    await sqlite_session.commit()
    await sqlite_session.refresh(incident_b)

    return client_a, client_b, incident_b


def _seed_cached_analysis(incident_id: str) -> dict:
    analysis = {
        "incident_id": incident_id,
        "source_ip": "45.33.32.156",
        "analysis": "attacker profiled — SSH credential stuffing from known botnet",
        "threat_level": "high",
        "recommended_actions": ["block_ip", "report_abuse"],
    }
    counter_attack_engine._analyses[incident_id] = analysis
    return analysis


@pytest.mark.asyncio
async def test_cross_tenant_read_returns_404(sqlite_session, two_tenants):
    """Client A must NOT be able to read Client B's cached counter-attack analysis."""
    client_a, client_b, incident_b = two_tenants
    _seed_cached_analysis(incident_b.id)

    auth_a = AuthContext(client=client_a, role="admin")
    try:
        with pytest.raises(HTTPException) as exc_info:
            await get_counter_attack_analysis(
                incident_id=incident_b.id,
                auth=auth_a,
                db=sqlite_session,
            )
        assert exc_info.value.status_code == 404
    finally:
        counter_attack_engine._analyses.pop(incident_b.id, None)


@pytest.mark.asyncio
async def test_owner_can_still_read_own_analysis(sqlite_session, two_tenants):
    """The owning tenant (Client B) can still read its own cached analysis."""
    _, client_b, incident_b = two_tenants
    seeded = _seed_cached_analysis(incident_b.id)

    auth_b = AuthContext(client=client_b, role="admin")
    try:
        result = await get_counter_attack_analysis(
            incident_id=incident_b.id,
            auth=auth_b,
            db=sqlite_session,
        )
        assert result == seeded
    finally:
        counter_attack_engine._analyses.pop(incident_b.id, None)


@pytest.mark.asyncio
async def test_unknown_incident_returns_404(sqlite_session, two_tenants):
    """A nonexistent incident_id returns 404 regardless of caller."""
    client_a, _, _ = two_tenants
    auth_a = AuthContext(client=client_a, role="admin")

    with pytest.raises(HTTPException) as exc_info:
        await get_counter_attack_analysis(
            incident_id="does-not-exist",
            auth=auth_a,
            db=sqlite_session,
        )
    assert exc_info.value.status_code == 404
