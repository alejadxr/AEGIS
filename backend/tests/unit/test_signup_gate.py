"""Unauthenticated signup must not mint an admin on a configured install (audit C1)."""
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api import onboarding
from app.config import settings
from app.models.base import Base
from app.models.client import Client


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(lambda c: Base.metadata.create_all(c, tables=[Client.__table__]))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session
    await engine.dispose()


async def test_open_on_a_fresh_install_with_only_the_demo_org(db, monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_ALLOW_SIGNUP", False)
    db.add(Client(id="d", name="Demo", slug="demo", api_key="k0"))
    await db.commit()
    assert await onboarding._signup_open(db) is True


async def test_closed_once_a_real_organisation_exists(db, monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_ALLOW_SIGNUP", False)
    db.add(Client(id="d", name="Demo", slug="demo", api_key="k0"))
    db.add(Client(id="w", name="Real Org", slug="real-org", api_key="k1"))
    await db.commit()
    assert await onboarding._signup_open(db) is False


async def test_flag_reopens_it_for_deliberate_multi_tenant(db, monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_ALLOW_SIGNUP", True)
    db.add(Client(id="w", name="Real Org", slug="real-org", api_key="k1"))
    await db.commit()
    assert await onboarding._signup_open(db) is True


async def test_signup_route_refuses_with_403_when_closed(db, monkeypatch):
    from fastapi import HTTPException
    from starlette.requests import Request

    monkeypatch.setattr(settings, "AEGIS_ALLOW_SIGNUP", False)
    db.add(Client(id="w", name="Real Org", slug="real-org", api_key="k1"))
    await db.commit()
    body = onboarding.SignupRequest(
        org_name="Evil Org", admin_name="x", admin_email="x@example.com", admin_password="correct-horse-battery",
    )
    request = Request({"type": "http", "method": "POST", "path": "/", "headers": [],
                       "client": ("203.0.113.5", 1234), "query_string": b""})
    # __wrapped__ skips the slowapi decorator; the gate is the first statement.
    with pytest.raises(HTTPException) as exc:
        await onboarding.signup.__wrapped__(request, body, db)
    assert exc.value.status_code == 403
    assert (await db.execute(Client.__table__.select())).fetchall().__len__() == 1
