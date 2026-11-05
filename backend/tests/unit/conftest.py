# Unit tests conftest — no app startup or DB required.
#
# The fixtures below are opt-in (nothing is autouse). They exist for the
# operator-action tests (block / safelist / incident status / assistant), which
# must never touch the developer's real blocklist, safelist or Pi agent.
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


@pytest.fixture
def ops_env(monkeypatch, tmp_path):
    """Isolated safelist file + blocklist file, and recording fakes for the Pi
    agent and the system firewall. Returns a namespace to assert against."""
    from app.core import attack_detector as ad
    from app.core import ip_blocker, safelist_store
    from app.core.firewall_client import firewall_client
    import app.services.firewall_local as firewall_local

    monkeypatch.setattr(safelist_store, "SAFELIST_FILE", tmp_path / "safelist.json")
    monkeypatch.setattr(safelist_store, "_next_check", 0.0)
    safelist_store.load()

    monkeypatch.setattr(ip_blocker, "BLOCKED_IPS_FILE", tmp_path / "blocked_ips.txt")
    monkeypatch.setattr(ip_blocker.ip_blocker_service, "_blocked", set())
    monkeypatch.setattr(ad, "_blocked_ips", set())

    pi_block = AsyncMock(return_value={"success": True, "response": {"blocked": True}})
    pi_unblock = AsyncMock(return_value={"success": True})
    monkeypatch.setattr(firewall_client, "block_ip", pi_block)
    monkeypatch.setattr(firewall_client, "unblock_ip", pi_unblock)

    sysfw = SimpleNamespace(calls=[], available=True)
    sysfw.block = lambda ip: sysfw.calls.append(("block", ip)) or True
    sysfw.unblock = lambda ip: sysfw.calls.append(("unblock", ip)) or True
    # Some tests reload firewall_local, so the responder may hold an older module
    # object than sys.modules does: patch every reference that code will use.
    from app.modules.response import responder
    for mod in {id(m): m for m in (firewall_local, responder.firewall_local)}.values():
        monkeypatch.setattr(mod, "get_firewall", lambda: sysfw)

    from app.config import settings
    monkeypatch.setattr(settings, "AEGIS_FIREWALL_URL", "http://pi.example.com:8765", raising=False)
    monkeypatch.delenv("AEGIS_BLOCKS_PERMANENT", raising=False)

    yield SimpleNamespace(
        tmp=tmp_path, pi_block=pi_block, pi_unblock=pi_unblock, sysfw=sysfw,
        blocker=ip_blocker.ip_blocker_service, safelist_file=tmp_path / "safelist.json", ad=ad,
    )
    safelist_store.load()   # drop the tmp state so later tests see the module default


@pytest_asyncio.fixture
async def db_factory():
    from app.models.action import Action
    from app.models.asset import Asset
    from app.models.audit_log import AuditLog
    from app.models.base import Base
    from app.models.client import Client
    from app.models.honeypot import Honeypot
    from app.models.incident import Incident
    from app.models.vulnerability import Vulnerability

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(lambda c: Base.metadata.create_all(
            c, tables=[m.__table__ for m in (Client, Asset, Incident, Action, AuditLog, Vulnerability, Honeypot)]))
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as db:
        db.add(Client(id="c1", name="Test Org", slug="t", api_key="k"))
        await db.commit()
    yield factory
    await engine.dispose()


def make_auth(role="admin", email="op@example.com"):
    from app.core.auth import AuthContext
    from app.models.client import Client
    return AuthContext(client=Client(id="c1", name="Test Org", slug="t", api_key="k"),
                       role=role, email=email)
