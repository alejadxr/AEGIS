"""Per-agent cached process index + edr_chain_handler: no per-event DB load."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import event as sa_event
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.core import bg_tasks
from app.models.endpoint_agent import (
    AgentEvent, EndpointAgent, EventCategory, EventSeverity,
)
from app.services import process_tree as pt
from app.services.process_tree import (
    ProcessIndex, compute_tree, load_process_index,
)

AGENT = "agent-cache-1"
CLIENT = "client-cache-1"


@pytest.fixture(autouse=True)
def _fresh():
    pt.reset_cache()
    yield
    pt.reset_cache()


async def _setup(seed_n):
    eng = create_async_engine("sqlite+aiosqlite://")
    async with eng.begin() as c:
        await c.run_sync(lambda sc: EndpointAgent.__table__.create(sc))
        await c.run_sync(lambda sc: AgentEvent.__table__.create(sc))
    maker = async_sessionmaker(eng, expire_on_commit=False)
    async with maker() as s:
        s.add(EndpointAgent(id=AGENT, client_id=CLIENT, hostname="h.example.test"))
        for i in range(seed_n):
            s.add(AgentEvent(
                agent_id=AGENT, client_id=CLIENT, category=EventCategory.process,
                severity=EventSeverity.info, title="proc_start: s.exe",
                timestamp=datetime.utcnow() - timedelta(seconds=seed_n - i + 5),
                details={"kind": "process_start", "pid": 500 + i, "ppid": 500 + i - 1,
                         "process_name": "s.exe"}))
        await s.commit()
    stmts: list[str] = []
    sa_event.listen(eng.sync_engine, "before_cursor_execute",
                    lambda conn, cur, st, *a: stmts.append(st))
    return eng, maker, stmts


def _loads(stmts):
    return [s for s in stmts if "FROM agent_events" in s and "agent_events.category" in s]


def _main():
    try:
        import app.main as main
    except ImportError as e:  # optional deps (e.g. email-validator) missing locally
        pytest.skip(f"app.main not importable here: {e}")
    return main


def _payload(i, ppid=None):
    return {"kind": "process_start", "agent_id": AGENT, "pid": 90000 + i,
            "ppid": ppid if ppid is not None else 519, "process_name": "a.exe",
            "command_line": "a.exe", "timestamp": datetime.utcnow().isoformat()}


def test_handler_300_events_one_index_load(monkeypatch):
    main = _main()

    async def go():
        eng, maker, stmts = await _setup(50)
        monkeypatch.setattr(main, "async_session", maker)
        for i in range(300):
            await main.edr_chain_handler(_payload(i))
        while bg_tasks._inflight:
            await asyncio.gather(*list(bg_tasks._inflight))
        await eng.dispose()
        return stmts

    stmts = asyncio.run(go())
    assert len(_loads(stmts)) <= 1
    # no agent lookup either: nothing matched, so no session was needed
    assert not [s for s in stmts if "FROM endpoint_agents" in s]


def test_single_flight_concurrent_misses(monkeypatch):
    async def go():
        eng, maker, stmts = await _setup(50)
        await asyncio.gather(*[
            pt.get_agent_index(AGENT, session_factory=maker) for _ in range(25)
        ])
        first = len(_loads(stmts))
        # concurrent lookup misses (unknown parent) after the min interval
        pt._entries[AGENT].loaded_at -= 120
        await asyncio.gather(*[
            pt.ancestors_for(AGENT, 505, session_factory=maker) for _ in range(25)
        ])
        await eng.dispose()
        return first, len(_loads(stmts))

    first, total = asyncio.run(go())
    assert first == 1
    # 500 has parent 499 which is not stored -> incomplete chain -> one refresh
    assert total == 2


def test_miss_refresh_is_rate_limited():
    async def go():
        eng, maker, stmts = await _setup(10)
        for _ in range(20):
            await pt.ancestors_for(AGENT, 505, session_factory=maker)  # chain ends at 499
        await eng.dispose()
        return len(_loads(stmts))

    assert asyncio.run(go()) == 1


def test_caps_enforced(monkeypatch):
    monkeypatch.setattr(pt, "MAX_NODES_PER_AGENT", 100)
    monkeypatch.setattr(pt, "MAX_AGENTS", 3)
    now = datetime.utcnow()
    idx = ProcessIndex()
    for i in range(300):
        idx.add_event(now - timedelta(seconds=300 - i), "t", {"pid": i + 1, "ppid": i})
    idx.prune(None, 100)
    assert len(idx.by_pid) == 100 and min(idx.by_pid) == 201  # oldest dropped
    assert all(c in idx.by_pid for kids in idx.children_of.values() for c in kids)

    # window eviction
    idx2 = ProcessIndex()
    idx2.add_event(now - timedelta(hours=30), "t", {"pid": 1})
    idx2.add_event(now, "t", {"pid": 2})
    idx2.prune(now - timedelta(hours=24), 100)
    assert list(idx2.by_pid) == [2]

    # feed path auto-prunes once past 1.25x cap
    async def go():
        eng, maker, _ = await _setup(1)
        await pt.get_agent_index(AGENT, session_factory=maker)
        for i in range(200):
            pt.feed_event(AGENT, now + timedelta(seconds=i), "t", {"pid": 1000 + i})
        await eng.dispose()
    asyncio.run(go())
    assert len(pt._entries[AGENT].index.by_pid) <= 100 * 1.25 + 1

    # agent LRU
    for n in range(6):
        pt.feed_event(f"a{n}", now, "t", {"pid": 1})
    assert len(pt._entries) == 3 and "a5" in pt._entries and "a0" not in pt._entries


def test_ttl_refresh(monkeypatch):
    monkeypatch.setenv("AEGIS_PROCESS_INDEX_TTL_S", "900")

    async def go():
        eng, maker, stmts = await _setup(20)
        await pt.get_agent_index(AGENT, session_factory=maker)
        await pt.get_agent_index(AGENT, session_factory=maker)
        assert len(_loads(stmts)) == 1
        pt._entries[AGENT].loaded_at -= 901
        await pt.get_agent_index(AGENT, session_factory=maker)
        n = len(_loads(stmts))
        await eng.dispose()
        return n

    assert asyncio.run(go()) == 2


def test_events_fed_before_and_during_load_survive():
    async def go():
        eng, maker, _ = await _setup(5)
        pt.feed_event(AGENT, datetime.utcnow(), "t", {"pid": 777, "ppid": 500})  # pre-load
        idx = await pt.get_agent_index(AGENT, session_factory=maker)
        assert 777 in idx.by_pid
        await eng.dispose()

    asyncio.run(go())


def test_equivalence_with_fresh_load():
    async def go():
        eng, maker, _ = await _setup(200)
        async with maker() as s:
            fresh = await load_process_index(s, AGENT)
        cached_ancestors = {}
        for pid in (500, 520, 699, 12345):
            cached_ancestors[pid] = await pt.ancestors_for(AGENT, pid, session_factory=maker)
        # live feed, then compare against a DB reload containing the same rows
        ts = datetime.utcnow()
        async with maker() as s:
            for k in range(5):
                d = {"kind": "process_start", "pid": 40000 + k, "ppid": 40000 + k - 1 if k else 600,
                     "process_name": "n.exe"}
                pt.feed_event(AGENT, ts + timedelta(seconds=k), f"proc_start: n.exe (pid={40000+k})", d)
                s.add(AgentEvent(agent_id=AGENT, client_id=CLIENT, category=EventCategory.process,
                                 severity=EventSeverity.info, title=f"proc_start: n.exe (pid={40000+k})",
                                 timestamp=ts + timedelta(seconds=k), details=d))
            await s.commit()
        async with maker() as s:
            reloaded = await load_process_index(s, AGENT)
        live = pt._entries[AGENT].index
        for pid in (40004, 40000, 600, 500):
            assert (compute_tree(live, pid, ancestors_only=True)["ancestors"]
                    == compute_tree(reloaded, pid, ancestors_only=True)["ancestors"])
        for pid, anc in cached_ancestors.items():
            assert anc == compute_tree(fresh, pid, ancestors_only=True)["ancestors"]
        await eng.dispose()

    asyncio.run(go())


def test_handler_match_persists_incident(monkeypatch):
    """A matching cmd_pattern still opens a session and stores the incident."""
    main = _main()
    from app.services import attack_chain_detector as acd

    if not acd.CMD_PATTERN_RULES:
        pytest.skip("no cmd pattern rules")

    async def go():
        eng, maker, stmts = await _setup(5)
        monkeypatch.setattr(main, "async_session", maker)
        seen = []
        orig = acd.persist_matches

        def spy(db, agent, anchor, event, matches):
            seen.append(len(matches))
            return orig(db, agent, anchor, event, matches)

        monkeypatch.setattr(acd, "persist_matches", spy)
        monkeypatch.setattr(acd, "match_event", _fake_match(acd))
        await main.edr_chain_handler(_payload(1))
        while bg_tasks._inflight:
            await asyncio.gather(*list(bg_tasks._inflight))
        await eng.dispose()
        return seen

    seen = asyncio.run(go())
    assert seen == [1]


def _fake_match(acd):
    async def fake(event, fetch):
        m = acd.ChainMatch(rule_id="r", title="t", mitre_technique="T1", mitre_tactic="x",
                           severity="high", description="d", anchor_pid=1, ancestry=["a"])
        return {"pid": 1}, [m]
    return fake
