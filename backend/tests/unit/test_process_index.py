"""process_tree index: equivalence with the old per-call tree builder, and the
ingest cost bound (<= 1 process-index query per POST /edr/events batch)."""
from __future__ import annotations

import asyncio
import gzip
import json
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import event as sa_event
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.models.endpoint_agent import (
    AgentEvent, EndpointAgent, EventCategory, EventSeverity,
)
from app.services.process_tree import ProcessIndex, compute_tree

AGENT = "agent-px-1"
CLIENT = "client-px-1"
NOW = datetime.utcnow()


def _legacy(rows, pid, max_depth=12, ancestors_only=False):
    """Verbatim copy of the pre-fix build_process_tree body (rows ascending)."""
    by_pid, children_of = {}, {}
    for ev in rows:
        details = ev.details or {}
        ev_pid = details.get("pid") or details.get("process_pid")
        if ev_pid is None:
            continue
        try:
            ev_pid = int(ev_pid)
        except (TypeError, ValueError):
            continue
        ppid = details.get("ppid") or details.get("parent_pid")
        try:
            ppid = int(ppid) if ppid is not None else None
        except (TypeError, ValueError):
            ppid = None
        by_pid[ev_pid] = {
            "pid": ev_pid, "ppid": ppid,
            "name": details.get("process_name") or details.get("name"),
            "path": details.get("process_path") or details.get("path"),
            "command_line": details.get("command_line") or details.get("cmdline"),
            "user": details.get("user"),
            "started_at": ev.timestamp.isoformat() if ev.timestamp else None,
            "event_kind": details.get("kind") or ev.title,
        }
        if ppid is not None:
            children_of.setdefault(ppid, []).append(ev_pid)
    anchor = by_pid.get(pid)
    if not anchor:
        return {"anchor": {"pid": pid, "name": "<unknown>"}, "ancestors": [],
                "descendants": [], "total_nodes": 0}
    ancestors, cursor, depth = [], anchor.get("ppid"), 0
    while cursor is not None and depth < max_depth:
        parent = by_pid.get(cursor)
        if not parent:
            break
        ancestors.append(parent)
        cursor = parent.get("ppid")
        depth += 1
    if ancestors_only:
        return {"anchor": anchor, "ancestors": ancestors, "descendants": {},
                "total_nodes": len(by_pid)}

    def subtree(root, d=0):
        node = dict(by_pid.get(root, {"pid": root}))
        if d >= max_depth:
            node["children"] = []
            node["truncated"] = True
            return node
        node["children"] = [subtree(k, d + 1) for k in children_of.get(root, [])]
        return node

    return {"anchor": anchor, "ancestors": ancestors, "descendants": subtree(pid),
            "total_nodes": len(by_pid)}


def _row(i, pid, ppid, name="p.exe", kind="process_start"):
    return SimpleNamespace(
        timestamp=NOW - timedelta(minutes=1000 - i), title=f"{kind}: {name}",
        details={"kind": kind, "pid": pid, "ppid": ppid, "process_name": name,
                 "command_line": f"{name} --x"},
    )


def _synthetic_rows():
    rows, i = [], 0
    # chain 1 -> 2 -> ... -> 20 (depth > max_depth)
    for pid in range(1, 21):
        rows.append(_row(i, pid, pid - 1 if pid > 1 else None)); i += 1
    # pid reuse: 5 restarts under a different parent, later wins
    rows.append(_row(i, 5, 900, "reused.exe")); i += 1
    rows.append(_row(i, 900, 1, "newparent.exe")); i += 1
    # cycle 70 <-> 71
    rows.append(_row(i, 70, 71)); i += 1
    rows.append(_row(i, 71, 70)); i += 1
    # stop event overwrites node, junk pid, string pid
    rows.append(_row(i, 3, None, kind="process_stop")); i += 1
    rows.append(SimpleNamespace(timestamp=NOW, title="x", details={"pid": "abc"}))
    rows.append(SimpleNamespace(timestamp=NOW, title="x", details={"pid": "42", "ppid": "1"}))
    return rows


def _index(rows):
    idx = ProcessIndex()
    for r in rows:
        idx.add_event(r.timestamp, r.title, r.details)
    return idx


@pytest.mark.parametrize("pid", [1, 3, 5, 20, 900, 70, 71, 42, 999])
@pytest.mark.parametrize("max_depth", [3, 12])
@pytest.mark.parametrize("anc_only", [False, True])
def test_compute_tree_matches_legacy(pid, max_depth, anc_only):
    rows = _synthetic_rows()
    idx = _index(rows)
    assert compute_tree(idx, pid, max_depth, anc_only) == _legacy(rows, pid, max_depth, anc_only)


# ---------------------------------------------------------------------------
# ingest cost
# ---------------------------------------------------------------------------

class _Req:
    def __init__(self, payload):
        self._raw = json.dumps(payload).encode()
        self.headers = {}

    async def body(self):
        return self._raw


class _Bus:
    async def publish(self, *a, **k):
        pass

    publish_critical = publish
    publish_high = publish


def _batch(n, base_pid=100000):
    at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    evs = []
    for i in range(n):
        # each event's parent is the previous one in the same batch
        evs.append({"kind": "process_start", "at": at, "pid": base_pid + i,
                    "ppid": base_pid + i - 1 if i else 1,
                    "process_name": "a.exe", "process_path": "C:\\a.exe",
                    "command_line": "a.exe"})
    return {"agent_id": AGENT, "events_dropped_total": 0, "events": evs}


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
    return eng, maker


def _run_ingest(monkeypatch, payload, seed_n):
    from app.api import edr as edr_api
    from app.services import edr_transport

    seen = {}

    async def go():
        eng, maker = await _setup(seed_n)
        stmts = []
        sa_event.listen(
            eng.sync_engine, "before_cursor_execute",
            lambda conn, cur, st, *a: stmts.append(st),
        )
        monkeypatch.setattr(edr_transport, "event_bus", _Bus())
        monkeypatch.setattr(edr_api, "event_bus", _Bus())

        async def spy(db, agent, ev, fetch):
            seen[ev["pid"]] = [a["pid"] for a in await fetch(int(ev["pid"]))]
            return []

        monkeypatch.setattr(edr_api, "evaluate_event", spy)
        async with maker() as db:
            await edr_api.ingest_events(
                _Req(payload), db=db, auth=SimpleNamespace(client_id=CLIENT))
        await eng.dispose()
        return stmts

    stmts = asyncio.run(go())
    return seen, stmts


def _index_queries(stmts):
    return [s for s in stmts if s.lstrip().upper().startswith("SELECT")
            and "FROM agent_events" in s and "agent_events.category" in s]


def test_ingest_issues_at_most_one_index_query(monkeypatch):
    for n in (1, 50, 300):
        _, stmts = _run_ingest(monkeypatch, _batch(n), seed_n=20)
        assert len(_index_queries(stmts)) <= 1, n


def test_ingest_ancestry_sees_same_batch_parent_and_history(monkeypatch):
    seen, stmts = _run_ingest(monkeypatch, _batch(5), seed_n=20)
    # parent chain inside the batch: 100004 <- 100003 <- ... <- 100000 <- pid 1 (unknown)
    assert seen[100004] == [100003, 100002, 100001, 100000]
    assert seen[100000] == []
    assert len(_index_queries(stmts)) == 1


def test_ingest_ancestry_sees_stored_history(monkeypatch):
    p = _batch(1)
    p["events"][0]["ppid"] = 519  # seeded row, itself child of 518 ...
    seen, _ = _run_ingest(monkeypatch, p, seed_n=20)
    assert seen[100000][:3] == [519, 518, 517]
