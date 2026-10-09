"""
Reconstruct process trees from agent_events (Task #5).

Given an anchor (agent_id, pid), return the full ancestor chain up to root
and the full descendant subtree. Events are correlated by pid/ppid within
the agent's scope.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import OrderedDict, deque
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.endpoint_agent import AgentEvent, EventCategory


logger = logging.getLogger("aegis.process_tree")


class ProcessIndex:
    """pid -> latest node, plus parent -> children, for one agent's window.

    Built from plain column tuples (never ORM entities) so nothing lands in
    the session identity map. `add_event` lets a caller keep it current as
    new process events are ingested without re-querying.
    """

    __slots__ = ("by_pid", "children_of", "_last_ts")

    def __init__(self) -> None:
        self.by_pid: dict[int, dict] = {}
        self.children_of: dict[int, list[int]] = {}
        self._last_ts: dict[int, object] = {}

    def add_event(self, timestamp, title, details) -> None:
        details = details or {}
        ev_pid = details.get("pid") or details.get("process_pid")
        if ev_pid is None:
            return
        try:
            ev_pid = int(ev_pid)
        except (TypeError, ValueError):
            return

        ppid = details.get("ppid") or details.get("parent_pid")
        try:
            ppid = int(ppid) if ppid is not None else None
        except (TypeError, ValueError):
            ppid = None

        # Query order is timestamp ASC, "latest wins". An out-of-order event
        # (older timestamp than what we hold) would have sorted earlier.
        prev = self._last_ts.get(ev_pid)
        if prev is not None and timestamp is not None and timestamp < prev:
            return
        if timestamp is not None:
            self._last_ts[ev_pid] = timestamp

        self.by_pid[ev_pid] = {
            "pid": ev_pid,
            "ppid": ppid,
            "name": details.get("process_name") or details.get("name"),
            "path": details.get("process_path") or details.get("path"),
            "command_line": details.get("command_line") or details.get("cmdline"),
            "user": details.get("user"),
            "started_at": timestamp.isoformat() if timestamp else None,
            "event_kind": details.get("kind") or title,
        }
        if ppid is not None:
            self.children_of.setdefault(ppid, []).append(ev_pid)

    def prune(self, cutoff, max_nodes: int) -> None:
        """Drop nodes older than `cutoff`, then the oldest beyond `max_nodes`."""
        ts_of = self._last_ts
        keep = [
            p for p in self.by_pid
            if cutoff is None or ts_of.get(p) is None or ts_of[p] >= cutoff
        ]
        if len(keep) > max_nodes:
            # Nodes without a timestamp rank oldest.
            keep.sort(key=lambda p: (ts_of.get(p) is not None, ts_of.get(p) or datetime.min))
            keep = keep[len(keep) - max_nodes:]
        keep_set = set(keep)
        self.by_pid = {p: self.by_pid[p] for p in keep_set}
        self._last_ts = {p: t for p, t in ts_of.items() if p in keep_set}
        self.children_of = {
            pp: kids2
            for pp, kids in self.children_of.items()
            if (kids2 := [c for c in kids if c in keep_set])
        }


async def load_process_index(
    db: AsyncSession,
    agent_id: str,
    time_window_hours: int = 24,
    max_events: int = 5000,
) -> ProcessIndex:
    """ONE column-only query (timestamp, title, details); no ORM entities."""
    from datetime import datetime, timedelta

    since = datetime.utcnow() - timedelta(hours=time_window_hours)
    stmt = (
        select(AgentEvent.timestamp, AgentEvent.title, AgentEvent.details)
        .where(
            and_(
                AgentEvent.agent_id == agent_id,
                AgentEvent.category == EventCategory.process,
                AgentEvent.timestamp >= since,
            )
        )
        .order_by(AgentEvent.timestamp.desc())
        .limit(max_events)
    )
    result = await db.execute(stmt)
    rows = result.all()
    index = ProcessIndex()
    # Restore ascending order so "latest event per pid wins" holds.
    for ts, title, details in reversed(rows):
        index.add_event(ts, title, details)
    return index


def compute_tree(
    index: ProcessIndex,
    pid: int,
    max_depth: int = 12,
    ancestors_only: bool = False,
) -> dict:
    """Pure: ancestors/descendants for `pid` from a prebuilt index."""
    by_pid = index.by_pid
    children_of = index.children_of

    anchor = by_pid.get(pid)
    if not anchor:
        return {
            "anchor": {"pid": pid, "name": "<unknown>"},
            "ancestors": [],
            "descendants": [],
            "total_nodes": 0,
        }

    ancestors: list[dict] = []
    cursor: Optional[int] = anchor.get("ppid")
    depth = 0
    while cursor is not None and depth < max_depth:
        parent = by_pid.get(cursor)
        if not parent:
            break
        ancestors.append(parent)
        cursor = parent.get("ppid")
        depth += 1

    if ancestors_only:
        return {
            "anchor": anchor,
            "ancestors": ancestors,
            "descendants": {},
            "total_nodes": len(by_pid),
        }

    def subtree(root_pid: int, depth: int = 0) -> dict:
        node = dict(by_pid.get(root_pid, {"pid": root_pid}))
        if depth >= max_depth:
            node["children"] = []
            node["truncated"] = True
            return node
        kids = children_of.get(root_pid, [])
        node["children"] = [subtree(k, depth + 1) for k in kids]
        return node

    return {
        "anchor": anchor,
        "ancestors": ancestors,          # root-most last
        "descendants": subtree(pid),     # with .children nested tree
        "total_nodes": len(by_pid),
    }


async def build_process_tree(
    db: AsyncSession,
    agent_id: str,
    pid: int,
    max_depth: int = 12,
    time_window_hours: int = 24,
    max_events: int = 5000,
    ancestors_only: bool = False,
) -> dict:
    """Ancestors (+ descendants unless `ancestors_only`) for (agent_id, pid).

    One bounded column-only query; see `load_process_index`.
    """
    index = await load_process_index(db, agent_id, time_window_hours, max_events)
    return compute_tree(index, pid, max_depth, ancestors_only)


# ---------------------------------------------------------------------------
# Per-agent in-memory cache
#
# Loading the 24 h index is a 5000-row JSON query. Doing it per event (the
# host monitor emits ~30 process_start/min) saturated CPU and grew RSS, so the
# index is loaded once per agent and then kept current by feeding it every
# process event (`feed_event`). It is re-read from the DB only on a TTL, or
# when an ancestry lookup comes up short and the last load is old enough.
# ---------------------------------------------------------------------------

MAX_NODES_PER_AGENT = 20000
MAX_AGENTS = 64
WINDOW_HOURS = 24
MISS_REFRESH_S = float(os.environ.get("AEGIS_PROCESS_INDEX_MISS_S", "60"))
_now = time.monotonic


def _ttl_s() -> float:
    try:
        return float(os.environ.get("AEGIS_PROCESS_INDEX_TTL_S", "900"))
    except ValueError:
        return 900.0


class _Entry:
    __slots__ = ("index", "loaded_at", "loading", "pending", "lock")

    def __init__(self) -> None:
        self.index = ProcessIndex()
        self.loaded_at: Optional[float] = None  # None = never loaded from DB
        self.loading = False
        # Events fed while no DB load covers them (before the first load, or
        # during a reload); replayed on top of the freshly loaded index.
        self.pending: deque = deque(maxlen=MAX_NODES_PER_AGENT)
        self.lock = asyncio.Lock()


_entries: "OrderedDict[str, _Entry]" = OrderedDict()


def _entry(agent_id: str) -> _Entry:
    e = _entries.get(agent_id)
    if e is None:
        e = _entries[agent_id] = _Entry()
        while len(_entries) > MAX_AGENTS:
            _entries.popitem(last=False)
    else:
        _entries.move_to_end(agent_id)
    return e


def reset_cache() -> None:
    _entries.clear()


def feed_event(agent_id: str, timestamp, title, details) -> None:
    """Keep the agent's cached index current with one process event."""
    e = _entry(agent_id)
    if e.loaded_at is None or e.loading:
        e.pending.append((timestamp, title, details))
    if e.loaded_at is not None:
        idx = e.index
        idx.add_event(timestamp, title, details)
        if len(idx.by_pid) > MAX_NODES_PER_AGENT * 1.25:
            idx.prune(datetime.utcnow() - timedelta(hours=WINDOW_HOURS), MAX_NODES_PER_AGENT)


def feed_payload(agent_id: str, payload: dict) -> None:
    """Feed an event-bus process payload (details are top-level keys)."""
    ts = None
    raw = payload.get("timestamp")
    if isinstance(raw, datetime):
        ts = raw
    elif isinstance(raw, str):
        try:
            ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            ts = None
    if ts is None:
        ts = datetime.utcnow()
    elif ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    title = payload.get("title") or (
        f"proc_start: {payload.get('process_name') or '?'} (pid={payload.get('pid')})"
    )
    feed_event(agent_id, ts, title, payload)


async def _load(agent_id: str, db, session_factory) -> ProcessIndex:
    if db is not None:
        return await load_process_index(db, agent_id, WINDOW_HOURS)
    async with session_factory() as s:
        return await load_process_index(s, agent_id, WINDOW_HOURS)


async def _refresh(entry: _Entry, agent_id: str, db, session_factory, max_age: float) -> None:
    """Single-flight reload: concurrent callers queue on the lock and the
    later ones find the index already fresh."""
    async with entry.lock:
        if entry.loaded_at is not None and _now() - entry.loaded_at <= max_age:
            return
        had_index = entry.loaded_at is not None
        if had_index:
            entry.pending.clear()
        entry.loading = True
        try:
            fresh = await _load(agent_id, db, session_factory)
        except Exception:
            entry.loading = False
            if not had_index:
                raise
            logger.warning("process index refresh failed for %s; keeping stale", agent_id, exc_info=True)
            entry.loaded_at = _now()  # back off instead of retrying every event
            return
        for rec in entry.pending:
            fresh.add_event(*rec)
        entry.pending.clear()
        entry.index = fresh
        entry.loaded_at = _now()
        entry.loading = False


async def get_agent_index(agent_id: str, db=None, session_factory=None) -> ProcessIndex:
    """Cached index; loaded on first use and after the TTL."""
    entry = _entry(agent_id)
    ttl = _ttl_s()
    if entry.loaded_at is None or _now() - entry.loaded_at > ttl:
        await _refresh(entry, agent_id, db, session_factory, ttl)
    return entry.index


def _chain_incomplete(index: ProcessIndex, ancestors: list[dict], pid: int) -> bool:
    anchor = index.by_pid.get(pid)
    if anchor is None:
        return True
    last = ancestors[-1] if ancestors else anchor
    ppid = last.get("ppid")
    return ppid is not None and ppid not in index.by_pid and len(ancestors) < 12


async def ancestors_for(
    agent_id: str, pid: int, db=None, session_factory=None,
) -> list[dict]:
    """Ancestors of `pid` from the cached index. A lookup that cannot reach a
    root triggers one (rate-limited, single-flight) reload before answering."""
    index = await get_agent_index(agent_id, db, session_factory)
    ancestors = compute_tree(index, pid, ancestors_only=True)["ancestors"]
    if _chain_incomplete(index, ancestors, pid):
        entry = _entry(agent_id)
        if entry.loaded_at is not None and _now() - entry.loaded_at > MISS_REFRESH_S:
            await _refresh(entry, agent_id, db, session_factory, MISS_REFRESH_S)
            ancestors = compute_tree(entry.index, pid, ancestors_only=True)["ancestors"]
    return ancestors
