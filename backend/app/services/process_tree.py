"""
Reconstruct process trees from agent_events (Task #5).

Given an anchor (agent_id, pid), return the full ancestor chain up to root
and the full descendant subtree. Events are correlated by pid/ppid within
the agent's scope.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.endpoint_agent import AgentEvent, EventCategory


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
