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


async def build_process_tree(
    db: AsyncSession,
    agent_id: str,
    pid: int,
    max_depth: int = 12,
    time_window_hours: int = 24,
) -> dict:
    """
    Walk AgentEvents of category=process for the given agent and assemble:
      - ancestors: parent chain up to root
      - descendants: full child subtree
      - anchor: the node matching `pid`
    """
    from datetime import datetime, timedelta

    since = datetime.utcnow() - timedelta(hours=time_window_hours)

    stmt = (
        select(AgentEvent)
        .where(
            and_(
                AgentEvent.agent_id == agent_id,
                AgentEvent.category == EventCategory.process,
                AgentEvent.timestamp >= since,
            )
        )
        .order_by(AgentEvent.timestamp.asc())
    )
    rows = (await db.execute(stmt)).scalars().all()

    # Index by pid, keeping the latest start event per pid
    by_pid: dict[int, dict] = {}
    children_of: dict[int, list[int]] = {}

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

        node = {
            "pid": ev_pid,
            "ppid": ppid,
            "name": details.get("process_name") or details.get("name"),
            "path": details.get("process_path") or details.get("path"),
            "command_line": details.get("command_line") or details.get("cmdline"),
            "user": details.get("user"),
            "started_at": ev.timestamp.isoformat() if ev.timestamp else None,
            "event_kind": details.get("kind") or ev.title,
        }
        by_pid[ev_pid] = node
        if ppid is not None:
            children_of.setdefault(ppid, []).append(ev_pid)

    anchor = by_pid.get(pid)
    if not anchor:
        return {
            "anchor": {"pid": pid, "name": "<unknown>"},
            "ancestors": [],
            "descendants": [],
            "total_nodes": 0,
        }

    # Walk up to collect ancestors
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

    # Walk down to collect descendants (BFS)
    def subtree(root_pid: int, depth: int = 0) -> dict:
        node = dict(by_pid.get(root_pid, {"pid": root_pid}))
        if depth >= max_depth:
            node["children"] = []
            node["truncated"] = True
            return node
        kids = children_of.get(root_pid, [])
        node["children"] = [subtree(k, depth + 1) for k in kids]
        return node

    descendants_root = subtree(pid)

    return {
        "anchor": anchor,
        "ancestors": ancestors,          # root-most last
        "descendants": descendants_root,  # with .children nested tree
        "total_nodes": len(by_pid),
    }
