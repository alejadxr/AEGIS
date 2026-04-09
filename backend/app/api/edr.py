"""
EDR/XDR API (Task #5).

Endpoints:
  POST /edr/events          — agent batch ingestion (gzip-aware)
  GET  /edr/process-tree    — reconstruct ancestors + descendants
  GET  /edr/chains          — list recently matched attack-chain incidents
  GET  /edr/events/recent   — tail of recent EDR events for an agent
"""

from __future__ import annotations

import gzip
import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.auth import AuthContext, require_analyst, get_auth_context
from app.core.events import event_bus
from app.models.endpoint_agent import (
    AgentEvent, EndpointAgent, EventCategory, EventSeverity,
)
from app.models.incident import Incident
from app.services.process_tree import build_process_tree
from app.services.attack_chain_detector import evaluate_event
from app.services.host_monitor import host_monitor, AGENT_ID as HOST_MONITOR_AGENT_ID

logger = logging.getLogger("aegis.edr")
router = APIRouter(prefix="/edr", tags=["edr"])

# How many events per batch we accept in one POST
MAX_BATCH = 5000


class EdrEventIn(BaseModel):
    kind: str
    at: str
    pid: Optional[int] = None
    ppid: Optional[int] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    command_line: Optional[str] = None
    user: Optional[str] = None
    target: Optional[str] = None
    extra: Optional[dict] = None


class EdrEventsIn(BaseModel):
    agent_id: str
    events_dropped_total: int = 0
    events: list[EdrEventIn]


class EdrEventsOut(BaseModel):
    accepted: int
    dropped: int = 0
    chain_matches: int = 0


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

@router.post("/events", response_model=EdrEventsOut)
async def ingest_events(
    request: Request,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    # Accept gzipped bodies from the Rust uploader
    raw = await request.body()
    if request.headers.get("content-encoding", "").lower() == "gzip":
        try:
            raw = gzip.decompress(raw)
        except OSError as e:
            raise HTTPException(status_code=400, detail=f"gzip decode failed: {e}")

    try:
        payload_dict = json.loads(raw)
        payload = EdrEventsIn(**payload_dict)
    except (json.JSONDecodeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"invalid payload: {e}")

    agent = await db.get(EndpointAgent, payload.agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    if auth.client_id and agent.client_id != auth.client_id:
        raise HTTPException(status_code=403, detail="agent does not belong to this client")

    if len(payload.events) > MAX_BATCH:
        raise HTTPException(
            status_code=413,
            detail=f"batch too large ({len(payload.events)} > {MAX_BATCH})",
        )

    accepted = 0
    chain_match_count = 0

    async def ancestry_fetcher(pid: int) -> list[dict]:
        tree = await build_process_tree(db, agent.id, pid)
        return tree.get("ancestors", [])

    for ev in payload.events:
        # Map kind -> category/severity
        category = _event_category(ev.kind)
        severity = _event_severity(ev.kind)

        try:
            ts = datetime.fromisoformat(ev.at.replace("Z", "+00:00"))
        except ValueError:
            ts = datetime.utcnow()

        details = {
            "kind": ev.kind,
            "pid": ev.pid,
            "ppid": ev.ppid,
            "process_name": ev.process_name,
            "process_path": ev.process_path,
            "command_line": ev.command_line,
            "user": ev.user,
            "target": ev.target,
            "extra": ev.extra or {},
        }

        row = AgentEvent(
            agent_id=agent.id,
            client_id=agent.client_id,
            category=category,
            severity=severity,
            title=_event_title(ev),
            details=details,
            timestamp=ts,
        )
        db.add(row)
        accepted += 1

        # Only run chain detection on process starts — the ancestry lookup is
        # expensive and the other event kinds don't drive chain rules.
        if ev.kind == "process_start":
            matches = await evaluate_event(
                db, agent, ev.model_dump(), ancestry_fetcher,
            )
            chain_match_count += len(matches)

    await db.commit()

    # Fan out a live-dashboard event so widgets refresh
    try:
        await event_bus.publish("edr.batch", {
            "client_id": agent.client_id,
            "agent_id": agent.id,
            "hostname": agent.hostname,
            "accepted": accepted,
            "dropped": payload.events_dropped_total,
            "chain_matches": chain_match_count,
        })
    except Exception as e:  # pragma: no cover
        logger.debug("edr.batch publish failed: %s", e)

    return EdrEventsOut(
        accepted=accepted,
        dropped=payload.events_dropped_total,
        chain_matches=chain_match_count,
    )


def _event_category(kind: str) -> EventCategory:
    mapping = {
        "process_start": EventCategory.process,
        "process_stop": EventCategory.process,
        "image_load": EventCategory.process,
        "tcp_connect": EventCategory.network,
        "tcp_accept": EventCategory.network,
        "dns_query": EventCategory.network,
        "file_create": EventCategory.fim,
        "file_write": EventCategory.fim,
        "file_delete": EventCategory.fim,
        "registry_set": EventCategory.breadcrumb,
        "registry_delete": EventCategory.breadcrumb,
        "amsi_scan": EventCategory.forensic,
    }
    return mapping.get(kind, EventCategory.breadcrumb)


def _event_severity(kind: str) -> EventSeverity:
    if kind in ("amsi_scan",):
        return EventSeverity.high
    if kind in ("file_delete", "registry_delete"):
        return EventSeverity.medium
    return EventSeverity.info


def _event_title(ev: EdrEventIn) -> str:
    name = ev.process_name or "?"
    if ev.kind == "process_start":
        return f"proc_start: {name} (pid={ev.pid})"
    if ev.kind == "process_stop":
        return f"proc_stop: pid={ev.pid}"
    if ev.kind in ("tcp_connect", "tcp_accept"):
        return f"{ev.kind}: {name or ''} -> {ev.target or '?'}"
    if ev.kind.startswith("file_"):
        return f"{ev.kind}: {ev.target or '?'}"
    if ev.kind.startswith("registry_"):
        return f"{ev.kind}: {ev.target or '?'}"
    return f"{ev.kind}: {name}"


# ---------------------------------------------------------------------------
# Query endpoints
# ---------------------------------------------------------------------------

@router.get("/process-tree")
async def get_process_tree(
    agent_id: str = Query(...),
    pid: int = Query(...),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_analyst),
):
    agent = await db.get(EndpointAgent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    if agent.client_id != auth.client_id:
        raise HTTPException(status_code=403, detail="forbidden")

    return await build_process_tree(db, agent_id, pid)


@router.get("/chains")
async def list_chain_matches(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_analyst),
):
    """Recent chain-rule incidents for this client."""
    stmt = (
        select(Incident)
        .where(
            and_(
                Incident.client_id == auth.client_id,
                Incident.source.like("edr-chain:%"),
            )
        )
        .order_by(Incident.detected_at.desc())
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "title": r.title,
            "description": r.description,
            "severity": r.severity,
            "status": r.status,
            "source": r.source,
            "mitre_technique": r.mitre_technique,
            "mitre_tactic": r.mitre_tactic,
            "ai_analysis": r.ai_analysis,
            "detected_at": r.detected_at.isoformat() if r.detected_at else None,
        }
        for r in rows
    ]


@router.get("/host-monitor/status")
async def host_monitor_status(
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_analyst),
):
    """Check if the built-in host monitor is running and return its agent info."""
    agent = await db.get(EndpointAgent, HOST_MONITOR_AGENT_ID)
    return {
        "running": host_monitor._running,
        "agent_id": HOST_MONITOR_AGENT_ID,
        "registered": agent is not None,
        "hostname": agent.hostname if agent else None,
        "status": agent.status.value if agent else None,
        "last_heartbeat": agent.last_heartbeat.isoformat() if agent and agent.last_heartbeat else None,
        "known_pids": len(host_monitor._known_pids),
    }


@router.get("/events/recent")
async def recent_events(
    agent_id: str = Query(...),
    minutes: int = 15,
    limit: int = 200,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_analyst),
):
    agent = await db.get(EndpointAgent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    if agent.client_id != auth.client_id:
        raise HTTPException(status_code=403, detail="forbidden")

    since = datetime.utcnow() - timedelta(minutes=minutes)
    stmt = (
        select(AgentEvent)
        .where(
            and_(
                AgentEvent.agent_id == agent_id,
                AgentEvent.timestamp >= since,
            )
        )
        .order_by(AgentEvent.timestamp.desc())
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "category": r.category.value if r.category else None,
            "severity": r.severity.value if r.severity else None,
            "title": r.title,
            "details": r.details,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        }
        for r in rows
    ]
