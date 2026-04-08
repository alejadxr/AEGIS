"""
Ransomware incident API.

Accepts forensic chains posted by the Rust node agent's ransomware module
when it detects and blocks a ransomware process. Creates:
  1. A RansomwareEvent row (full forensic chain)
  2. A CRITICAL Incident (so the dashboard surfaces it immediately)
  3. An AgentEvent (forensic category) for timeline continuity
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.auth import AuthContext, require_analyst, get_auth_context
from app.core.events import event_bus
from app.models.ransomware_event import RansomwareEvent
from app.models.endpoint_agent import (
    EndpointAgent, AgentEvent, EventSeverity, EventCategory,
)
from app.models.incident import Incident

logger = logging.getLogger("aegis.ransomware")
router = APIRouter(prefix="/ransomware", tags=["ransomware"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class SignalReport(BaseModel):
    kind: str
    detail: str
    at: str


class RansomwareIncidentIn(BaseModel):
    agent_id: str
    node_id: Optional[str] = None
    detected_at: str
    process_pid: Optional[int] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    signals: list[SignalReport] = Field(default_factory=list)
    affected_files: list[str] = Field(default_factory=list)
    killed_pids: list[int] = Field(default_factory=list)
    rollback_status: str = "unknown"
    rollback_files_restored: int = 0
    severity: str = "critical"


class RansomwareIncidentOut(BaseModel):
    id: str
    incident_id: Optional[str]
    rollback_status: str
    rollback_files_restored: int
    signal_count: int
    affected_file_count: int


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/events", response_model=RansomwareIncidentOut)
async def report_ransomware_incident(
    payload: RansomwareIncidentIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    """
    Agent-facing endpoint: accept a ransomware incident forensic chain.

    Authenticated via the client's X-API-Key. We then resolve the agent by
    agent_id and scope everything to the client.
    """
    # Resolve agent -> client
    agent = await db.get(EndpointAgent, payload.agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    if auth.client_id and agent.client_id != auth.client_id:
        raise HTTPException(status_code=403, detail="agent does not belong to this client")

    try:
        detected = datetime.fromisoformat(payload.detected_at.replace("Z", "+00:00"))
    except ValueError:
        detected = datetime.utcnow()

    # 1. Create the forensic record
    event = RansomwareEvent(
        client_id=agent.client_id,
        agent_id=agent.id,
        process_pid=payload.process_pid,
        process_name=payload.process_name,
        process_path=payload.process_path,
        signals=[s.model_dump() for s in payload.signals],
        affected_files=payload.affected_files,
        killed_pids=payload.killed_pids,
        rollback_status=payload.rollback_status,
        rollback_files_restored=payload.rollback_files_restored,
        severity=payload.severity,
        detected_at=detected,
    )
    db.add(event)
    await db.flush()

    # 2. Create a CRITICAL incident the dashboard will surface immediately
    signal_kinds = ", ".join(sorted({s.kind for s in payload.signals}))
    title = (
        f"Ransomware activity blocked on {agent.hostname}"
        f" ({len(payload.signals)} signals: {signal_kinds})"
    )
    description = (
        f"AEGIS node agent detected ransomware encryption activity. "
        f"Process: {payload.process_name or 'unknown'} "
        f"(pid={payload.process_pid}, path={payload.process_path or 'n/a'}). "
        f"Killed {len(payload.killed_pids)} PIDs. "
        f"{payload.rollback_files_restored} files restored via {payload.rollback_status}."
    )

    incident = Incident(
        client_id=agent.client_id,
        title=title,
        description=description,
        severity="critical",
        status="contained" if payload.rollback_files_restored > 0 else "open",
        source="node-agent-ransomware",
        mitre_technique="T1486",   # Data Encrypted for Impact
        mitre_tactic="impact",
        source_ip=agent.ip_address,
        ai_analysis={
            "auto_contained": True,
            "response_chain": [
                f"killed {len(payload.killed_pids)} PIDs",
                f"rollback={payload.rollback_status}",
                f"restored={payload.rollback_files_restored} files",
            ],
        },
        raw_alert={
            "signals": [s.model_dump() for s in payload.signals],
            "affected_files": payload.affected_files[:200],
            "process": {
                "pid": payload.process_pid,
                "name": payload.process_name,
                "path": payload.process_path,
            },
        },
        detected_at=detected,
    )
    if payload.rollback_files_restored > 0:
        incident.contained_at = datetime.utcnow()

    db.add(incident)
    await db.flush()

    # Link the forensic record to its incident
    event.incident_id = incident.id

    # 3. Mirror into AgentEvent for timeline continuity
    agent_ev = AgentEvent(
        agent_id=agent.id,
        client_id=agent.client_id,
        category=EventCategory.forensic,
        severity=EventSeverity.critical,
        title=title,
        details={
            "ransomware_event_id": event.id,
            "incident_id": incident.id,
            "signals": [s.model_dump() for s in payload.signals],
            "process": {
                "pid": payload.process_pid,
                "name": payload.process_name,
                "path": payload.process_path,
            },
            "rollback_status": payload.rollback_status,
            "rollback_files_restored": payload.rollback_files_restored,
            "killed_pids": payload.killed_pids,
            "affected_file_count": len(payload.affected_files),
        },
        timestamp=detected,
    )
    db.add(agent_ev)

    await db.commit()

    # Fire real-time event so the dashboard updates
    try:
        await event_bus.publish("ransomware.incident", {
            "client_id": agent.client_id,
            "incident_id": incident.id,
            "ransomware_event_id": event.id,
            "hostname": agent.hostname,
            "process_name": payload.process_name,
            "signal_count": len(payload.signals),
            "rollback_status": payload.rollback_status,
            "rollback_files_restored": payload.rollback_files_restored,
            "severity": "critical",
        })
    except Exception as e:
        logger.warning("ransomware event publish failed: %s", e)

    logger.critical(
        "ransomware incident on %s: %s signals, killed=%s, restored=%s",
        agent.hostname,
        len(payload.signals),
        len(payload.killed_pids),
        payload.rollback_files_restored,
    )

    return RansomwareIncidentOut(
        id=event.id,
        incident_id=incident.id,
        rollback_status=payload.rollback_status,
        rollback_files_restored=payload.rollback_files_restored,
        signal_count=len(payload.signals),
        affected_file_count=len(payload.affected_files),
    )


@router.get("", response_model=list[dict])
async def list_ransomware_events(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_analyst),
):
    """List recent ransomware incidents for the authenticated client."""
    stmt = (
        select(RansomwareEvent)
        .where(RansomwareEvent.client_id == auth.client_id)
        .order_by(RansomwareEvent.detected_at.desc())
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "agent_id": r.agent_id,
            "incident_id": r.incident_id,
            "process_pid": r.process_pid,
            "process_name": r.process_name,
            "process_path": r.process_path,
            "signals": r.signals,
            "affected_files": r.affected_files,
            "killed_pids": r.killed_pids,
            "rollback_status": r.rollback_status,
            "rollback_files_restored": r.rollback_files_restored,
            "severity": r.severity,
            "detected_at": r.detected_at.isoformat() if r.detected_at else None,
        }
        for r in rows
    ]
