"""
API endpoints for EDR-lite endpoint agent communication.

Agents authenticate via X-API-Key (the client's API key) and include
their agent_id in the request body/path. The API key determines which
client the agent belongs to.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.database import get_db
from app.core.auth import AuthContext, require_analyst, require_viewer, get_auth_context
from app.core.events import event_bus

limiter = Limiter(key_func=get_remote_address)
from app.models.endpoint_agent import (
    EndpointAgent, AgentEvent, ForensicSnapshot,
    AgentStatus, EventSeverity, EventCategory,
)

logger = logging.getLogger("aegis.agents")
router = APIRouter(prefix="/agents", tags=["agents"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class AgentRegisterRequest(BaseModel):
    agent_id: str
    hostname: str
    os_info: str = ""
    ip_address: str = ""
    agent_version: str = "1.0.0"
    tags: list[str] = []


class AgentRegisterResponse(BaseModel):
    agent_id: str
    status: str
    message: str
    config: dict = {}


class HeartbeatRequest(BaseModel):
    agent_id: str
    uptime_seconds: int = 0
    process_count: int = 0
    connection_count: int = 0


class HeartbeatResponse(BaseModel):
    ack: bool = True
    commands: list[dict] = []


class EventItem(BaseModel):
    category: str       # process, network, fim, breadcrumb
    severity: str = "info"
    title: str
    details: dict = {}
    timestamp: str = ""  # ISO format; server fills if empty


class EventBatchRequest(BaseModel):
    agent_id: str
    events: list[EventItem]


class EventBatchResponse(BaseModel):
    accepted: int
    rejected: int = 0


class ForensicUploadRequest(BaseModel):
    agent_id: str
    trigger: str = "manual"
    data: dict = {}


class AgentOut(BaseModel):
    id: str
    hostname: str
    os_info: str | None = None
    ip_address: str | None = None
    agent_version: str
    status: str
    last_heartbeat: str | None = None
    tags: list = []
    created_at: str | None = None


class EventOut(BaseModel):
    id: str
    agent_id: str
    category: str
    severity: str
    title: str
    details: dict = {}
    timestamp: str | None = None


class ForensicOut(BaseModel):
    id: str
    agent_id: str
    trigger: str
    data: dict = {}
    captured_at: str | None = None


class AgentCommandRequest(BaseModel):
    command: str   # "capture_forensic", "update_config", "restart"
    params: dict = {}


# ---------------------------------------------------------------------------
# Helper: resolve pending commands for an agent
# ---------------------------------------------------------------------------

# In-memory command queue (per agent_id). For production, use Redis.
_pending_commands: dict[str, list[dict]] = {}


def _enqueue_command(agent_id: str, command: dict):
    _pending_commands.setdefault(agent_id, []).append(command)


def _drain_commands(agent_id: str) -> list[dict]:
    return _pending_commands.pop(agent_id, [])


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/register", response_model=AgentRegisterResponse)
@limiter.limit("20/minute")
async def register_agent(
    request: Request,
    body: AgentRegisterRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """
    An endpoint agent registers itself on first startup.
    If the agent_id already exists for this client, update its info.
    """
    client = auth.client

    result = await db.execute(
        select(EndpointAgent).where(
            EndpointAgent.id == body.agent_id,
            EndpointAgent.client_id == client.id,
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.hostname = body.hostname
        existing.os_info = body.os_info
        existing.ip_address = body.ip_address
        existing.agent_version = body.agent_version
        existing.status = AgentStatus.online
        existing.last_heartbeat = datetime.utcnow()
        existing.tags = body.tags
        await db.commit()
        logger.info(f"Agent re-registered: {body.agent_id} ({body.hostname})")
        return AgentRegisterResponse(
            agent_id=body.agent_id,
            status="re-registered",
            message=f"Agent {body.hostname} re-registered successfully",
            config=existing.config or {},
        )

    agent = EndpointAgent(
        id=body.agent_id,
        client_id=client.id,
        hostname=body.hostname,
        os_info=body.os_info,
        ip_address=body.ip_address,
        agent_version=body.agent_version,
        status=AgentStatus.online,
        last_heartbeat=datetime.utcnow(),
        tags=body.tags,
        config={},
    )
    db.add(agent)
    await db.commit()

    logger.info(f"Agent registered: {body.agent_id} ({body.hostname})")

    # Emit event for dashboard
    try:
        await event_bus.publish("agent_registered", {
            "agent_id": body.agent_id,
            "hostname": body.hostname,
            "client_id": client.id,
        })
    except Exception:
        pass

    return AgentRegisterResponse(
        agent_id=body.agent_id,
        status="registered",
        message=f"Agent {body.hostname} registered successfully",
        config={},
    )


@router.post("/heartbeat", response_model=HeartbeatResponse)
async def agent_heartbeat(
    body: HeartbeatRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Agent sends a heartbeat every 30s. Server responds with any pending
    commands (e.g., capture_forensic, update_config).
    """
    client = auth.client

    result = await db.execute(
        select(EndpointAgent).where(
            EndpointAgent.id == body.agent_id,
            EndpointAgent.client_id == client.id,
        )
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not registered")

    agent.status = AgentStatus.online
    agent.last_heartbeat = datetime.utcnow()
    await db.commit()

    commands = _drain_commands(body.agent_id)
    return HeartbeatResponse(ack=True, commands=commands)


@router.post("/events", response_model=EventBatchResponse)
async def ingest_events(
    body: EventBatchRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Agent sends a batch of events (process, network, FIM, breadcrumb).
    Server stores them and emits WebSocket events for critical/high severity.
    """
    client = auth.client

    # Verify agent exists
    result = await db.execute(
        select(EndpointAgent.id).where(
            EndpointAgent.id == body.agent_id,
            EndpointAgent.client_id == client.id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Agent not registered")

    accepted = 0
    for ev in body.events:
        try:
            cat = EventCategory(ev.category)
        except ValueError:
            cat = EventCategory.process

        try:
            sev = EventSeverity(ev.severity)
        except ValueError:
            sev = EventSeverity.info

        ts = datetime.utcnow()
        if ev.timestamp:
            try:
                ts = datetime.fromisoformat(ev.timestamp)
            except ValueError:
                pass

        event = AgentEvent(
            agent_id=body.agent_id,
            client_id=client.id,
            category=cat,
            severity=sev,
            title=ev.title,
            details=ev.details,
            timestamp=ts,
        )
        db.add(event)
        accepted += 1

        # Broadcast critical/high to WebSocket
        if sev in (EventSeverity.critical, EventSeverity.high):
            try:
                await event_bus.publish("agent_alert", {
                    "agent_id": body.agent_id,
                    "category": cat.value,
                    "severity": sev.value,
                    "title": ev.title,
                    "details": ev.details,
                    "client_id": client.id,
                })
            except Exception:
                pass

    await db.commit()

    logger.info(
        f"Ingested {accepted} events from agent {body.agent_id}"
    )
    return EventBatchResponse(accepted=accepted)


@router.post("/forensic", status_code=201)
async def upload_forensic(
    body: ForensicUploadRequest,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    """Agent uploads a forensic snapshot."""
    client = auth.client

    result = await db.execute(
        select(EndpointAgent.id).where(
            EndpointAgent.id == body.agent_id,
            EndpointAgent.client_id == client.id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Agent not registered")

    snapshot = ForensicSnapshot(
        agent_id=body.agent_id,
        client_id=client.id,
        trigger=body.trigger,
        data=body.data,
        captured_at=datetime.utcnow(),
    )
    db.add(snapshot)
    await db.commit()
    await db.refresh(snapshot)

    logger.info(f"Forensic snapshot received from agent {body.agent_id}")

    try:
        await event_bus.publish("forensic_captured", {
            "agent_id": body.agent_id,
            "snapshot_id": snapshot.id,
            "trigger": body.trigger,
            "client_id": client.id,
        })
    except Exception:
        pass

    return {"id": snapshot.id, "status": "stored"}


# ---------------------------------------------------------------------------
# Management endpoints (dashboard)
# ---------------------------------------------------------------------------

@router.get("", response_model=list[AgentOut])
async def list_agents(
    status: Optional[str] = None,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List all registered agents for the client."""
    client = auth.client

    # Mark agents with no heartbeat in 2 minutes as stale
    stale_threshold = datetime.utcnow() - timedelta(minutes=2)
    await db.execute(
        update(EndpointAgent)
        .where(
            EndpointAgent.client_id == client.id,
            EndpointAgent.status == AgentStatus.online,
            EndpointAgent.last_heartbeat < stale_threshold,
        )
        .values(status=AgentStatus.stale)
    )
    await db.commit()

    query = select(EndpointAgent).where(EndpointAgent.client_id == client.id)
    if status:
        try:
            query = query.where(EndpointAgent.status == AgentStatus(status))
        except ValueError:
            pass
    query = query.order_by(EndpointAgent.last_heartbeat.desc())

    result = await db.execute(query)
    agents = result.scalars().all()

    return [
        AgentOut(
            id=a.id,
            hostname=a.hostname,
            os_info=a.os_info,
            ip_address=a.ip_address,
            agent_version=a.agent_version,
            status=a.status.value if hasattr(a.status, "value") else a.status,
            last_heartbeat=a.last_heartbeat.isoformat() if a.last_heartbeat else None,
            tags=a.tags or [],
            created_at=a.created_at.isoformat() if a.created_at else None,
        )
        for a in agents
    ]


@router.get("/{agent_id}/events", response_model=list[EventOut])
async def get_agent_events(
    agent_id: str,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get events from a specific agent with filtering."""
    client = auth.client

    query = select(AgentEvent).where(
        AgentEvent.agent_id == agent_id,
        AgentEvent.client_id == client.id,
    )
    if category:
        try:
            query = query.where(AgentEvent.category == EventCategory(category))
        except ValueError:
            pass
    if severity:
        try:
            query = query.where(AgentEvent.severity == EventSeverity(severity))
        except ValueError:
            pass

    query = query.order_by(AgentEvent.timestamp.desc()).offset(offset).limit(limit)

    result = await db.execute(query)
    events = result.scalars().all()

    return [
        EventOut(
            id=e.id,
            agent_id=e.agent_id,
            category=e.category.value if hasattr(e.category, "value") else e.category,
            severity=e.severity.value if hasattr(e.severity, "value") else e.severity,
            title=e.title,
            details=e.details or {},
            timestamp=e.timestamp.isoformat() if e.timestamp else None,
        )
        for e in events
    ]


@router.get("/{agent_id}/forensic", response_model=list[ForensicOut])
async def get_agent_forensics(
    agent_id: str,
    limit: int = Query(20, le=100),
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get forensic snapshots from a specific agent."""
    client = auth.client

    result = await db.execute(
        select(ForensicSnapshot)
        .where(
            ForensicSnapshot.agent_id == agent_id,
            ForensicSnapshot.client_id == client.id,
        )
        .order_by(ForensicSnapshot.captured_at.desc())
        .limit(limit)
    )
    snapshots = result.scalars().all()

    return [
        ForensicOut(
            id=s.id,
            agent_id=s.agent_id,
            trigger=s.trigger,
            data=s.data or {},
            captured_at=s.captured_at.isoformat() if s.captured_at else None,
        )
        for s in snapshots
    ]


@router.post("/{agent_id}/command", status_code=202)
async def send_command(
    agent_id: str,
    body: AgentCommandRequest,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """
    Queue a command for the agent. The agent picks it up on next heartbeat.
    Supported commands: capture_forensic, update_config, restart.
    """
    client = auth.client

    result = await db.execute(
        select(EndpointAgent).where(
            EndpointAgent.id == agent_id,
            EndpointAgent.client_id == client.id,
        )
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    allowed_commands = {"capture_forensic", "update_config", "restart"}
    if body.command not in allowed_commands:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown command. Allowed: {allowed_commands}",
        )

    _enqueue_command(agent_id, {
        "command": body.command,
        "params": body.params,
        "issued_at": datetime.utcnow().isoformat(),
    })

    logger.info(f"Command '{body.command}' queued for agent {agent_id}")
    return {"status": "queued", "command": body.command, "agent_id": agent_id}


@router.delete("/{agent_id}", status_code=204)
async def deregister_agent(
    agent_id: str,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Deregister (soft-delete) an agent."""
    client = auth.client

    result = await db.execute(
        select(EndpointAgent).where(
            EndpointAgent.id == agent_id,
            EndpointAgent.client_id == client.id,
        )
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent.status = AgentStatus.deregistered
    await db.commit()
    logger.info(f"Agent deregistered: {agent_id}")
