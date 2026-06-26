"""
Node enrollment API.

Provides a user-friendly enrollment flow where the AEGIS Node app
generates a short code (C6-XXXX-XXXX), the user pastes it in the
dashboard, and the backend validates and creates an agent record.
"""

import logging
import secrets
import string
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.auth import AuthContext, require_analyst, require_viewer
from app.core.events import event_bus
from app.models.endpoint_agent import EndpointAgent, AgentStatus

logger = logging.getLogger("aegis.nodes")
router = APIRouter(prefix="/nodes", tags=["nodes"])

# ---------------------------------------------------------------------------
# In-memory pending enrollment codes
# In production, use Redis with TTL keys.
# ---------------------------------------------------------------------------

# code -> { agent_id, hostname, os_info, ip_address, created_at, agent_version }
_pending_enrollments: dict[str, dict] = {}

ENROLLMENT_TTL_MINUTES = 15


def _generate_code() -> str:
    """Generate a code like C6-AB12-XY34."""
    chars = string.ascii_uppercase + string.digits
    part1 = "".join(secrets.choice(chars) for _ in range(4))
    part2 = "".join(secrets.choice(chars) for _ in range(4))
    return f"C6-{part1}-{part2}"


def _cleanup_expired():
    """Remove expired enrollment codes."""
    now = datetime.utcnow()
    expired = [
        code
        for code, info in _pending_enrollments.items()
        if now - info["created_at"] > timedelta(minutes=ENROLLMENT_TTL_MINUTES)
    ]
    for code in expired:
        del _pending_enrollments[code]


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class HeartbeatRequest(BaseModel):
    node_id: str
    # Accept both naming conventions (node-tauri uses cpu_usage, Python agent uses cpu)
    cpu: float = 0
    mem: float = 0
    disk: float = 0
    cpu_usage: float = 0
    ram_usage: float = 0
    disk_usage: float = 0
    processes: int = 0
    process_count: int = 0
    events_count: int = 0
    hostname: str | None = None
    uptime_seconds: int = 0
    suspicious_processes: list = []
    timestamp: str | None = None


class HeartbeatResponse(BaseModel):
    status: str
    commands: list = []


class EnrollRequest(BaseModel):
    code: str
    node_type: str = "workspace"  # "server" | "workspace"


class EnrollResponse(BaseModel):
    status: str
    node_id: str
    hostname: str
    message: str


class NodeOut(BaseModel):
    id: str
    hostname: str
    os_info: str | None = None
    ip_address: str | None = None
    agent_version: str
    status: str
    last_heartbeat: str | None = None
    node_type: str = "workspace"
    tags: list = []
    asset_count: int = 0
    created_at: str | None = None
    cpu: float = 0
    mem: float = 0
    disk: float = 0
    processes: int = 0


class NodeGenerateResponse(BaseModel):
    code: str
    expires_in_minutes: int = ENROLLMENT_TTL_MINUTES


# ---------------------------------------------------------------------------
# Routes: Node app facing (generate code)
# ---------------------------------------------------------------------------

@router.post("/generate-code", response_model=NodeGenerateResponse)
async def generate_enrollment_code(
    body: dict,
    auth: AuthContext = Depends(require_analyst),
):
    """
    Called by the AEGIS Node app on the target machine.
    Generates a short enrollment code that the user pastes in the dashboard.
    Body: { agent_id, hostname, os_info, ip_address, agent_version }
    """
    _cleanup_expired()

    code = _generate_code()
    while code in _pending_enrollments:
        code = _generate_code()

    _pending_enrollments[code] = {
        "agent_id": body.get("agent_id", ""),
        "hostname": body.get("hostname", "unknown"),
        "os_info": body.get("os_info", ""),
        "ip_address": body.get("ip_address", ""),
        "agent_version": body.get("agent_version", "1.0.0"),
        "node_type": body.get("node_type", "workspace"),
        "created_at": datetime.utcnow(),
    }

    logger.info(f"Enrollment code generated: {code} for host {body.get('hostname')}")
    return NodeGenerateResponse(code=code, expires_in_minutes=ENROLLMENT_TTL_MINUTES)


# ---------------------------------------------------------------------------
# Routes: Node heartbeat (no auth — node identifies itself by node_id)
# ---------------------------------------------------------------------------

@router.post("/heartbeat", response_model=HeartbeatResponse)
async def node_heartbeat(
    body: HeartbeatRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Called periodically by the AEGIS Node agent to report health metrics.
    Updates the agent record with latest metrics and marks it as online.
    No API-key auth required — the node authenticates via its own agent_id.
    """
    logger.debug(f"Heartbeat from {body.node_id}: cpu={body.cpu}/{body.cpu_usage} mem={body.mem}/{body.ram_usage} disk={body.disk}/{body.disk_usage} procs={body.processes}/{body.process_count}")
    result = await db.execute(
        select(EndpointAgent).where(EndpointAgent.id == body.node_id)
    )
    agent = result.scalar_one_or_none()

    if not agent:
        raise HTTPException(status_code=404, detail="Node not registered. Enroll first.")

    # Update status and heartbeat timestamp
    agent.status = AgentStatus.online
    agent.last_heartbeat = datetime.utcnow()

    # Store metrics — accept both naming conventions
    metrics = {
        "cpu": body.cpu_usage if body.cpu_usage > 0 else body.cpu,
        "mem": body.ram_usage if body.ram_usage > 0 else body.mem,
        "disk": body.disk_usage if body.disk_usage > 0 else body.disk,
        "processes": body.process_count if body.process_count > 0 else body.processes,
        "events_count": body.events_count,
        "uptime_seconds": body.uptime_seconds,
        "suspicious_processes": len(body.suspicious_processes),
        "reported_at": datetime.utcnow().isoformat(),
    }
    config = dict(agent.config) if agent.config else {}
    config["last_metrics"] = metrics
    agent.config = config

    # Flag JSON column as modified so SQLAlchemy detects the change
    from sqlalchemy.orm.attributes import flag_modified
    flag_modified(agent, "config")

    await db.commit()

    logger.debug(f"Heartbeat from {body.node_id}: cpu={body.cpu}% mem={body.mem}%")

    # Return commands list (placeholder for future remote command dispatch)
    return HeartbeatResponse(status="ok", commands=[])


# ---------------------------------------------------------------------------
# Routes: Dashboard facing
# ---------------------------------------------------------------------------

@router.post("/enroll", response_model=EnrollResponse)
async def enroll_node(
    body: EnrollRequest,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """
    User pastes an enrollment code from the Node app.
    Validates the code and creates the agent record.
    """
    _cleanup_expired()

    code = body.code.strip().upper()

    # Validate format
    import re
    if not re.match(r"^C6-[A-Z0-9]{4}-[A-Z0-9]{4}$", code):
        raise HTTPException(status_code=400, detail="Invalid code format. Expected C6-XXXX-XXXX.")

    # Accept any valid code — node app will connect via heartbeat later
    info = _pending_enrollments.pop(code, None)

    client = auth.client
    agent_id = f"node-{secrets.token_hex(8)}"
    _hostname = info["hostname"] if info else f"node-{code[-4:]}"
    _os_info = info.get("os_info") if info else None
    _ip_address = info.get("ip_address") if info else None
    _agent_version = info.get("agent_version", "pending") if info else "pending"
    _node_type = body.node_type if body.node_type != "workspace" else (info.get("node_type", "workspace") if info else "workspace")

    # Check if already registered
    result = await db.execute(
        select(EndpointAgent).where(
            EndpointAgent.id == agent_id,
            EndpointAgent.client_id == client.id,
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.hostname = _hostname
        existing.os_info = _os_info
        existing.ip_address = _ip_address
        existing.agent_version = _agent_version
        existing.node_type = _node_type
        existing.status = AgentStatus.online
        existing.last_heartbeat = datetime.utcnow()
        await db.commit()
    else:
        agent = EndpointAgent(
            id=agent_id,
            client_id=client.id,
            hostname=_hostname,
            os_info=_os_info,
            ip_address=_ip_address,
            agent_version=_agent_version,
            node_type=_node_type,
            status=AgentStatus.online,
            last_heartbeat=datetime.utcnow(),
            tags=["enrolled-via-code"],
            config={},
        )
        db.add(agent)
        await db.commit()

    logger.info(f"Node enrolled via code {code}: {agent_id} ({_hostname})")

    try:
        await event_bus.publish("agent_registered", {
            "agent_id": agent_id,
            "hostname": _hostname,
            "client_id": client.id,
        })
    except Exception:
        pass

    return EnrollResponse(
        status="enrolled",
        node_id=agent_id,
        hostname=_hostname,
        message=f"Node '{_hostname}' enrolled successfully. It will appear in your dashboard shortly.",
    )


@router.get("", response_model=list[NodeOut])
async def list_nodes(
    status: Optional[str] = None,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List all enrolled nodes (agents) for the client."""
    from sqlalchemy import update as sql_update

    client = auth.client

    # Mark stale agents
    stale_threshold = datetime.utcnow() - timedelta(minutes=2)
    await db.execute(
        sql_update(EndpointAgent)
        .where(
            EndpointAgent.client_id == client.id,
            EndpointAgent.status == AgentStatus.online,
            EndpointAgent.last_heartbeat < stale_threshold,
        )
        .values(status=AgentStatus.stale)
    )
    await db.commit()

    query = select(EndpointAgent).where(
        EndpointAgent.client_id == client.id,
        EndpointAgent.status != AgentStatus.deregistered,
    )
    if status:
        try:
            query = query.where(EndpointAgent.status == AgentStatus(status))
        except ValueError:
            pass
    query = query.order_by(EndpointAgent.last_heartbeat.desc())

    result = await db.execute(query)
    agents = result.scalars().all()

    nodes = []
    for a in agents:
        metrics = (a.config or {}).get("last_metrics", {})
        nodes.append(NodeOut(
            id=a.id,
            hostname=a.hostname,
            os_info=a.os_info,
            ip_address=a.ip_address,
            agent_version=a.agent_version,
            node_type=getattr(a, "node_type", None) or "workspace",
            status=a.status.value if hasattr(a.status, "value") else a.status,
            last_heartbeat=a.last_heartbeat.isoformat() if a.last_heartbeat else None,
            tags=a.tags or [],
            asset_count=0,
            created_at=a.created_at.isoformat() if a.created_at else None,
            cpu=metrics.get("cpu", 0),
            mem=metrics.get("mem", 0),
            disk=metrics.get("disk", 0),
            processes=metrics.get("processes", 0),
        ))
    return nodes


@router.get("/{node_id}", response_model=NodeOut)
async def get_node(
    node_id: str,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get details for a specific node."""
    client = auth.client

    result = await db.execute(
        select(EndpointAgent).where(
            EndpointAgent.id == node_id,
            EndpointAgent.client_id == client.id,
        )
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Node not found")

    metrics = (agent.config or {}).get("last_metrics", {})
    return NodeOut(
        id=agent.id,
        hostname=agent.hostname,
        os_info=agent.os_info,
        ip_address=agent.ip_address,
        agent_version=agent.agent_version,
        node_type=getattr(agent, "node_type", None) or "workspace",
        status=agent.status.value if hasattr(agent.status, "value") else agent.status,
        last_heartbeat=agent.last_heartbeat.isoformat() if agent.last_heartbeat else None,
        tags=agent.tags or [],
        asset_count=0,
        created_at=agent.created_at.isoformat() if agent.created_at else None,
        cpu=metrics.get("cpu", 0),
        mem=metrics.get("mem", 0),
        disk=metrics.get("disk", 0),
        processes=metrics.get("processes", 0),
    )


@router.delete("/{node_id}", status_code=204)
async def remove_node(
    node_id: str,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Remove (deregister) a node."""
    client = auth.client

    result = await db.execute(
        select(EndpointAgent).where(
            EndpointAgent.id == node_id,
            EndpointAgent.client_id == client.id,
        )
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Node not found")

    # Hard delete — remove completely from DB
    await db.delete(agent)
    await db.commit()
    logger.info(f"Node deleted: {node_id}")


# ---------------------------------------------------------------------------
# Node-facing endpoints (no auth)
# ---------------------------------------------------------------------------

class AnnounceRequest(BaseModel):
    enroll_code: str
    hostname: str
    os_name: str | None = None
    os_version: str | None = None
    local_ip: str | None = None
    agent_version: str = "0.1.0"


@router.post("/announce")
async def announce_node(body: AnnounceRequest):
    _cleanup_expired()
    code = body.enroll_code.strip().upper()
    os_info = f"{body.os_name or ''} {body.os_version or ''}".strip() or None
    if code in _pending_enrollments and _pending_enrollments[code].get("enrolled"):
        info = _pending_enrollments[code]
        return {
            "status": "active",
            "client_id": info.get("client_id"),
            "client_name": info.get("client_name"),
            "node_id": info.get("node_id"),
        }
    _pending_enrollments[code] = {
        "agent_id": "",
        "hostname": body.hostname,
        "os_info": os_info,
        "ip_address": body.local_ip,
        "agent_version": body.agent_version,
        "created_at": datetime.utcnow(),
        "enrolled": False,
        "client_id": None,
        "client_name": None,
        "node_id": None,
    }
    logger.info(f"Node announced: {code} from {body.hostname} ({body.local_ip})")
    return {"status": "pending", "code": code}


@router.get("/status/{code}")
async def check_enrollment_status(code: str):
    _cleanup_expired()
    code = code.strip().upper()
    info = _pending_enrollments.get(code)
    if not info:
        return {"status": "expired", "message": "Code expired or not found"}
    if info.get("enrolled"):
        return {
            "status": "active",
            "client_id": info.get("client_id"),
            "client_name": info.get("client_name"),
            "node_id": info.get("node_id"),
        }
    return {"status": "pending", "message": "Waiting for manager to enter code"}


class NodeEventRequest(BaseModel):
    node_id: str
    event_type: str
    severity: str = "medium"
    details: dict = {}
    timestamp: str | None = None


@router.post("/events")
async def receive_node_event(
    body: NodeEventRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(EndpointAgent).where(EndpointAgent.id == body.node_id)
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Node not found")

    logger.info(f"Node event from {body.node_id}: {body.event_type} [{body.severity}]")

    if body.severity in ("high", "critical"):
        from app.models.incident import Incident

        incident = Incident(
            client_id=agent.client_id,
            title=f"EDR: {body.event_type}",
            description=str(body.details),
            severity=body.severity,
            status="open",
            source=f"node:{body.node_id}",
            source_ip=agent.ip_address,
        )
        db.add(incident)
        await db.commit()

    return {"status": "received", "event_type": body.event_type}


class AssetReportRequest(BaseModel):
    node_id: str
    hostname: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    local_ip: str | None = None
    cpu_brand: str | None = None
    cpu_count: int | None = None
    ram_total_mb: int | None = None
    disk_total_gb: float | None = None
    open_services: list = []
    scan_timestamp: str | None = None


@router.post("/report-assets")
async def report_assets(
    body: AssetReportRequest,
    db: AsyncSession = Depends(get_db),
):
    import uuid as _uuid
    from app.models.asset import Asset

    result = await db.execute(
        select(EndpointAgent).where(EndpointAgent.id == body.node_id)
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Node not found")

    client_id = agent.client_id
    if body.local_ip:
        agent.ip_address = body.local_ip
    if body.os_name:
        agent.os_info = f"{body.os_name} {body.os_version or ''}".strip()

    ip = body.local_ip or "127.0.0.1"
    ports_list = [s.get("port") for s in body.open_services if s.get("port")]
    techs = [
        f"{s.get('service', 'unknown')}:{s.get('port')}"
        for s in body.open_services
        if s.get("service") and s.get("service") != "unknown"
    ]

    existing = await db.execute(
        select(Asset).where(Asset.client_id == client_id, Asset.ip_address == ip)
    )
    existing_asset = existing.scalar_one_or_none()
    assets_created = assets_updated = 0

    if existing_asset:
        existing_asset.hostname = body.hostname or existing_asset.hostname
        existing_asset.ports = ports_list
        existing_asset.technologies = techs
        existing_asset.last_scan_at = datetime.utcnow()
        assets_updated = 1
    else:
        db.add(Asset(
            id=str(_uuid.uuid4()),
            client_id=client_id,
            hostname=body.hostname or "unknown",
            ip_address=ip,
            asset_type="server",
            ports=ports_list,
            technologies=techs,
            status="active",
            risk_score=0.0,
            last_scan_at=datetime.utcnow(),
        ))
        assets_created = 1

    await db.commit()
    logger.info(f"Asset report from {body.node_id}: {len(body.open_services)} services")
    return {
        "status": "ok",
        "services_found": len(body.open_services),
        "assets_created": assets_created,
        "assets_updated": assets_updated,
    }
