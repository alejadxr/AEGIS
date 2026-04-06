from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.auth import AuthContext, require_analyst, require_viewer
from app.core.audit import log_audit
from app.models.client import Client
from app.models.honeypot import Honeypot, HoneypotInteraction
from app.models.attacker_profile import AttackerProfile
from app.modules.phantom.orchestrator import honeypot_orchestrator
from app.modules.phantom.rotation import rotation_engine
from app.modules.phantom.profiler import attacker_profiler

router = APIRouter(prefix="/phantom", tags=["phantom"])

# Allowed config keys per honeypot type (whitelist)
ALLOWED_CONFIG_KEYS = {
    "ssh": {"banner", "port", "credentials_log", "max_sessions", "session_timeout"},
    "http": {"server_header", "port", "fake_paths", "capture_headers", "capture_body"},
    "smb": {"port", "share_name", "fake_files"},
    "api": {"port", "endpoints", "fake_auth", "rate_limit"},
    "database": {"port", "fake_engine", "fake_databases"},
    "smtp": {"port", "banner", "relay_test"},
}
# Common keys accepted for all types
_COMMON_KEYS = {"port"}


def _sanitize_honeypot_config(honeypot_type: str, config: dict) -> dict:
    """Filter config dict to only allowed keys for the honeypot type."""
    allowed = ALLOWED_CONFIG_KEYS.get(honeypot_type, _COMMON_KEYS)
    return {k: v for k, v in config.items() if k in allowed}


# --- Schemas ---

class HoneypotCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    honeypot_type: str  # ssh, http, smb, api, database, smtp
    config: dict = {}


class HoneypotUpdate(BaseModel):
    name: str | None = None
    config: dict | None = None
    status: str | None = None


class HoneypotOut(BaseModel):
    id: str
    name: str
    honeypot_type: str
    config: dict
    status: str
    ip_address: str | None = None
    port: int | None = None
    last_rotation: str | None = None
    interactions_count: int
    created_at: str | None = None


class InteractionOut(BaseModel):
    id: str
    honeypot_id: str
    source_ip: str
    source_port: int | None = None
    protocol: str | None = None
    commands: list = []
    credentials_tried: list = []
    session_duration: int | None = None
    attacker_profile_id: str | None = None
    timestamp: str | None = None


class AttackerOut(BaseModel):
    id: str
    source_ip: str | None = None
    known_ips: list = []
    tools_used: list = []
    techniques: list = []
    sophistication: str | None = None
    total_interactions: int
    first_seen: str | None = None
    last_seen: str | None = None
    ai_assessment: str | None = None


# --- Routes ---

@router.get("/honeypots", response_model=list[HoneypotOut])
async def list_honeypots(
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List all honeypots."""
    client = auth.client
    result = await db.execute(
        select(Honeypot).where(Honeypot.client_id == client.id)
    )
    honeypots = result.scalars().all()
    return [
        HoneypotOut(
            id=h.id,
            name=h.name,
            honeypot_type=h.honeypot_type,
            config=h.config or {},
            status=h.status,
            ip_address=h.ip_address,
            port=h.port,
            last_rotation=h.last_rotation.isoformat() if h.last_rotation else None,
            interactions_count=h.interactions_count,
            created_at=h.created_at.isoformat() if h.created_at else None,
        )
        for h in honeypots
    ]


@router.post("/honeypots", response_model=HoneypotOut, status_code=201)
async def deploy_honeypot(
    body: HoneypotCreate,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Deploy a new honeypot. Analyst or admin only."""
    client = auth.client
    supported = honeypot_orchestrator.get_supported_types()
    if body.honeypot_type not in supported:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported type. Supported: {supported}",
        )

    sanitized_config = _sanitize_honeypot_config(body.honeypot_type, body.config)

    honeypot = await honeypot_orchestrator.deploy(
        honeypot_type=body.honeypot_type,
        name=body.name,
        client_id=client.id,
        db=db,
        custom_config=sanitized_config,
    )

    await log_audit(
        db, "honeypot_deploy",
        f"Deployed {body.honeypot_type} honeypot '{body.name}' (id={honeypot.id})",
        client_id=client.id,
        user_id=auth.user_id,
    )
    await db.commit()

    return HoneypotOut(
        id=honeypot.id,
        name=honeypot.name,
        honeypot_type=honeypot.honeypot_type,
        config=honeypot.config or {},
        status=honeypot.status,
        ip_address=honeypot.ip_address,
        port=honeypot.port,
        last_rotation=None,
        interactions_count=0,
        created_at=honeypot.created_at.isoformat() if honeypot.created_at else None,
    )


@router.patch("/honeypots/{honeypot_id}", response_model=HoneypotOut)
async def update_honeypot(
    honeypot_id: str,
    body: HoneypotUpdate,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Update honeypot configuration. Analyst or admin only."""
    client = auth.client
    result = await db.execute(
        select(Honeypot).where(
            Honeypot.id == honeypot_id,
            Honeypot.client_id == client.id,
        )
    )
    honeypot = result.scalar_one_or_none()
    if not honeypot:
        raise HTTPException(status_code=404, detail="Honeypot not found")

    if body.name is not None:
        honeypot.name = body.name
    if body.config is not None:
        sanitized = _sanitize_honeypot_config(honeypot.honeypot_type, body.config)
        await honeypot_orchestrator.update_config(honeypot, sanitized, db)
    if body.status is not None:
        if body.status == "running":
            await honeypot_orchestrator.start(honeypot, db)
        elif body.status == "stopped":
            await honeypot_orchestrator.stop(honeypot, db)

    await db.commit()
    await db.refresh(honeypot)

    return HoneypotOut(
        id=honeypot.id,
        name=honeypot.name,
        honeypot_type=honeypot.honeypot_type,
        config=honeypot.config or {},
        status=honeypot.status,
        ip_address=honeypot.ip_address,
        port=honeypot.port,
        last_rotation=honeypot.last_rotation.isoformat() if honeypot.last_rotation else None,
        interactions_count=honeypot.interactions_count,
        created_at=honeypot.created_at.isoformat() if honeypot.created_at else None,
    )


@router.delete("/honeypots/{honeypot_id}", status_code=204)
async def delete_honeypot(
    honeypot_id: str,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Remove a honeypot. Analyst or admin only."""
    client = auth.client
    result = await db.execute(
        select(Honeypot).where(
            Honeypot.id == honeypot_id,
            Honeypot.client_id == client.id,
        )
    )
    honeypot = result.scalar_one_or_none()
    if not honeypot:
        raise HTTPException(status_code=404, detail="Honeypot not found")

    await honeypot_orchestrator.remove(honeypot, db)


@router.post("/honeypots/{honeypot_id}/rotate", response_model=HoneypotOut)
async def rotate_honeypot(
    honeypot_id: str,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Force rotation of a honeypot's configuration. Analyst or admin only."""
    client = auth.client
    result = await db.execute(
        select(Honeypot).where(
            Honeypot.id == honeypot_id,
            Honeypot.client_id == client.id,
        )
    )
    honeypot = result.scalar_one_or_none()
    if not honeypot:
        raise HTTPException(status_code=404, detail="Honeypot not found")

    honeypot = await rotation_engine.rotate(honeypot, db)

    return HoneypotOut(
        id=honeypot.id,
        name=honeypot.name,
        honeypot_type=honeypot.honeypot_type,
        config=honeypot.config or {},
        status=honeypot.status,
        ip_address=honeypot.ip_address,
        port=honeypot.port,
        last_rotation=honeypot.last_rotation.isoformat() if honeypot.last_rotation else None,
        interactions_count=honeypot.interactions_count,
        created_at=honeypot.created_at.isoformat() if honeypot.created_at else None,
    )


@router.get("/interactions", response_model=list[InteractionOut])
async def list_interactions(
    honeypot_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List honeypot interactions with filtering."""
    client = auth.client
    query = select(HoneypotInteraction).where(
        HoneypotInteraction.client_id == client.id
    )
    if honeypot_id:
        query = query.where(HoneypotInteraction.honeypot_id == honeypot_id)
    if source_ip:
        query = query.where(HoneypotInteraction.source_ip == source_ip)
    query = query.order_by(HoneypotInteraction.timestamp.desc()).offset(offset).limit(limit)

    result = await db.execute(query)
    interactions = result.scalars().all()

    return [
        InteractionOut(
            id=i.id,
            honeypot_id=i.honeypot_id,
            source_ip=i.source_ip,
            source_port=i.source_port,
            protocol=i.protocol,
            commands=i.commands or [],
            credentials_tried=i.credentials_tried or [],
            session_duration=i.session_duration,
            attacker_profile_id=i.attacker_profile_id,
            timestamp=i.timestamp.isoformat() if i.timestamp else None,
        )
        for i in interactions
    ]


@router.get("/attackers", response_model=list[AttackerOut])
async def list_attackers(
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List attacker profiles."""
    client = auth.client
    result = await db.execute(
        select(AttackerProfile)
        .where(AttackerProfile.client_id == client.id)
        .order_by(AttackerProfile.total_interactions.desc())
        .offset(offset)
        .limit(limit)
    )
    profiles = result.scalars().all()

    return [
        AttackerOut(
            id=p.id,
            source_ip=p.source_ip,
            known_ips=p.known_ips or [],
            tools_used=p.tools_used or [],
            techniques=p.techniques or [],
            sophistication=p.sophistication,
            total_interactions=p.total_interactions,
            first_seen=p.first_seen.isoformat() if p.first_seen else None,
            last_seen=p.last_seen.isoformat() if p.last_seen else None,
            ai_assessment=p.ai_assessment,
        )
        for p in profiles
    ]


@router.get("/attackers/{attacker_id}", response_model=AttackerOut)
async def get_attacker(
    attacker_id: str,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get attacker profile details."""
    client = auth.client
    result = await db.execute(
        select(AttackerProfile).where(
            AttackerProfile.id == attacker_id,
            AttackerProfile.client_id == client.id,
        )
    )
    profile = result.scalar_one_or_none()
    if not profile:
        raise HTTPException(status_code=404, detail="Attacker profile not found")

    return AttackerOut(
        id=profile.id,
        source_ip=profile.source_ip,
        known_ips=profile.known_ips or [],
        tools_used=profile.tools_used or [],
        techniques=profile.techniques or [],
        sophistication=profile.sophistication,
        total_interactions=profile.total_interactions,
        first_seen=profile.first_seen.isoformat() if profile.first_seen else None,
        last_seen=profile.last_seen.isoformat() if profile.last_seen else None,
        ai_assessment=profile.ai_assessment,
    )
