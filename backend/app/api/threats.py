from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.auth import AuthContext, require_analyst, require_viewer
from app.core.events import event_bus
from app.models.client import Client
from app.models.threat_intel import ThreatIntel
from app.modules.phantom.intel import threat_intel_generator
from app.services.threat_intel_hub import threat_intel_hub
from app.core.mongo_client import is_connected as mongo_connected
from app.services.ioc_validator import validate_ioc, IOCValidationError

router = APIRouter(prefix="/threats", tags=["threats"])


# --- Schemas ---

class IOCCreate(BaseModel):
    ioc_type: str  # ip, domain, hash, url, email
    ioc_value: str
    threat_type: str | None = None
    confidence: float = 0.5
    source: str = "manual"
    tags: list[str] = []


class IOCOut(BaseModel):
    id: str
    ioc_type: str
    ioc_value: str
    threat_type: str | None = None
    confidence: float | None = None
    source: str | None = None
    tags: list = []
    first_seen: str | None = None
    last_seen: str | None = None


# --- Routes ---

@router.get("/intel", response_model=list[IOCOut])
async def list_intel(
    ioc_type: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List threat intel IOCs."""
    query = select(ThreatIntel)
    if ioc_type:
        query = query.where(ThreatIntel.ioc_type == ioc_type)
    if source:
        query = query.where(ThreatIntel.source == source)
    query = query.order_by(ThreatIntel.last_seen.desc()).offset(offset).limit(limit)

    result = await db.execute(query)
    iocs = result.scalars().all()

    return [
        IOCOut(
            id=ioc.id,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.ioc_value,
            threat_type=ioc.threat_type,
            confidence=ioc.confidence,
            source=ioc.source,
            tags=ioc.tags or [],
            first_seen=ioc.first_seen.isoformat() if ioc.first_seen else None,
            last_seen=ioc.last_seen.isoformat() if ioc.last_seen else None,
        )
        for ioc in iocs
    ]


@router.post("/intel", response_model=IOCOut, status_code=201)
async def create_ioc(
    body: IOCCreate,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Add an IOC manually. Analyst or admin only."""
    ioc = ThreatIntel(
        ioc_type=body.ioc_type,
        ioc_value=body.ioc_value,
        threat_type=body.threat_type,
        confidence=body.confidence,
        source=body.source,
        tags=body.tags,
    )
    db.add(ioc)
    await db.commit()
    await db.refresh(ioc)

    return IOCOut(
        id=ioc.id,
        ioc_type=ioc.ioc_type,
        ioc_value=ioc.ioc_value,
        threat_type=ioc.threat_type,
        confidence=ioc.confidence,
        source=ioc.source,
        tags=ioc.tags or [],
        first_seen=ioc.first_seen.isoformat() if ioc.first_seen else None,
        last_seen=ioc.last_seen.isoformat() if ioc.last_seen else None,
    )


@router.get("/feed")
async def get_threat_feed(
    format: str = "json",
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Public threat feed endpoint -- NO authentication required.

    Remote AEGIS nodes and third-party tools can pull shared IOCs from here.
    Supports JSON (default) and STIX format.
    Optionally pass ?since=<ISO8601> to get only recent IOCs.
    """
    since_param = request.query_params.get("since") if request else None

    # If MongoDB is connected, serve from the shared hub (richer data)
    if mongo_connected():
        since_dt = None
        if since_param:
            try:
                since_dt = datetime.fromisoformat(since_param.replace("Z", "+00:00"))
            except ValueError:
                pass
        iocs = await threat_intel_hub.pull_iocs(since=since_dt)
        # Serialize datetimes
        for ioc in iocs:
            for key in ("first_seen", "last_seen"):
                if isinstance(ioc.get(key), datetime):
                    ioc[key] = ioc[key].isoformat()
        return {
            "iocs": iocs,
            "count": len(iocs),
            "source": "aegis_hub",
            "hub_url": "https://api-aegis.somoswilab.com",
        }

    # Fallback: serve from local PostgreSQL
    return await threat_intel_generator.generate_threat_feed(db, format=format)


# ---------------------------------------------------------------------------
# Public threat sharing endpoints (no auth required for node-to-hub comms)
# ---------------------------------------------------------------------------

class SharedIOCSubmit(BaseModel):
    ioc_type: str = Field(..., description="ip | domain | hash | url")
    ioc_value: str = Field(..., description="The indicator value")
    threat_type: str = Field("unknown", description="brute_force, c2, phishing, malware, etc.")
    confidence: float = Field(0.75, ge=0.0, le=1.0)
    mitre_techniques: list[str] = Field(default_factory=list)
    detection_source: str = Field("remote_node", description="Source: remote_node, honeypot, scanner, etc.")
    node_id: str = Field("", description="Optional reporting node identifier")


@router.post("/intel/share")
async def share_ioc_public(body: SharedIOCSubmit):
    """
    Public IOC sharing endpoint -- remote AEGIS nodes submit IOCs here.

    No authentication required so that any AEGIS node configured with
    the hub URL can contribute threat intelligence.
    Validates IOCs before accepting to prevent poisoning.
    """
    # Validate IOC to prevent poisoning
    try:
        validated = validate_ioc(
            ioc_type=body.ioc_type,
            ioc_value=body.ioc_value,
            threat_type=body.threat_type,
            confidence=body.confidence,
            source_node=body.node_id,
        )
    except IOCValidationError as e:
        return {"status": "rejected", "reason": str(e)}

    if not mongo_connected():
        raise HTTPException(status_code=503, detail="Threat intel hub not available (MongoDB not connected)")

    result = await threat_intel_hub.share_ioc({
        "ioc_type": validated["ioc_type"],
        "ioc_value": validated["ioc_value"],
        "threat_type": validated["threat_type"],
        "confidence": validated["confidence"],
        "mitre_techniques": body.mitre_techniques,
        "detection_source": body.detection_source,
    })

    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("reason"))

    # Broadcast to connected WebSocket clients
    try:
        await event_bus.publish("threat_shared", {
            "_event_type": "threat_shared",
            "ioc_type": body.ioc_type,
            "ioc_value": body.ioc_value,
            "threat_type": body.threat_type,
            "confidence": body.confidence,
            "detection_source": body.detection_source,
            "node_id": body.node_id,
        })
    except Exception:
        pass

    return {"status": "accepted", "upserted": result.get("upserted", False)}


@router.get("/intel/search")
async def search_iocs_public(
    q: str,
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Search IOCs by value or type -- public endpoint for node queries.

    No authentication required so remote nodes can query the hub.
    """
    result = await db.execute(
        select(ThreatIntel).where(
            or_(
                ThreatIntel.ioc_value.contains(q),
                ThreatIntel.ioc_type.contains(q),
                ThreatIntel.threat_type.contains(q),
            )
        ).limit(50)
    )
    iocs = result.scalars().all()

    return [
        IOCOut(
            id=ioc.id,
            ioc_type=ioc.ioc_type,
            ioc_value=ioc.ioc_value,
            threat_type=ioc.threat_type,
            confidence=ioc.confidence,
            source=ioc.source,
            tags=ioc.tags or [],
            first_seen=ioc.first_seen.isoformat() if ioc.first_seen else None,
            last_seen=ioc.last_seen.isoformat() if ioc.last_seen else None,
        )
        for ioc in iocs
    ]


# ---------------------------------------------------------------------------
# Hub info endpoint (public -- nodes discover capabilities)
# ---------------------------------------------------------------------------

@router.get("/hub/info")
async def hub_info():
    """
    Public hub info endpoint. Returns capabilities and connection details
    so remote AEGIS nodes can auto-configure.
    """
    from app.config import settings as cfg

    hub_stats = threat_intel_hub.get_stats() if mongo_connected() else {}

    return {
        "hub": "aegis-threat-sharing",
        "version": "1.0.0",
        "api_url": "https://api-aegis.somoswilab.com",
        "ws_url": "wss://api-aegis.somoswilab.com/ws",
        "endpoints": {
            "feed": "/api/v1/threats/feed",
            "share": "/api/v1/threats/intel/share",
            "search": "/api/v1/threats/intel/search",
            "register": "/api/v1/threats/nodes/register",
            "nodes": "/api/v1/threats/nodes",
        },
        "mongo_connected": mongo_connected(),
        "instance_id": hub_stats.get("instance_id", "unknown"),
        "iocs_shared": hub_stats.get("iocs_shared", 0),
        "iocs_pulled": hub_stats.get("iocs_pulled", 0),
    }


# ---------------------------------------------------------------------------
# Sharing node registration (separate from EDR node enrollment)
# ---------------------------------------------------------------------------

# In-memory registry of sharing nodes (lightweight -- no DB required)
_sharing_nodes: dict[str, dict] = {}


class SharingNodeRegister(BaseModel):
    node_id: str = Field(..., description="Unique node identifier")
    node_name: str = Field("", description="Human-readable name")
    node_url: str = Field("", description="Node's own API URL (for bidirectional sharing)")
    version: str = Field("1.0.0", description="AEGIS version running on the node")


@router.post("/nodes/register")
async def register_sharing_node(body: SharingNodeRegister):
    """
    Register a remote AEGIS node for threat sharing.

    No authentication required -- any AEGIS instance can register.
    """
    _sharing_nodes[body.node_id] = {
        "node_id": body.node_id,
        "node_name": body.node_name or body.node_id,
        "node_url": body.node_url,
        "version": body.version,
        "registered_at": datetime.utcnow().isoformat(),
        "last_seen": datetime.utcnow().isoformat(),
        "iocs_submitted": 0,
    }

    # Broadcast registration event
    try:
        await event_bus.publish("node_status", {
            "_event_type": "node_status",
            "action": "sharing_node_registered",
            "node_id": body.node_id,
            "node_name": body.node_name,
        })
    except Exception:
        pass

    return {
        "status": "registered",
        "node_id": body.node_id,
        "hub_url": "https://api-aegis.somoswilab.com",
        "ws_url": "wss://api-aegis.somoswilab.com/ws",
        "message": f"Node registered for threat sharing.",
    }


@router.get("/nodes")
async def list_sharing_nodes():
    """List all registered sharing nodes. Public endpoint."""
    return {
        "nodes": list(_sharing_nodes.values()),
        "count": len(_sharing_nodes),
    }


@router.get("/sharing/stats")
async def get_sharing_stats():
    """Get threat sharing statistics (hub sync + auto-sharer)."""
    from app.services.hub_sync_client import hub_sync_client
    from app.services.auto_sharer import auto_sharer

    return {
        "hub_sync": hub_sync_client.stats,
        "auto_sharer": auto_sharer.stats,
        "nodes_registered": len(_sharing_nodes),
    }
