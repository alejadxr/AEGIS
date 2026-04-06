from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.auth import AuthContext, require_analyst, require_viewer
from app.models.client import Client
from app.models.threat_intel import ThreatIntel
from app.modules.phantom.intel import threat_intel_generator

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


@router.get("/intel/search", response_model=list[IOCOut])
async def search_iocs(
    q: str,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Search IOCs by value or type."""
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


@router.get("/feed")
async def get_threat_feed(
    format: str = "json",
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Export threat feed in JSON or STIX format."""
    return await threat_intel_generator.generate_threat_feed(db, format=format)
