from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.auth import AuthContext, require_viewer
from app.models.client import Client
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.incident import Incident
from app.models.action import Action
from app.models.honeypot import HoneypotInteraction
from app.models.audit_log import AuditLog

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


class OverviewStats(BaseModel):
    total_assets: int
    open_vulnerabilities: int
    critical_vulnerabilities: int
    active_incidents: int
    honeypot_interactions: int
    actions_taken: int
    risk_level: str


class TimelineEvent(BaseModel):
    id: str
    type: str
    title: str
    severity: str | None = None
    timestamp: str


class ThreatMapEntry(BaseModel):
    source_ip: str
    count: int
    last_seen: str


@router.get("/overview", response_model=OverviewStats)
async def get_overview(
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get dashboard overview statistics."""
    client = auth.client
    total_assets = await db.scalar(
        select(func.count(Asset.id)).where(Asset.client_id == client.id)
    ) or 0

    open_vulns = await db.scalar(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.client_id == client.id,
            Vulnerability.status == "open",
        )
    ) or 0

    critical_vulns = await db.scalar(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.client_id == client.id,
            Vulnerability.severity == "critical",
            Vulnerability.status == "open",
        )
    ) or 0

    active_incidents = await db.scalar(
        select(func.count(Incident.id)).where(
            Incident.client_id == client.id,
            Incident.status.in_(["open", "investigating"]),
        )
    ) or 0

    hp_interactions = await db.scalar(
        select(func.count(HoneypotInteraction.id)).where(
            HoneypotInteraction.client_id == client.id,
        )
    ) or 0

    actions_taken = await db.scalar(
        select(func.count(Action.id)).where(
            Action.client_id == client.id,
            Action.status == "executed",
        )
    ) or 0

    score = critical_vulns * 10 + active_incidents * 5
    if score >= 50:
        risk_level = "critical"
    elif score >= 20:
        risk_level = "high"
    elif score >= 5:
        risk_level = "medium"
    else:
        risk_level = "low"

    return OverviewStats(
        total_assets=total_assets,
        open_vulnerabilities=open_vulns,
        critical_vulnerabilities=critical_vulns,
        active_incidents=active_incidents,
        honeypot_interactions=hp_interactions,
        actions_taken=actions_taken,
        risk_level=risk_level,
    )


@router.get("/timeline", response_model=list[TimelineEvent])
async def get_timeline(
    limit: int = 50,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get recent activity timeline."""
    client = auth.client
    events = []

    result = await db.execute(
        select(Incident)
        .where(Incident.client_id == client.id)
        .order_by(Incident.detected_at.desc())
        .limit(limit // 2)
    )
    for inc in result.scalars().all():
        events.append(TimelineEvent(
            id=inc.id,
            type="incident",
            title=inc.title,
            severity=inc.severity,
            timestamp=inc.detected_at.isoformat(),
        ))

    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.client_id == client.id)
        .order_by(AuditLog.timestamp.desc())
        .limit(limit // 2)
    )
    for log in result.scalars().all():
        events.append(TimelineEvent(
            id=log.id,
            type="audit",
            title=f"AI: {log.action}",
            severity=None,
            timestamp=log.timestamp.isoformat(),
        ))

    events.sort(key=lambda e: e.timestamp, reverse=True)
    return events[:limit]


@router.get("/threat-map", response_model=list[ThreatMapEntry])
async def get_threat_map(
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Get threat geography data from honeypot interactions."""
    client = auth.client
    result = await db.execute(
        select(
            HoneypotInteraction.source_ip,
            func.count(HoneypotInteraction.id).label("count"),
            func.max(HoneypotInteraction.timestamp).label("last_seen"),
        )
        .where(HoneypotInteraction.client_id == client.id)
        .group_by(HoneypotInteraction.source_ip)
        .order_by(func.count(HoneypotInteraction.id).desc())
        .limit(100)
    )
    entries = []
    for row in result.all():
        entries.append(ThreatMapEntry(
            source_ip=row[0],
            count=row[1],
            last_seen=row[2].isoformat() if row[2] else "",
        ))
    return entries
