"""
Antivirus API (Task #6).

Endpoints:
  GET  /antivirus/signatures            — agents fetch the latest rule bundle
  POST /antivirus/detections            — agents report on-access detections
  GET  /antivirus/quarantine            — list quarantined items
  POST /antivirus/quarantine/{id}/release — restore a quarantined file
  GET  /antivirus/hash/{sha256}/lookup  — hash reputation query
  POST /antivirus/scan                  — trigger on-demand scan command
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.auth import AuthContext, require_analyst, get_auth_context
from app.core.events import event_bus
from app.models.av_detection import AvDetection
from app.models.endpoint_agent import (
    AgentEvent, EndpointAgent, EventCategory, EventSeverity,
)
from app.models.incident import Incident
from app.services.signature_updater import signature_updater

logger = logging.getLogger("aegis.av")
router = APIRouter(prefix="/antivirus", tags=["antivirus"])


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

@router.get("/signatures")
async def get_signatures():
    bundle = signature_updater.current()
    return bundle.to_dict()


@router.post("/signatures/update")
async def force_signature_update(
    auth: AuthContext = Depends(require_analyst),
):
    """Force a fresh signature pull. Admin-only."""
    bundle = await signature_updater.update_now()
    return {
        "version": bundle.version,
        "bad_hash_count": len(bundle.bad_hashes),
        "generated_at": bundle.generated_at,
    }


# ---------------------------------------------------------------------------
# Detections
# ---------------------------------------------------------------------------

class DetectionIn(BaseModel):
    agent_id: str
    path: str
    sha256: str
    rule: Optional[str] = None
    engine: str = "yara"
    quarantined: bool = False
    detected_at: str = ""
    file_size: Optional[int] = None


class DetectionOut(BaseModel):
    id: str
    incident_id: Optional[str]
    path: str
    sha256: str
    rule: Optional[str]
    engine: str
    quarantined: bool
    detected_at: str


@router.post("/detections", response_model=DetectionOut)
async def report_detection(
    payload: DetectionIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth_context),
):
    agent = await db.get(EndpointAgent, payload.agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    if auth.client_id and agent.client_id != auth.client_id:
        raise HTTPException(status_code=403, detail="agent does not belong to this client")

    try:
        detected = (
            datetime.fromisoformat(payload.detected_at.replace("Z", "+00:00"))
            if payload.detected_at
            else datetime.utcnow()
        )
    except ValueError:
        detected = datetime.utcnow()

    row = AvDetection(
        client_id=agent.client_id,
        agent_id=agent.id,
        path=payload.path,
        sha256=payload.sha256,
        rule=payload.rule,
        engine=payload.engine,
        quarantined=payload.quarantined,
        file_size=payload.file_size,
        detected_at=detected,
    )
    db.add(row)
    await db.flush()

    # Create a HIGH incident (CRITICAL if not quarantined)
    severity = "high" if payload.quarantined else "critical"
    incident = Incident(
        client_id=agent.client_id,
        title=f"Malware detected on {agent.hostname}: {payload.rule or 'unknown'}",
        description=(
            f"Detection engine '{payload.engine}' matched rule "
            f"'{payload.rule or 'unknown'}' against {payload.path} "
            f"(sha256={payload.sha256}). "
            f"{'File was quarantined.' if payload.quarantined else 'File NOT quarantined.'}"
        ),
        severity=severity,
        status="contained" if payload.quarantined else "open",
        source=f"antivirus:{payload.engine}",
        mitre_technique="T1204",  # User Execution
        mitre_tactic="execution",
        source_ip=agent.ip_address,
        ai_analysis={
            "engine": payload.engine,
            "rule": payload.rule,
            "quarantined": payload.quarantined,
        },
        raw_alert={
            "path": payload.path,
            "sha256": payload.sha256,
            "file_size": payload.file_size,
        },
        detected_at=detected,
    )
    if payload.quarantined:
        incident.contained_at = datetime.utcnow()
    db.add(incident)
    await db.flush()

    row.incident_id = incident.id

    # Mirror into agent_events
    ev = AgentEvent(
        agent_id=agent.id,
        client_id=agent.client_id,
        category=EventCategory.forensic,
        severity=EventSeverity.high if payload.quarantined else EventSeverity.critical,
        title=f"AV detection: {payload.rule or 'unknown'} at {payload.path}",
        details={
            "av_detection_id": row.id,
            "incident_id": incident.id,
            "path": payload.path,
            "sha256": payload.sha256,
            "rule": payload.rule,
            "engine": payload.engine,
            "quarantined": payload.quarantined,
        },
        timestamp=detected,
    )
    db.add(ev)

    await db.commit()

    try:
        await event_bus.publish("antivirus.detection", {
            "client_id": agent.client_id,
            "agent_id": agent.id,
            "hostname": agent.hostname,
            "rule": payload.rule,
            "engine": payload.engine,
            "path": payload.path,
            "sha256": payload.sha256,
            "quarantined": payload.quarantined,
            "incident_id": incident.id,
        })
    except Exception as e:
        logger.debug("av event publish failed: %s", e)

    logger.warning(
        "av detection: host=%s rule=%s engine=%s path=%s quarantined=%s",
        agent.hostname,
        payload.rule,
        payload.engine,
        payload.path,
        payload.quarantined,
    )

    return DetectionOut(
        id=row.id,
        incident_id=incident.id,
        path=row.path,
        sha256=row.sha256,
        rule=row.rule,
        engine=row.engine,
        quarantined=row.quarantined,
        detected_at=row.detected_at.isoformat(),
    )


# ---------------------------------------------------------------------------
# Quarantine list + release
# ---------------------------------------------------------------------------

@router.get("/quarantine")
async def list_quarantine(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_analyst),
):
    stmt = (
        select(AvDetection)
        .where(
            and_(
                AvDetection.client_id == auth.client_id,
                AvDetection.quarantined == True,  # noqa: E712
                AvDetection.released == False,  # noqa: E712
            )
        )
        .order_by(AvDetection.detected_at.desc())
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "agent_id": r.agent_id,
            "path": r.path,
            "sha256": r.sha256,
            "rule": r.rule,
            "engine": r.engine,
            "file_size": r.file_size,
            "detected_at": r.detected_at.isoformat() if r.detected_at else None,
        }
        for r in rows
    ]


@router.post("/quarantine/{detection_id}/release")
async def release_quarantine(
    detection_id: str,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_analyst),
):
    row = await db.get(AvDetection, detection_id)
    if not row or row.client_id != auth.client_id:
        raise HTTPException(status_code=404, detail="not found")
    if row.released:
        return {"released": True, "already_released": True}

    row.released = True
    await db.commit()

    # Dispatch release command to the agent via event bus — the agent polls
    # its commands list and carries out the release locally.
    try:
        await event_bus.publish("agent.command", {
            "agent_id": row.agent_id,
            "command": "av_release",
            "detection_id": row.id,
            "sha256": row.sha256,
        })
    except Exception as e:
        logger.debug("release command publish failed: %s", e)

    return {"released": True, "detection_id": row.id, "sha256": row.sha256}


# ---------------------------------------------------------------------------
# Hash reputation
# ---------------------------------------------------------------------------

@router.get("/hash/{sha256}/lookup")
async def hash_lookup(
    sha256: str,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_analyst),
):
    sha = sha256.lower().strip()
    if len(sha) != 64:
        raise HTTPException(status_code=400, detail="invalid sha256")

    # Check signature bundle
    bundle = signature_updater.current()
    in_bad_list = sha in set(bundle.bad_hashes)

    # Check local detections
    stmt = (
        select(AvDetection)
        .where(
            and_(
                AvDetection.client_id == auth.client_id,
                AvDetection.sha256 == sha,
            )
        )
        .limit(5)
    )
    rows = (await db.execute(stmt)).scalars().all()

    return {
        "sha256": sha,
        "known_bad": in_bad_list,
        "local_detections": len(rows),
        "last_detection": rows[0].detected_at.isoformat() if rows else None,
        "engines": list({r.engine for r in rows}),
    }


# ---------------------------------------------------------------------------
# On-demand scan command
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    agent_id: str
    paths: list[str] = Field(default_factory=list)
    full_scan: bool = False


@router.post("/scan")
async def trigger_scan(
    payload: ScanRequest,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_analyst),
):
    agent = await db.get(EndpointAgent, payload.agent_id)
    if not agent or agent.client_id != auth.client_id:
        raise HTTPException(status_code=404, detail="agent not found")

    try:
        await event_bus.publish("agent.command", {
            "agent_id": agent.id,
            "command": "av_scan",
            "paths": payload.paths,
            "full_scan": payload.full_scan,
        })
    except Exception as e:
        logger.debug("scan command publish failed: %s", e)
    return {"queued": True, "agent_id": agent.id, "full_scan": payload.full_scan}
