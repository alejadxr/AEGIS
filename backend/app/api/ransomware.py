"""
Ransomware incident API.

Accepts forensic chains posted by the Rust node agent's ransomware module
when it detects and blocks a ransomware process. Creates:
  1. A RansomwareEvent row (full forensic chain)
  2. A CRITICAL Incident (so the dashboard surfaces it immediately)
  3. An AgentEvent (forensic category) for timeline continuity

Phase R-C additions:
  - GET  /recovery-options/{event_id}  — snapshots + decryptors for an event
  - POST /restore                       — trigger snapshot restore job
  - GET  /decryptors                    — direct decryptor lookup by file extension
"""

import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.auth import AuthContext, require_analyst, require_admin, get_auth_context
from app.core.events import event_bus
from app.models.ransomware_event import RansomwareEvent
from app.models.endpoint_agent import (
    EndpointAgent, AgentEvent, EventSeverity, EventCategory,
)
from app.models.incident import Incident
from app.services.snapshot_manager import get_snapshot_provider, Snapshot, RestoreJob
from app.services.decryptor_library import DecryptorLibrary, DecryptorEntry

logger = logging.getLogger("aegis.ransomware")
router = APIRouter(prefix="/ransomware", tags=["ransomware"])

# Module-level singleton — constructed lazily on first request
_decryptor_library: Optional[DecryptorLibrary] = None


def _get_decryptor_library() -> DecryptorLibrary:
    global _decryptor_library
    if _decryptor_library is None:
        _decryptor_library = DecryptorLibrary()
    return _decryptor_library


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


# ---------------------------------------------------------------------------
# Phase R-C: Recovery schemas
# ---------------------------------------------------------------------------

class SnapshotOut(BaseModel):
    id: str
    host_id: str
    created_at: str
    age_hours: float
    label: Optional[str] = None
    provider: str


class DecryptorOut(BaseModel):
    name: str
    source_url: str
    supported_groups: list[str]
    file_extensions: list[str]
    ransom_notes: list[str]


class RecoveryOptionsOut(BaseModel):
    event_id: str
    host_id: Optional[str]
    snapshots: list[SnapshotOut]
    decryptors: list[DecryptorOut]


class RestoreRequest(BaseModel):
    host_id: str = Field(..., description="Hostname or agent ID to restore")
    snapshot_id: str = Field(..., description="Snapshot identifier to restore from")
    target_path: str = Field(..., description="Filesystem path for the restore target")


class RestoreJobOut(BaseModel):
    job_id: str
    host_id: str
    snapshot_id: str
    target_path: str
    status: str
    started_at: str
    error: Optional[str] = None


def _snapshot_to_out(snap: Snapshot) -> SnapshotOut:
    return SnapshotOut(
        id=snap.id,
        host_id=snap.host_id,
        created_at=snap.created_at.isoformat(),
        age_hours=round(snap.age_hours(), 2),
        label=snap.label,
        provider=snap.provider,
    )


def _decryptor_to_out(entry: DecryptorEntry) -> DecryptorOut:
    return DecryptorOut(
        name=entry.name,
        source_url=entry.source_url,
        supported_groups=entry.supported_groups,
        file_extensions=entry.file_extensions,
        ransom_notes=entry.ransom_notes,
    )


def _job_to_out(job: RestoreJob) -> RestoreJobOut:
    return RestoreJobOut(
        job_id=job.job_id,
        host_id=job.host_id,
        snapshot_id=job.snapshot_id,
        target_path=job.target_path,
        status=job.status,
        started_at=job.started_at.isoformat(),
        error=job.error,
    )


# ---------------------------------------------------------------------------
# Phase R-C: Recovery endpoints
# ---------------------------------------------------------------------------

@router.get("/recovery-options/{event_id}", response_model=RecoveryOptionsOut)
async def get_recovery_options(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_analyst),
):
    """Return available snapshots and decryptors for a given ransomware event.

    Scoped to the authenticated client for tenant isolation.
    """
    # Resolve event — enforce tenant scope
    event = await db.get(RansomwareEvent, event_id)
    if not event:
        raise HTTPException(status_code=404, detail="ransomware event not found")
    if event.client_id != auth.client_id:
        raise HTTPException(status_code=403, detail="access denied")

    # Determine host from the linked agent
    host_id: Optional[str] = None
    if event.agent_id:
        agent = await db.get(EndpointAgent, event.agent_id)
        if agent:
            host_id = agent.hostname or agent.ip_address or event.agent_id

    # Snapshot listing (gated by AEGIS_REAL_RECOVERY; returns noop data in dev)
    provider = get_snapshot_provider()
    try:
        snapshots = provider.list_snapshots(host_id or "localhost")
    except Exception as e:
        logger.warning("ransomware.recovery_options: snapshot listing failed: %s", e)
        snapshots = []

    # Decryptor lookup — derive extensions from affected file names
    lib = _get_decryptor_library()
    decryptors: list[DecryptorEntry] = []
    seen_names: set[str] = set()

    affected_files: list[str] = event.affected_files or []
    for filepath in affected_files[:50]:  # cap at 50 to avoid O(n^2) on large sets
        ext = "." + filepath.rsplit(".", 1)[-1].lower() if "." in filepath else ""
        if ext and ext != ".":
            for entry in lib.lookup_by_extension(ext):
                if entry.name not in seen_names:
                    decryptors.append(entry)
                    seen_names.add(entry.name)

    return RecoveryOptionsOut(
        event_id=event_id,
        host_id=host_id,
        snapshots=[_snapshot_to_out(s) for s in snapshots],
        decryptors=[_decryptor_to_out(e) for e in decryptors],
    )


@router.post("/restore", response_model=RestoreJobOut)
async def trigger_restore(
    body: RestoreRequest,
    auth: AuthContext = Depends(require_admin),
):
    """Trigger a snapshot restore job on the given host.

    Requires admin role — destructive operation.
    Input is validated via Pydantic; snapshot_manager further sanitizes
    paths before any subprocess call.
    """
    provider = get_snapshot_provider()
    try:
        job = provider.restore(body.host_id, body.snapshot_id, body.target_path)
    except NotImplementedError as e:
        raise HTTPException(
            status_code=501,
            detail=f"restore not supported on this platform: {e}",
        )
    except Exception as e:
        logger.error("ransomware.restore: unexpected error: %s", e)
        raise HTTPException(status_code=500, detail="restore job failed to start")

    logger.info(
        "ransomware.restore: job %s started for host=%s snapshot=%s target=%s status=%s",
        job.job_id, job.host_id, job.snapshot_id, job.target_path, job.status,
    )
    return _job_to_out(job)


@router.get("/decryptors", response_model=list[DecryptorOut])
async def lookup_decryptors(
    file_extension: Optional[str] = Query(
        default=None,
        description="File extension to search for (e.g. .locky)",
    ),
    ransom_note: Optional[str] = Query(
        default=None,
        description="Ransom note filename to match (e.g. README.TXT)",
    ),
    auth: AuthContext = Depends(require_analyst),
):
    """Look up known decryptors by file extension or ransom note filename.

    At least one query parameter is required.
    """
    if not file_extension and not ransom_note:
        raise HTTPException(
            status_code=422,
            detail="At least one of 'file_extension' or 'ransom_note' is required",
        )

    lib = _get_decryptor_library()
    results: list[DecryptorEntry] = []
    seen_names: set[str] = set()

    if file_extension:
        for entry in lib.lookup_by_extension(file_extension):
            if entry.name not in seen_names:
                results.append(entry)
                seen_names.add(entry.name)

    if ransom_note:
        for entry in lib.lookup_by_ransom_note(ransom_note):
            if entry.name not in seen_names:
                results.append(entry)
                seen_names.add(entry.name)

    return [_decryptor_to_out(e) for e in results]
