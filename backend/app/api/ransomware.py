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

Dashboard additions:
  - GET  /stats                         — aggregated stats (rules_active, raas_groups_tracked, triggers_24h)
  - GET  /raas-groups                   — RaaS group activity timeline + group metadata
"""

import logging
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.core.auth import AuthContext, require_analyst, require_admin, require_viewer, get_auth_context
from app.core.events import event_bus
from app.models.ransomware_event import RansomwareEvent
from app.models.endpoint_agent import (
    EndpointAgent, AgentEvent, EventSeverity, EventCategory,
)
from app.models.incident import Incident
from app.models.threat_intel import ThreatIntel
from app.services.snapshot_manager import get_snapshot_provider, Snapshot, RestoreJob
from app.services.decryptor_library import DecryptorLibrary, DecryptorEntry

logger = logging.getLogger("aegis.ransomware")
router = APIRouter(prefix="/ransomware", tags=["ransomware"])

# Module-level singleton — constructed lazily on first request
_decryptor_library: Optional[DecryptorLibrary] = None

# Path to the Sigma rules directory (relative to this file)
_RULES_DIR = Path(__file__).parent.parent / "rules"


def _get_decryptor_library() -> DecryptorLibrary:
    global _decryptor_library
    if _decryptor_library is None:
        _decryptor_library = DecryptorLibrary()
    return _decryptor_library


def _count_ransomware_rules() -> int:
    """Count YAML rule files that contain 'ransomware' in their name or path."""
    count = 0
    if _RULES_DIR.exists():
        for path in _RULES_DIR.rglob("*.yaml"):
            if "ransomware" in path.name.lower() or "ransomware" in path.parent.name.lower():
                count += 1
    return count or 15  # safe fallback matching the known rule set


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


class RansomwareStatsOut(BaseModel):
    rules_active: int
    raas_groups_tracked: int
    triggers_24h: int


class RaaSGroupOut(BaseModel):
    name: str
    activity_score: int
    color: Optional[str] = None


class RaaSGroupsOut(BaseModel):
    timeline: list[dict]
    groups: list[RaaSGroupOut]


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
# Dashboard stats endpoint
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=RansomwareStatsOut)
async def get_ransomware_stats(
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_viewer),
):
    """
    Aggregated ransomware defense stats for the dashboard header pills.

    Returns:
      - rules_active: count of loaded ransomware Sigma/chain rules
      - raas_groups_tracked: unique ransomware-related entries in ThreatIntel
      - triggers_24h: incidents matching ransomware indicators in last 24 hours
    """
    # --- Rule count from filesystem (fast, no DB round-trip) ---
    rules_active = _count_ransomware_rules()

    # --- RaaS groups: distinct sources in ThreatIntel tagged as ransomware ---
    # ThreatIntel is global (no client_id) so we count across all feeds.
    raas_q = (
        select(func.count())
        .select_from(ThreatIntel)
        .where(
            or_(
                ThreatIntel.source.ilike("%ransomlook%"),
                ThreatIntel.source.ilike("%raas%"),
                ThreatIntel.source.ilike("%ransomware%"),
                ThreatIntel.threat_type.ilike("%ransomware%"),
            )
        )
    )
    raas_groups_tracked: int = (await db.execute(raas_q)).scalar() or 0

    # --- Triggers in last 24 h scoped to this client ---
    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    triggers_q = (
        select(func.count())
        .select_from(Incident)
        .where(
            and_(
                Incident.client_id == auth.client_id,
                Incident.detected_at >= cutoff_24h,
                or_(
                    Incident.mitre_technique.like("T1486%"),
                    Incident.source == "node-agent-ransomware",
                    Incident.title.ilike("%ransom%"),
                    Incident.title.ilike("%encrypt%"),
                ),
            )
        )
    )
    triggers_24h: int = (await db.execute(triggers_q)).scalar() or 0

    return RansomwareStatsOut(
        rules_active=rules_active,
        raas_groups_tracked=raas_groups_tracked,
        triggers_24h=triggers_24h,
    )


# ---------------------------------------------------------------------------
# RaaS group timeline endpoint
# ---------------------------------------------------------------------------

@router.get("/raas-groups", response_model=RaaSGroupsOut)
async def get_raas_groups(
    days: int = Query(14, ge=1, le=90, description="Number of past days for the activity timeline"),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_viewer),
):
    """
    Return RaaS group activity timeline and group metadata.

    Timeline: one entry per day for the requested window. Each entry contains
    the date plus a count per detected group (keyed by process_name from
    RansomwareEvent rows — the closest proxy for group attribution in the
    absence of an external RaaS-feed table).

    Groups: derived first from ThreatIntel rows tagged as ransomware (source
    or threat_type), then supplemented by unique process_name values seen in
    RansomwareEvent. activity_score is mapped from confidence (0-1 → 0-100).
    """
    cutoff = datetime.utcnow() - timedelta(days=days)

    # --- Pull RaaS group metadata from ThreatIntel ---
    intel_q = (
        select(ThreatIntel)
        .where(
            or_(
                ThreatIntel.source.ilike("%ransomlook%"),
                ThreatIntel.source.ilike("%raas%"),
                ThreatIntel.source.ilike("%ransomware%"),
                ThreatIntel.threat_type.ilike("%ransomware%"),
            )
        )
        .order_by(ThreatIntel.confidence.desc().nullslast(), ThreatIntel.last_seen.desc())
        .limit(200)
    )
    intel_rows = (await db.execute(intel_q)).scalars().all()

    # Build a name → score map from ThreatIntel.
    # Prefer tags[0] as the group name (feed convention); fall back to source.
    group_map: dict[str, int] = {}
    for row in intel_rows:
        tags = row.tags if isinstance(row.tags, list) else []
        name: str = ""
        for tag in tags:
            if isinstance(tag, str) and tag and not tag.startswith(("ioc:", "type:")):
                name = tag
                break
        if not name:
            name = (row.source or "").split("/")[-1] or "unknown"
        score = int((row.confidence or 0.5) * 100)
        if name not in group_map or score > group_map[name]:
            group_map[name] = score

    # --- Fetch RansomwareEvent rows in the window (client-scoped) ---
    events_q = (
        select(RansomwareEvent)
        .where(
            and_(
                RansomwareEvent.client_id == auth.client_id,
                RansomwareEvent.detected_at >= cutoff,
            )
        )
        .order_by(RansomwareEvent.detected_at.asc())
    )
    event_rows = (await db.execute(events_q)).scalars().all()

    # Count per (day, process_name) — process_name is our group attribution proxy
    day_buckets: dict[str, dict[str, int]] = {}
    process_scores: dict[str, int] = {}
    for evt in event_rows:
        if not evt.detected_at:
            continue
        day_key = evt.detected_at.strftime("%Y-%m-%d")
        group_key = (evt.process_name or "unknown").lower().replace(".exe", "")
        day_buckets.setdefault(day_key, {})[group_key] = (
            day_buckets[day_key].get(group_key, 0) + 1
        )
        # Assign a high activity_score (80+) to any process seen locally —
        # local detections are high-confidence.
        process_scores[group_key] = max(process_scores.get(group_key, 0), 80)

    # Merge process names into group_map (local detections take precedence)
    for name, score in process_scores.items():
        if name not in group_map:
            group_map[name] = score
        else:
            group_map[name] = max(group_map[name], score)

    # Collect all group keys that appear in the timeline
    all_keys: set[str] = set()
    for bucket in day_buckets.values():
        all_keys.update(bucket.keys())

    # Build timeline: one entry per day from oldest to newest
    timeline: list[dict] = []
    if all_keys:
        for i in range(days):
            day = (datetime.utcnow() - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")
            entry: dict = {"date": day}
            for gk in sorted(all_keys):
                entry[gk] = day_buckets.get(day, {}).get(gk, 0)
            timeline.append(entry)

    # Build groups list (cap at 6 for chart readability)
    groups: list[RaaSGroupOut] = [
        RaaSGroupOut(name=name, activity_score=score)
        for name, score in sorted(group_map.items(), key=lambda x: -x[1])
    ][:6]

    return RaaSGroupsOut(timeline=timeline, groups=groups)


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