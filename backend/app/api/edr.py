"""
EDR/XDR API.

Endpoints:
  POST /edr/events          — agent batch ingestion (gzip-aware)
  GET  /edr/process-tree    — reconstruct ancestors + descendants
  GET  /edr/chains          — list recently matched attack-chain incidents
  GET  /edr/events/recent   — tail of recent EDR events for an agent
  POST /edr/kill-process    — kill a process by PID (admin only)
  POST /edr/quarantine-file — quarantine a file with XOR obfuscation (admin only)
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import psutil
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.timeutil import parse_agent_ts
from app.database import get_db
from app.core.auth import (
    AuthContext, require_analyst, require_admin, enforce_node_scope,
    get_node_or_tenant_context,
)
from app.core.events import event_bus
from app.models.endpoint_agent import (
    AgentEvent, EndpointAgent, EventCategory, EventSeverity,
)
from app.models.incident import Incident
from app.services.edr_transport import publish_agent_batch
from app.services.edr_trusted_parents import (
    TrustResolver, in_provisioning_window, resolve_parent_from_db, trust_configured,
)
from app.services.process_tree import (
    build_process_tree, ancestors_for, feed_event,
)
from app.services.attack_chain_detector import evaluate_event, CMD_PATTERN_RULES
from app.services.host_monitor import host_monitor, AGENT_ID as HOST_MONITOR_AGENT_ID

logger = logging.getLogger("aegis.edr")
router = APIRouter(prefix="/edr", tags=["edr"])

# How many events per batch we accept in one POST
MAX_BATCH = 5000


class EdrEventIn(BaseModel):
    kind: str
    at: str
    pid: Optional[int] = None
    ppid: Optional[int] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    command_line: Optional[str] = None
    user: Optional[str] = None
    target: Optional[str] = None
    extra: Optional[dict] = None


class EdrEventsIn(BaseModel):
    agent_id: str
    events_dropped_total: int = 0
    events: list[EdrEventIn]


class EdrEventsOut(BaseModel):
    accepted: int
    dropped: int = 0
    chain_matches: int = 0


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

# --- Guards for the two routes that act on THIS host ---------------------------
#
# kill-process and quarantine-file run on the server AEGIS lives on. One wrong
# PID or path (or a stolen admin credential) could otherwise kill the API, its
# database or its process manager, or remove the platform's own secrets.

MAX_QUARANTINE_BYTES = 200 * 1024 * 1024

_PROTECTED_PROCESS_NAMES = frozenset({
    "postgres", "postmaster", "redis-server", "mongod", "pm2", "pm2 god daemon", "god daemon",
    "cloudflared", "tailscaled", "sshd", "launchd", "systemd", "init", "dockerd", "containerd",
    "com.docker.backend", "frps", "frpc", "kernel_task", "loginwindow", "windowserver",
})


def _protected_process_reason(proc) -> Optional[str]:
    """Why `proc` must not be killed through the API, or None if it may be."""
    try:
        pid = proc.pid
        if pid <= 1:
            return "it is the system's init process"
        me = psutil.Process(os.getpid())
        if pid == me.pid:
            return "it is the AEGIS API itself"
        if pid in {p.pid for p in me.parents()}:
            return "it is an ancestor of the AEGIS API (its process manager)"
        name = (proc.name() or "").lower()
        if name in _PROTECTED_PROCESS_NAMES or name.startswith("pm2"):
            return f"'{name}' is infrastructure this platform depends on"
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        raise
    except Exception as exc:  # cannot tell => do not kill
        return f"could not verify the process is safe to kill ({exc})"
    return None


def _protected_path_reason(file_path: Path) -> Optional[str]:
    """Why `file_path` must not be quarantined through the API, or None."""
    try:
        real = file_path.resolve(strict=True)
    except OSError as exc:
        return f"path cannot be resolved ({exc})"
    name = real.name.lower()
    if name.startswith(".env") or name in {"blocked_ips.txt", "safelist.json", "authorized_keys", "known_hosts"}:
        return "it is a configuration or credential file"
    home = Path.home().resolve()
    install_root = Path(__file__).resolve().parents[3]      # the repository checkout
    protected_roots = [
        install_root, home / ".aegis", home / ".ssh", home / ".pm2", home / ".config",
        Path("/etc"), Path("/bin"), Path("/sbin"), Path("/usr"), Path("/lib"), Path("/boot"),
        Path("/System"), Path("/Library"), Path("/private/etc"), Path("/var/lib"), Path("/opt"),
        Path("/proc"), Path("/sys"), Path("/dev"),
    ]
    for root in protected_roots:
        try:
            root_real = root.resolve()
        except OSError:
            continue
        if real == root_real or root_real in real.parents:
            return f"it lives under {root}"
    return None


MAX_DECOMPRESSED_BYTES = int(os.environ.get("AEGIS_EDR_MAX_DECOMPRESSED_BYTES", str(32 * 1024 * 1024)))


def _bounded_gunzip(raw: bytes, limit: Optional[int] = None) -> bytes:
    """gunzip with a ceiling on the OUTPUT size.

    The body-size middleware only sees the compressed length, and a few
    kilobytes of gzip expand to gigabytes. Decompress incrementally and stop
    the moment the ceiling is crossed.
    """
    import zlib
    limit = MAX_DECOMPRESSED_BYTES if limit is None else limit
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = decoder.decompress(raw, limit + 1)
    except zlib.error as e:
        raise HTTPException(status_code=400, detail=f"gzip decode failed: {e}")
    if len(out) > limit or decoder.unconsumed_tail:
        raise HTTPException(status_code=413, detail="decompressed payload too large")
    return out


@router.post("/events", response_model=EdrEventsOut)
async def ingest_events(
    request: Request,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_node_or_tenant_context),
):
    # Accept gzipped bodies from the Rust uploader
    raw = await request.body()
    if request.headers.get("content-encoding", "").lower() == "gzip":
        raw = _bounded_gunzip(raw)

    try:
        payload_dict = json.loads(raw)
        payload = EdrEventsIn(**payload_dict)
    except (json.JSONDecodeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"invalid payload: {e}")

    enforce_node_scope(auth, payload.agent_id)
    agent = await db.get(EndpointAgent, payload.agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    if auth.client_id and agent.client_id != auth.client_id:
        raise HTTPException(status_code=403, detail="agent does not belong to this client")

    if len(payload.events) > MAX_BATCH:
        raise HTTPException(
            status_code=413,
            detail=f"batch too large ({len(payload.events)} > {MAX_BATCH})",
        )

    accepted = 0
    chain_match_count = 0
    detection_events: list[dict] = []
    trust_on = trust_configured()
    enrolled_at = getattr(agent, "created_at", None)

    # Ancestry comes from the per-agent cached index (process_tree), which is
    # fed with this batch's own process events as they are staged so a parent
    # started earlier in the batch is visible to later children.
    window_start = datetime.utcnow() - timedelta(hours=24)

    async def ancestry_fetcher(pid: int) -> list[dict]:
        return await ancestors_for(agent.id, pid, db=db)

    for ev in payload.events:
        # Map kind -> category/severity
        category = _event_category(ev.kind)
        severity = _event_severity(ev.kind)

        ts = parse_agent_ts(ev.at)

        details = {
            "kind": ev.kind,
            "pid": ev.pid,
            "ppid": ev.ppid,
            "process_name": ev.process_name,
            "process_path": ev.process_path,
            "command_line": ev.command_line,
            "user": ev.user,
            "target": ev.target,
            "extra": ev.extra or {},
        }
        parent_path, trust, provisioning = None, None, False
        if trust_on and ev.kind in ("process_start", "process_stop"):
            if ev.kind == "process_stop":
                _ingest_trust.forget(agent.id, ev.pid)
            else:
                parent_path = await _resolve_parent_path(db, agent.id, ev, ts)
                provisioning = in_provisioning_window(enrolled_at, ts)
                trust = _ingest_trust.observe(
                    agent.id, ev.pid, ev.ppid, ev.process_path, ev.command_line,
                    parent_path=parent_path, provisioning=provisioning,
                )
        if parent_path:
            details["parent_path"] = parent_path
        if trust is not None:
            # Auditable: the stored event says why the engine did not judge it.
            details["trusted_by"] = trust.by
            details["trust_reason"] = trust.reason
            if trust.reason == "installer":
                details["provisioning"] = True

        row = AgentEvent(
            agent_id=agent.id,
            client_id=agent.client_id,
            category=category,
            severity=severity,
            title=_event_title(ev),
            details=details,
            timestamp=ts,
        )
        db.add(row)
        accepted += 1
        if category == EventCategory.process and ts is not None and ts >= window_start:
            feed_event(agent.id, ts, row.title, details)

        # Field names are the ones edr_events.translate_edr_event reads.
        detection_events.append({
            "kind": ev.kind,
            "severity": severity.value,
            "timestamp": ts.isoformat(),
            "pid": ev.pid,
            "ppid": ev.ppid,
            "process_name": ev.process_name,
            "process_path": ev.process_path,
            "command_line": ev.command_line,
            "user": ev.user,
            "target": ev.target,
            # registry value, image path, ... -- see edr_events
            "extra": ev.extra if isinstance(ev.extra, dict) else {},
            **({"parent_path": parent_path} if parent_path else {}),
            **({
                "trusted_by": trust.by,
                "trust_reason": trust.reason,
                **({"provisioning": True} if trust.reason == "installer" else {}),
            } if trust is not None else {}),
        })

        # Only run chain detection on process starts — the ancestry lookup is
        # expensive and the other event kinds don't drive chain rules.
        if ev.kind == "process_start":
            matches = await evaluate_event(
                db, agent, ev.model_dump(), ancestry_fetcher,
            )
            chain_match_count += len(matches)

    await db.commit()

    # Deliver the batch to the Sigma correlation engine. Without this the
    # events were stored and charted but never evaluated against any rule.
    await publish_agent_batch(
        client_id=agent.client_id,
        agent_id=agent.id,
        hostname=agent.hostname,
        events=detection_events,
    )

    # Fan out a live-dashboard event so widgets refresh
    try:
        await event_bus.publish("edr.batch", {
            "client_id": agent.client_id,
            "agent_id": agent.id,
            "hostname": agent.hostname,
            "accepted": accepted,
            "dropped": payload.events_dropped_total,
            "chain_matches": chain_match_count,
        })
    except Exception as e:  # pragma: no cover
        logger.debug("edr.batch publish failed: %s", e)

    return EdrEventsOut(
        accepted=accepted,
        dropped=payload.events_dropped_total,
        chain_matches=chain_match_count,
    )


# Server-side view of the process tree, used only to stamp stored events with
# the trust verdict (the correlation engine keeps its own for the other routes).
_ingest_trust = TrustResolver()


async def _resolve_parent_path(db, agent_id: str, ev, ts) -> str | None:
    """Path of the parent of a process start.

    Order: what the server itself saw start (the agent's claim is least
    trusted), then the stored history, then the `parent_path` the agent sent
    in `extra`. A parent that started before the agent and was never stored
    can only come from the agent."""
    claimed = ev.extra.get("parent_path") if isinstance(ev.extra, dict) else None
    ppid = ev.ppid
    if ppid in (None, 0):
        return claimed or None
    known = _ingest_trust.parent_path(agent_id, ppid)
    if known:
        return known
    if not _ingest_trust.known_miss(agent_id, ppid):
        found = await resolve_parent_from_db(db, agent_id, ppid, before=ts)
        if found and found[0]:
            _ingest_trust.seed(agent_id, ppid, found[0], found[1])
            return found[0]
        _ingest_trust.note_miss(agent_id, ppid)
    return claimed if isinstance(claimed, str) and claimed else None


def _event_category(kind: str) -> EventCategory:
    mapping = {
        "process_start": EventCategory.process,
        "process_stop": EventCategory.process,
        "image_load": EventCategory.process,
        "tcp_connect": EventCategory.network,
        "tcp_accept": EventCategory.network,
        "dns_query": EventCategory.network,
        "file_create": EventCategory.fim,
        "file_write": EventCategory.fim,
        "file_delete": EventCategory.fim,
        "registry_set": EventCategory.breadcrumb,
        "registry_delete": EventCategory.breadcrumb,
        "amsi_scan": EventCategory.forensic,
    }
    return mapping.get(kind, EventCategory.breadcrumb)


def _event_severity(kind: str) -> EventSeverity:
    if kind in ("amsi_scan",):
        return EventSeverity.high
    if kind in ("file_delete", "registry_delete"):
        return EventSeverity.medium
    return EventSeverity.info


def _event_title(ev: EdrEventIn) -> str:
    name = ev.process_name or "?"
    if ev.kind == "process_start":
        return f"proc_start: {name} (pid={ev.pid})"
    if ev.kind == "process_stop":
        return f"proc_stop: pid={ev.pid}"
    if ev.kind in ("tcp_connect", "tcp_accept"):
        return f"{ev.kind}: {name or ''} -> {ev.target or '?'}"
    if ev.kind.startswith("file_"):
        return f"{ev.kind}: {ev.target or '?'}"
    if ev.kind.startswith("registry_"):
        return f"{ev.kind}: {ev.target or '?'}"
    return f"{ev.kind}: {name}"


# ---------------------------------------------------------------------------
# Query endpoints
# ---------------------------------------------------------------------------

@router.get("/process-tree")
async def get_process_tree(
    agent_id: str = Query(...),
    pid: int = Query(...),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_analyst),
):
    agent = await db.get(EndpointAgent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    if agent.client_id != auth.client_id:
        raise HTTPException(status_code=403, detail="forbidden")

    return await build_process_tree(db, agent_id, pid)


@router.get("/chains")
async def list_chain_matches(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_analyst),
):
    """Recent chain-rule incidents for this client."""
    stmt = (
        select(Incident)
        .where(
            and_(
                Incident.client_id == auth.client_id,
                Incident.source.like("edr-chain:%"),
            )
        )
        .order_by(Incident.detected_at.desc())
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "title": r.title,
            "description": r.description,
            "severity": r.severity,
            "status": r.status,
            "source": r.source,
            "mitre_technique": r.mitre_technique,
            "mitre_tactic": r.mitre_tactic,
            "ai_analysis": r.ai_analysis,
            "detected_at": r.detected_at.isoformat() if r.detected_at else None,
        }
        for r in rows
    ]


@router.get("/host-monitor/status")
async def host_monitor_status(
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_analyst),
):
    """Check if the built-in host monitor is running and return its agent info."""
    agent = await db.get(EndpointAgent, HOST_MONITOR_AGENT_ID)
    return {
        "running": host_monitor._running,
        "agent_id": HOST_MONITOR_AGENT_ID,
        "registered": agent is not None,
        "hostname": agent.hostname if agent else None,
        "status": agent.status.value if agent else None,
        "last_heartbeat": agent.last_heartbeat.isoformat() if agent and agent.last_heartbeat else None,
        "known_pids": len(host_monitor._known_pids),
    }


@router.get("/events/recent")
async def recent_events(
    agent_id: str = Query(...),
    minutes: int = 15,
    limit: int = 200,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_analyst),
):
    agent = await db.get(EndpointAgent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    if agent.client_id != auth.client_id:
        raise HTTPException(status_code=403, detail="forbidden")

    since = datetime.utcnow() - timedelta(minutes=minutes)
    stmt = (
        select(AgentEvent)
        .where(
            and_(
                AgentEvent.agent_id == agent_id,
                AgentEvent.timestamp >= since,
            )
        )
        .order_by(AgentEvent.timestamp.desc())
        .limit(limit)
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": r.id,
            "category": r.category.value if r.category else None,
            "severity": r.severity.value if r.severity else None,
            "title": r.title,
            "details": r.details,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Response endpoints (admin only)
# ---------------------------------------------------------------------------

QUARANTINE_DIR = Path.home() / ".aegis" / "quarantine"
XOR_KEY = 0xAA  # Simple XOR obfuscation to prevent accidental execution


class KillProcessRequest(BaseModel):
    pid: int


class QuarantineFileRequest(BaseModel):
    path: str


@router.post("/kill-process")
async def kill_process(
    body: KillProcessRequest,
    auth: AuthContext = Depends(require_admin),
):
    """Kill a process by PID. Admin only."""
    pid = body.pid
    try:
        proc = psutil.Process(pid)
        proc_name = proc.name()
        refusal = _protected_process_reason(proc)
        if refusal:
            logger.warning("EDR kill-process REFUSED: pid=%d name=%s (%s) by user=%s",
                           pid, proc_name, refusal, auth.user_id or auth.client_id)
            raise HTTPException(status_code=403, detail=f"Refusing to kill pid {pid}: {refusal}")
        proc.kill()
        logger.warning("EDR kill-process: pid=%d name=%s by user=%s", pid, proc_name, auth.user_id or auth.client_id)

        try:
            await event_bus.publish_high("edr.event", {
                "type": "process_killed",
                "pid": pid,
                "process_name": proc_name,
                "killed_by": auth.user_id or auth.client_id,
                "timestamp": datetime.utcnow().isoformat(),
            })
        except Exception:
            pass

        return {"success": True, "pid": pid, "process_name": proc_name}
    except HTTPException:
        raise
    except psutil.NoSuchProcess:
        raise HTTPException(status_code=404, detail=f"Process {pid} not found")
    except psutil.AccessDenied:
        raise HTTPException(status_code=403, detail=f"Access denied killing process {pid}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to kill process: {e}")


@router.post("/quarantine-file")
async def quarantine_file(
    body: QuarantineFileRequest,
    auth: AuthContext = Depends(require_admin),
):
    """Move a file to quarantine with XOR obfuscation. Admin only."""
    file_path = Path(body.path)

    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"File not found: {body.path}")
    if not file_path.is_file():
        raise HTTPException(status_code=400, detail="Path is not a file")

    # Prevent quarantining what the platform (or the host) needs to keep running.
    refusal = _protected_path_reason(file_path)
    if refusal:
        logger.warning("EDR quarantine REFUSED: %s (%s) by user=%s",
                       body.path, refusal, auth.user_id or auth.client_id)
        raise HTTPException(status_code=403, detail=f"Cannot quarantine this file: {refusal}")
    if file_path.stat().st_size > MAX_QUARANTINE_BYTES:
        raise HTTPException(status_code=413, detail="File is too large to quarantine through the API")

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    quarantine_name = f"{ts}_{file_path.name}.quarantine"
    quarantine_path = QUARANTINE_DIR / quarantine_name

    try:
        # Read, XOR-obfuscate, write to quarantine
        raw = file_path.read_bytes()
        obfuscated = bytes(b ^ XOR_KEY for b in raw)
        quarantine_path.write_bytes(obfuscated)

        # Write metadata sidecar
        meta_path = quarantine_path.with_suffix(".quarantine.meta")
        import json as _json
        meta_path.write_text(_json.dumps({
            "original_path": str(file_path),
            "original_size": len(raw),
            "quarantined_at": datetime.utcnow().isoformat(),
            "quarantined_by": auth.user_id or auth.client_id,
            "xor_key": XOR_KEY,
        }, indent=2))

        # Remove original
        file_path.unlink()

        logger.warning(
            "EDR quarantine: %s -> %s by user=%s",
            body.path, quarantine_path, auth.user_id or auth.client_id,
        )

        try:
            await event_bus.publish_high("edr.event", {
                "type": "file_quarantined",
                "original_path": body.path,
                "quarantine_path": str(quarantine_path),
                "quarantined_by": auth.user_id or auth.client_id,
                "timestamp": datetime.utcnow().isoformat(),
            })
        except Exception:
            pass

        return {
            "success": True,
            "original_path": body.path,
            "quarantine_path": str(quarantine_path),
            "original_size": len(raw),
        }
    except PermissionError:
        raise HTTPException(status_code=403, detail=f"Permission denied: {body.path}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Quarantine failed: {e}")


# ---------------------------------------------------------------------------
# Chain rules listing
# ---------------------------------------------------------------------------

@router.get("/rules")
async def list_rules(
    auth: AuthContext = Depends(require_analyst),
):
    """List all active chain detection rules (ancestry + cmd_pattern)."""
    from app.services.attack_chain_detector import RULES as ANCESTRY_RULES
    rules = []

    for fn in ANCESTRY_RULES:
        rules.append({
            "rule_id": fn.__name__,
            "type": "ancestry_chain",
            "description": (fn.__doc__ or "").strip() or fn.__name__,
        })

    for cpr in CMD_PATTERN_RULES:
        rules.append({
            "rule_id": cpr.rule_id,
            "type": "cmd_pattern",
            "title": cpr.title,
            "mitre_technique": cpr.mitre_technique,
            "mitre_tactic": cpr.mitre_tactic,
            "severity": cpr.severity,
            "description": cpr.description,
        })

    return {"total": len(rules), "rules": rules}
