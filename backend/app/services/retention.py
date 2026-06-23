"""AEGIS data-retention service (v1.6.2).

Two APScheduler jobs registered on the global `scheduled_scanner.scheduler`:

1. nightly_retention_purge (cron 03:00) — DELETE incidents older than
   AEGIS_RETENTION_DAYS where status IN ('resolved','auto_responded'). Same
   for attacker_profiles and honeypot_interactions older than the cutoff.
2. hourly_stuck_incident_closer (interval 1h) — UPDATE incidents older than
   24h whose status='investigating' AND source_ip already in threat_intel
   (i.e. already blocked) to status='resolved' with resolved_at=now().

Both jobs honor AEGIS_RETENTION_DRY_RUN=1 (logs intended changes without
mutating). All deletions are appended to ~/.aegis/retention-audit.jsonl so
operators can replay or audit purges.
"""
import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path

from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import delete, select, update

from app.database import async_session
from app.models.incident import Incident
from app.models.attacker_profile import AttackerProfile
from app.models.honeypot import HoneypotInteraction
from app.models.threat_intel import ThreatIntel

logger = logging.getLogger("aegis.retention")

RETENTION_DAYS = int(os.environ.get("AEGIS_RETENTION_DAYS", "90"))
STUCK_CLOSER_HOURS = int(os.environ.get("AEGIS_STUCK_CLOSER_HOURS", "24"))
DRY_RUN = os.environ.get("AEGIS_RETENTION_DRY_RUN", "0").strip().lower() in {"1", "true", "yes"}
AUDIT_LOG_PATH = Path(os.environ.get(
    "AEGIS_RETENTION_AUDIT_LOG",
    str(Path.home() / ".aegis" / "retention-audit.jsonl"),
))


def _audit(event: dict) -> None:
    """Append a JSONL audit record. Best-effort; never raises."""
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"ts": datetime.utcnow().isoformat(), **event})
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except Exception as exc:
        logger.debug(f"retention audit log write failed: {exc}")


async def nightly_retention_purge() -> dict:
    """Delete records older than RETENTION_DAYS. Returns count summary."""
    cutoff = datetime.utcnow() - timedelta(days=RETENTION_DAYS)
    summary = {"incidents": 0, "attackers": 0, "honeypot": 0, "dry_run": DRY_RUN, "cutoff": cutoff.isoformat()}
    async with async_session() as db:
        # Incidents — only safely-purgeable terminal states
        if DRY_RUN:
            preview = await db.execute(
                select(Incident.id).where(
                    Incident.detected_at < cutoff,
                    Incident.status.in_(("resolved", "auto_responded")),
                )
            )
            summary["incidents"] = len(preview.all())
        else:
            result = await db.execute(
                delete(Incident).where(
                    Incident.detected_at < cutoff,
                    Incident.status.in_(("resolved", "auto_responded")),
                )
            )
            summary["incidents"] = result.rowcount or 0

        # Attacker profiles — last_seen older than cutoff
        if DRY_RUN:
            preview = await db.execute(
                select(AttackerProfile.id).where(AttackerProfile.last_seen < cutoff)
            )
            summary["attackers"] = len(preview.all())
        else:
            result = await db.execute(
                delete(AttackerProfile).where(AttackerProfile.last_seen < cutoff)
            )
            summary["attackers"] = result.rowcount or 0

        # Honeypot interactions
        if DRY_RUN:
            preview = await db.execute(
                select(HoneypotInteraction.id).where(HoneypotInteraction.timestamp < cutoff)
            )
            summary["honeypot"] = len(preview.all())
        else:
            result = await db.execute(
                delete(HoneypotInteraction).where(HoneypotInteraction.timestamp < cutoff)
            )
            summary["honeypot"] = result.rowcount or 0

        if not DRY_RUN:
            await db.commit()

    _audit({"job": "nightly_retention_purge", **summary})
    if DRY_RUN:
        logger.info(f"retention DRY_RUN: would purge {summary}")
    else:
        logger.info(f"retention purge complete: {summary}")
    return summary


async def hourly_stuck_incident_closer() -> dict:
    """Auto-resolve stuck-investigating incidents where source_ip is already blocked."""
    cutoff = datetime.utcnow() - timedelta(hours=STUCK_CLOSER_HOURS)
    summary = {"closed": 0, "dry_run": DRY_RUN, "cutoff": cutoff.isoformat()}
    async with async_session() as db:
        blocked_q = await db.execute(
            select(ThreatIntel.ioc_value).where(
                ThreatIntel.ioc_type == "ip",
                ThreatIntel.source.in_(("firewall", "tor_exit_nodes", "emerging_threats", "feodo_tracker")),
            )
        )
        blocked_ips = {row[0] for row in blocked_q.all()}
        if not blocked_ips:
            _audit({"job": "hourly_stuck_incident_closer", **summary, "note": "no blocked_ips snapshot"})
            return summary

        candidates_q = await db.execute(
            select(Incident.id, Incident.source_ip).where(
                Incident.status == "investigating",
                Incident.detected_at < cutoff,
                Incident.source_ip.in_(blocked_ips),
            )
        )
        candidates = candidates_q.all()
        summary["closed"] = len(candidates)
        if not candidates:
            _audit({"job": "hourly_stuck_incident_closer", **summary})
            return summary

        if not DRY_RUN:
            ids = [row[0] for row in candidates]
            await db.execute(
                update(Incident)
                .where(Incident.id.in_(ids))
                .values(status="resolved", resolved_at=datetime.utcnow())
            )
            await db.commit()

    _audit({"job": "hourly_stuck_incident_closer", **summary})
    if DRY_RUN:
        logger.info(f"stuck closer DRY_RUN: would close {summary['closed']} incidents")
    else:
        logger.info(f"stuck closer complete: closed {summary['closed']} incidents")
    return summary


async def start() -> None:
    """Register retention jobs onto the global scheduled_scanner.scheduler."""
    try:
        from app.services.scheduled_scanner import scheduled_scanner
        sched = scheduled_scanner.scheduler
        sched.add_job(
            nightly_retention_purge,
            CronTrigger(hour=3, minute=0),
            id="nightly_retention_purge",
            replace_existing=True,
            max_instances=1,
        )
        sched.add_job(
            hourly_stuck_incident_closer,
            IntervalTrigger(hours=1),
            id="hourly_stuck_incident_closer",
            replace_existing=True,
            max_instances=1,
        )
        logger.info(
            f"retention service started: RETENTION_DAYS={RETENTION_DAYS}, "
            f"STUCK_CLOSER_HOURS={STUCK_CLOSER_HOURS}, DRY_RUN={DRY_RUN}, "
            f"audit_log={AUDIT_LOG_PATH}"
        )
    except Exception as exc:
        logger.error(f"retention service failed to start: {exc}")


async def stop() -> None:
    """Remove retention jobs from the global scheduler."""
    try:
        from app.services.scheduled_scanner import scheduled_scanner
        for job_id in ("nightly_retention_purge", "hourly_stuck_incident_closer"):
            try:
                scheduled_scanner.scheduler.remove_job(job_id)
            except Exception:
                pass
        logger.info("retention service stopped")
    except Exception as exc:
        logger.error(f"retention service stop failed: {exc}")
