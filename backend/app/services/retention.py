"""AEGIS data-retention service (v1.6.2).

Two APScheduler jobs registered on the global `scheduled_scanner.scheduler`:

1. nightly_retention_purge (cron 03:00) — DELETE incidents older than
   AEGIS_RETENTION_DAYS where status IN ('resolved','auto_responded'). Same
   for attacker_profiles and honeypot_interactions older than the cutoff.
2. hourly_stuck_incident_closer (interval 1h) — UPDATE incidents older than
   24h whose status IN ('investigating', 'auto_responded') AND source_ip
   already in threat_intel (i.e. already blocked) to status='resolved' with
   resolved_at=now(). 'auto_responded' was added in v1.6.4.x (Fix 5) — it's
   the status fast_triage-sourced incidents get, and without it those
   incidents were structurally orphaned (this job never touched them, and
   firewall_sync._reconcile_incidents didn't either until the same fix).

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
    """Auto-resolve stuck incidents (status 'investigating' or 'auto_responded')
    where source_ip is already blocked.

    v1.6.4.x (Fix 5): widened from 'investigating'-only to also include
    'auto_responded' — fast_triage is the only source that ever sets that
    status, and it was never in this job's WHERE clause, so those incidents
    could never auto-close.
    """
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
                Incident.status.in_(("investigating", "auto_responded")),
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


async def expire_provisional_blocks() -> dict:
    """Lift auto-blocks that AEGIS made on an UNCONFIRMED threat, once expired.

    This is the counterweight to running unattended. When the confirmation gate
    cannot confirm an attack, ai_engine still blocks — parking the decision for
    a human would mean not acting at all — but it stamps
    ``parameters.expires_at`` on the Action. This job is what honours that
    stamp, and without it "provisional" would be a lie: the block would be as
    permanent as a confirmed one and false positives would accumulate silently,
    exactly as 66 of them did before this existed.

    Confirmed blocks carry no expires_at and are never touched here.
    """
    from app.models.action import Action
    from app.core.firewall_client import firewall_client
    from app.core.ip_blocker import ip_blocker_service

    summary = {"scanned": 0, "expired": 0, "failed": 0, "dry_run": DRY_RUN}
    now = datetime.utcnow()

    async with async_session() as db:
        stmt = select(Action).where(
            Action.action_type == "block_ip",
            Action.status.in_(("approved", "executed")),
        )
        rows = (await db.execute(stmt)).scalars().all()

        for action in rows:
            params = action.parameters or {}
            if not params.get("provisional") or params.get("expired_at"):
                continue
            raw_exp = params.get("expires_at")
            if not raw_exp:
                continue
            summary["scanned"] += 1
            try:
                if datetime.fromisoformat(str(raw_exp).replace("Z", "")) > now:
                    continue  # still within its window
            except (ValueError, TypeError):
                logger.warning(
                    f"provisional block {action.id} has unparseable "
                    f"expires_at={raw_exp!r}; leaving it in force"
                )
                continue

            ip = action.target
            if not ip:
                continue
            if DRY_RUN:
                logger.info(f"[DRY_RUN] would expire provisional block on {ip}")
                summary["expired"] += 1
                continue

            try:
                # Lift on the Pi executor first (the enforced layer), then the
                # local 403 blocklist. Order matters: if the remote call fails
                # we keep the local block rather than half-lifting it.
                await firewall_client.unblock_ip(ip)
                try:
                    ip_blocker_service.unblock_ip(ip)
                except Exception as exc:
                    logger.warning(f"local unblock of {ip} failed: {exc}")

                params["expired_at"] = now.isoformat()
                action.parameters = dict(params)   # reassign so SQLAlchemy sees it
                action.status = "expired"
                summary["expired"] += 1
                _audit({
                    "event": "provisional_block_expired",
                    "ip": ip,
                    "action_id": str(action.id),
                    "ts": now.isoformat(),
                })
                logger.info(f"Expired provisional block on {ip}")
            except Exception as exc:
                summary["failed"] += 1
                logger.error(f"failed to expire provisional block on {ip}: {exc}")

        if not DRY_RUN:
            await db.commit()

    if summary["scanned"]:
        logger.info(
            f"provisional block expiry: scanned={summary['scanned']} "
            f"expired={summary['expired']} failed={summary['failed']}"
        )
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
        # Every 10 min, not hourly: this bounds how long a false-positive block
        # outlives its TTL, and it is the only thing that un-does an autonomous
        # mistake when nobody is watching.
        sched.add_job(
            expire_provisional_blocks,
            IntervalTrigger(minutes=10),
            id="expire_provisional_blocks",
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
