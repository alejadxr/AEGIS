"""AEGIS data-retention service (v1.6.2).

Two APScheduler jobs registered on the global `scheduled_scanner.scheduler`:

1. nightly_retention_purge (cron 03:00) — DELETE incidents older than
   AEGIS_RETENTION_DAYS where status IN ('resolved','auto_responded'). Same
   for attacker_profiles and honeypot_interactions older than the cutoff.
2. hourly_stuck_incident_closer (interval 1h) — closes ACTIVE incidents
   (open / investigating / auto_responded) that have shown no activity for
   AEGIS_INCIDENT_AUTOCLOSE_DAYS, setting status='auto_closed' plus a reason
   in ai_analysis.auto_close. It deliberately does not look at threat-feed
   membership: that says nothing about whether an incident is still live (the
   old rule matched 0 of 241 stuck incidents in production).

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
from sqlalchemy import delete, func, select, update

from app.database import async_session
from app.models.incident import Incident
from app.models.action import Action
from app.models.audit_log import AuditLog
from app.models.attacker_profile import AttackerProfile
from app.models.honeypot import HoneypotInteraction

logger = logging.getLogger("aegis.retention")

RETENTION_DAYS = int(os.environ.get("AEGIS_RETENTION_DAYS", "90"))
# 7 days: longer than the 24h dedup window and any weekend, so a campaign that
# pauses for a few days is not closed under the operator's feet, yet short
# enough that August's noise cannot linger. Criticals get twice as long because
# a wrongly closed critical costs far more than a stale one.
AUTOCLOSE_DAYS = int(os.environ.get("AEGIS_INCIDENT_AUTOCLOSE_DAYS", "7"))
AUTOCLOSE_CRITICAL_DAYS = int(os.environ.get("AEGIS_INCIDENT_AUTOCLOSE_CRITICAL_DAYS", "14"))
# incidents.status is VARCHAR(20); "auto_closed" fits (11) and, unlike "resolved",
# can never be mistaken for a human triage decision.
AUTOCLOSED_STATUS = "auto_closed"
ACTIVE_STATUSES = ("open", "investigating", "auto_responded")
PURGEABLE_STATUSES = ("resolved", "auto_responded", AUTOCLOSED_STATUS)
# Cumulative since process start; the closer's per-run summary is also returned.
STATS = {"runs": 0, "auto_closed_total": 0, "last_run": None, "last_closed": 0, "last_kept_active": 0}
# Scans get a tighter window than incidents: the full-scan nmap timeout is 600s,
# so anything still "running" after hours is dead, not slow.
SCAN_STUCK_HOURS = int(os.environ.get("AEGIS_SCAN_STUCK_HOURS", "3"))
PURGE_BATCH_SIZE = int(os.environ.get("AEGIS_RETENTION_BATCH_SIZE", "500"))
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


async def _purge_incidents(db, cutoff: datetime) -> int:
    """Delete expired terminal incidents plus their FK children, in bounded batches.

    actions.incident_id (NOT NULL) and audit_log.incident_id reference
    incidents without ON DELETE, so deleting an incident that still has either
    raises ForeignKeyViolationError and aborts the whole nightly purge.
    Actions are deleted; audit_log rows are kept with incident_id set NULL.
    (ransomware_events / av_detections are ON DELETE SET NULL and need nothing.)
    Children go first, in the same transaction as their parents; the caller commits.
    """
    total = 0
    while True:
        ids = [row[0] for row in (await db.execute(
            select(Incident.id).where(
                Incident.detected_at < cutoff,
                Incident.status.in_(PURGEABLE_STATUSES),
            ).limit(PURGE_BATCH_SIZE)
        )).all()]
        if not ids:
            return total
        await db.execute(delete(Action).where(Action.incident_id.in_(ids)))
        # The audit trail outlives the incident: detach rather than delete.
        await db.execute(update(AuditLog).where(AuditLog.incident_id.in_(ids)).values(incident_id=None))
        result = await db.execute(delete(Incident).where(Incident.id.in_(ids)))
        total += result.rowcount or 0


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
                    Incident.status.in_(PURGEABLE_STATUSES),
                )
            )
            summary["incidents"] = len(preview.all())
        else:
            summary["incidents"] = await _purge_incidents(db, cutoff)

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


def _parse_ts(value) -> "datetime | None":
    try:
        return datetime.fromisoformat(str(value).replace("Z", "")).replace(tzinfo=None)
    except (ValueError, TypeError):
        return None


def _incident_host(incident) -> "str | None":
    raw = incident.raw_alert if isinstance(incident.raw_alert, dict) else {}
    return raw.get("host") or raw.get("hostname")


async def hourly_stuck_incident_closer() -> dict:
    """Close active incidents that have gone quiet.

    An incident is closed when it is open/investigating/auto_responded and
    NOTHING related to it happened inside its window (AUTOCLOSE_DAYS, doubled
    for criticals). "Related activity" is whatever AEGIS can actually join on:
      - ai_analysis.dedup.last_seen: repeat triggers fold into the existing
        incident (correlation_engine._escalate_incident) without touching
        detected_at, so an old incident can still be accumulating hits;
      - any newer incident from the same source_ip, or the same host for
        host-scoped detections (source_ip is NULL there);
      - a newer action or audit_log row on the incident itself.
    Statuses a human set (resolved, false_positive, ...) are never selected.
    """
    now = datetime.utcnow()
    window = timedelta(days=AUTOCLOSE_DAYS)
    crit_window = timedelta(days=max(AUTOCLOSE_CRITICAL_DAYS, AUTOCLOSE_DAYS))
    summary = {"closed": 0, "kept_active": 0, "dry_run": DRY_RUN,
               "cutoff": (now - window).isoformat()}
    async with async_session() as db:
        candidates = (await db.execute(
            select(Incident).where(
                Incident.status.in_(ACTIVE_STATUSES),
                Incident.detected_at < now - window,
            )
        )).scalars().all()
        if not candidates:
            return _finish_closer_run(summary)

        ids = [i.id for i in candidates]
        ips = {i.source_ip for i in candidates if i.source_ip}

        last_by_ip = {ip: ts for ip, ts in (await db.execute(
            select(Incident.source_ip, func.max(Incident.detected_at))
            .where(Incident.source_ip.in_(ips)).group_by(Incident.source_ip)
        )).all()} if ips else {}

        # raw_alert is a plain json column (no operators), so host matching
        # happens in Python over the widest window only.
        last_by_host: dict = {}
        recent = (await db.execute(
            select(Incident.raw_alert, Incident.detected_at)
            .where(Incident.detected_at >= now - crit_window)
        )).all()
        for raw, ts in recent:
            raw = raw if isinstance(raw, dict) else {}
            host = raw.get("host") or raw.get("hostname")
            if host and ts > last_by_host.get(host, datetime.min):
                last_by_host[host] = ts

        last_action = {iid: max(t for t in (c, e) if t) for iid, c, e in (await db.execute(
            select(Action.incident_id, func.max(Action.created_at), func.max(Action.executed_at))
            .where(Action.incident_id.in_(ids)).group_by(Action.incident_id)
        )).all()}
        last_audit = {iid: ts for iid, ts in (await db.execute(
            select(AuditLog.incident_id, func.max(AuditLog.timestamp))
            .where(AuditLog.incident_id.in_(ids)).group_by(AuditLog.incident_id)
        )).all()}

        for inc in candidates:
            days = max(AUTOCLOSE_CRITICAL_DAYS, AUTOCLOSE_DAYS) if inc.severity == "critical" else AUTOCLOSE_DAYS
            dedup = (inc.ai_analysis or {}).get("dedup") or {}
            signals = [
                inc.detected_at,
                _parse_ts(dedup.get("last_seen")),
                last_by_ip.get(inc.source_ip),
                last_by_host.get(_incident_host(inc)),
                last_action.get(inc.id),
                last_audit.get(inc.id),
            ]
            last_activity = max(t for t in signals if t)
            if last_activity >= now - timedelta(days=days):
                summary["kept_active"] += 1
                continue
            summary["closed"] += 1
            if DRY_RUN:
                continue
            analysis = dict(inc.ai_analysis or {})
            analysis["auto_close"] = {
                "reason": f"Auto-closed for inactivity: no activity for {days} days "
                          f"(last activity {last_activity.isoformat()}). Not a human triage decision.",
                "previous_status": inc.status,
                "inactivity_days": days,
                "last_activity": last_activity.isoformat(),
                "closed_at": now.isoformat(),
            }
            inc.ai_analysis = analysis  # reassign so SQLAlchemy sees the JSON change
            inc.status = AUTOCLOSED_STATUS
            inc.resolved_at = now
            _audit({"event": "incident_auto_closed", "incident_id": str(inc.id),
                    "previous_status": analysis["auto_close"]["previous_status"],
                    "severity": inc.severity, "last_activity": last_activity.isoformat()})

        if not DRY_RUN and summary["closed"]:
            await db.commit()

    return _finish_closer_run(summary)


def _finish_closer_run(summary: dict) -> dict:
    STATS["runs"] += 1
    STATS["last_run"] = datetime.utcnow().isoformat()
    STATS["last_closed"] = summary["closed"]
    STATS["last_kept_active"] = summary["kept_active"]
    if not summary["dry_run"]:
        STATS["auto_closed_total"] += summary["closed"]
    _audit({"job": "hourly_stuck_incident_closer", **summary})
    logger.info(
        f"stuck incident closer{' DRY_RUN' if summary['dry_run'] else ''}: "
        f"closed={summary['closed']} kept_active={summary['kept_active']} "
        f"window={AUTOCLOSE_DAYS}d (critical {AUTOCLOSE_CRITICAL_DAYS}d)"
    )
    return summary


async def hourly_stuck_scan_closer() -> dict:
    """Mark scans as failed once they have been 'running' impossibly long.

    A scan row is set to `running` before nmap/nuclei start and only flipped to
    `completed` by the code path that finishes them. If the process dies in
    between — a crash, or simply a `pm2 restart` mid-scan — nothing ever
    revisits the row, so it stays `running` forever. Four had been stuck for
    134-156 hours when this was written.

    That is not just untidy. The Surface console derives "scan in progress" from
    `status == 'running'`, so a zombie row renders as a permanently active scan
    at 50% progress, and an operator watching for their own scan cannot tell it
    apart from a real one. This is the same structural gap the stuck-INCIDENT
    closer above fixes for incidents.

    Uses SCAN_STUCK_HOURS rather than the incident auto-close window: a scan that has run
    longer than the longest legitimate scan is already dead, and the full-scan
    nmap timeout is 600s, so hours of grace is generous by orders of magnitude.
    """
    from app.models.scan import Scan

    summary = {"scanned": 0, "closed": 0, "dry_run": DRY_RUN}
    cutoff = datetime.utcnow() - timedelta(hours=SCAN_STUCK_HOURS)

    async with async_session() as db:
        rows = (await db.execute(
            select(Scan).where(Scan.status == "running", Scan.started_at < cutoff)
        )).scalars().all()
        summary["scanned"] = len(rows)

        for scan in rows:
            age_h = (datetime.utcnow() - scan.started_at).total_seconds() / 3600
            if DRY_RUN:
                logger.info(f"[DRY_RUN] would close stuck scan {scan.id} ({age_h:.1f}h)")
                summary["closed"] += 1
                continue
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()
            scan.error = (
                f"Auto-closed: still 'running' after {age_h:.1f}h "
                f"(threshold {SCAN_STUCK_HOURS}h). The worker did not survive to "
                f"report a result — most likely an API restart mid-scan."
            )
            summary["closed"] += 1
            _audit({
                "event": "stuck_scan_closed",
                "scan_id": str(scan.id),
                "scan_type": scan.scan_type,
                "age_hours": round(age_h, 1),
                "ts": datetime.utcnow().isoformat(),
            })

        if not DRY_RUN and summary["closed"]:
            await db.commit()

    if summary["closed"]:
        logger.info(f"stuck scan closer: closed {summary['closed']} scan(s)")
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
            hourly_stuck_scan_closer,
            IntervalTrigger(hours=1),
            id="hourly_stuck_scan_closer",
            replace_existing=True,
            max_instances=1,
        )
        sched.add_job(
            expire_provisional_blocks,
            IntervalTrigger(minutes=10),
            id="expire_provisional_blocks",
            replace_existing=True,
            max_instances=1,
        )
        logger.info(
            f"retention service started: RETENTION_DAYS={RETENTION_DAYS}, "
            f"AUTOCLOSE_DAYS={AUTOCLOSE_DAYS}, DRY_RUN={DRY_RUN}, "
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
