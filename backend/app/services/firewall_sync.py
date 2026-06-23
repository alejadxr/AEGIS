import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, Set

from sqlalchemy import select, exists
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session
from app.core.firewall_client import firewall_client
from app.core.ip_blocker import ip_blocker_service
from app.core.attack_detector import _is_safe_ip
from app.models.attacker_profile import AttackerProfile
from app.models.threat_intel import ThreatIntel
from app.models.incident import Incident
from app.models.action import Action
from app.models.client import Client
from app.config import settings
from app.modules.phantom.safety import should_skip_profile

logger = logging.getLogger("aegis.firewall_sync")

SYNC_INTERVAL_SECONDS = 300  # 5 minutes

# v1.6.2: track when each local_only IP first appeared so we can auto-evict
# entries that have been "local-only" for > AEGIS_STALE_LOCAL_EVICT_HOURS
# (default 24). Without this, IPs blocked manually or via legacy paths sit in
# blocked_ips.txt forever, generating warning logs every sync cycle.
import os as _os_v162
_LOCAL_ONLY_FIRST_SEEN: dict[str, datetime] = {}
_STALE_LOCAL_EVICT_HOURS = int(_os_v162.environ.get("AEGIS_STALE_LOCAL_EVICT_HOURS", "24"))


async def _get_demo_client_id(db: AsyncSession) -> Optional[str]:
    # Get the first (primary) client — works for single-tenant and multi-tenant
    result = await db.execute(select(Client).limit(1))
    client = result.scalar_one_or_none()
    return client.id if client else None


def _threat_level_to_severity(threat_level: str) -> str:
    mapping = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "info",
    }
    return mapping.get((threat_level or "").upper(), "medium")


async def _sync_attackers(db: AsyncSession, client_id: str) -> int:
    attackers = await firewall_client.get_attackers()
    if not attackers:
        return 0

    count = 0
    for atk in attackers:
        ip = atk.get("ip")
        if not ip:
            continue

        # Skip safe/documentation/non-routable IPs — prevents synthetic profiles
        if should_skip_profile(ip):
            continue

        result = await db.execute(
            select(AttackerProfile).where(
                AttackerProfile.client_id == client_id,
                AttackerProfile.source_ip == ip,
            )
        )
        profile = result.scalar_one_or_none()

        first_seen_str = atk.get("first_seen")
        last_seen_str = atk.get("last_seen")
        first_seen = datetime.fromisoformat(first_seen_str).replace(tzinfo=None) if first_seen_str else datetime.utcnow()
        last_seen = datetime.fromisoformat(last_seen_str).replace(tzinfo=None) if last_seen_str else datetime.utcnow()

        intel = atk.get("intel") or {}
        geo_data = {
            "country": intel.get("country"),
            "city": intel.get("city"),
            "isp": intel.get("isp"),
        }

        attack_types = atk.get("attack_types", [])
        stats = atk.get("stats") or {}
        ai_info = atk.get("ai") or {}
        assessment = ai_info.get("reasoning") or f"Threat level: {atk.get('threat_level', 'LOW')}"

        if profile is None:
            profile = AttackerProfile(
                client_id=client_id,
                source_ip=ip,
                known_ips=[ip],
                tools_used=[],
                techniques=attack_types,
                sophistication=_threat_level_to_severity(atk.get("threat_level", "LOW")),
                geo_data=geo_data,
                first_seen=first_seen,
                last_seen=last_seen,
                total_interactions=stats.get("total_attempts", 0),
                ai_assessment=assessment,
            )
            db.add(profile)
        else:
            profile.last_seen = last_seen
            profile.total_interactions = stats.get("total_attempts", profile.total_interactions)
            profile.techniques = list(set((profile.techniques or []) + attack_types))
            profile.geo_data = geo_data
            profile.ai_assessment = assessment
            profile.sophistication = _threat_level_to_severity(atk.get("threat_level", "LOW"))

        count += 1

    await db.commit()
    return count


async def _sync_blocked_ips(db: AsyncSession) -> int:
    blocked = await firewall_client.get_blocked()
    if not blocked:
        return 0

    count = 0
    for ip in blocked:
        if not ip:
            continue

        result = await db.execute(
            select(ThreatIntel).where(
                ThreatIntel.ioc_type == "ip",
                ThreatIntel.ioc_value == ip,
                ThreatIntel.source == "firewall",
            )
        )
        existing = result.scalar_one_or_none()

        if existing is None:
            intel = ThreatIntel(
                ioc_type="ip",
                ioc_value=ip,
                threat_type="blocked_attacker",
                confidence=0.9,
                source="firewall",
                tags=["blocked", "firewall", "iptables"],
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
            )
            db.add(intel)
        else:
            existing.last_seen = datetime.utcnow()

        count += 1

    await db.commit()
    return count


async def _sync_auto_response_events(db: AsyncSession, client_id: str) -> int:
    events = await firewall_client.get_events()
    if not events:
        return 0

    # Operational events that should NOT create incidents
    _SKIP_EVENT_TYPES = {"startup", "shutdown", "ip_blocked", "ip_unblocked", "config_reload", "health_check"}

    count = 0
    for event in events:
        ip = event.get("ip") or event.get("source_ip")
        event_type = event.get("type") or event.get("event_type", "firewall_alert")

        # Skip operational events — they are not security incidents
        if event_type in _SKIP_EVENT_TYPES:
            continue

        # Skip events from safe/internal IPs (own scans, localhost)
        if ip and ip in ("127.0.0.1", "::1", "localhost", ""):
            continue

        description = event.get("description") or event.get("reason") or f"Firewall detected: {event_type}"
        severity = _threat_level_to_severity(event.get("threat_level") or event.get("severity") or "medium")

        if ip:
            result = await db.execute(
                select(Incident).where(
                    Incident.client_id == client_id,
                    Incident.source_ip == ip,
                    Incident.source == "firewall",
                )
            )
            if result.scalar_one_or_none():
                continue

        incident = Incident(
            client_id=client_id,
            title=f"Firewall: {event_type.replace('_', ' ').title()} from {ip or 'unknown'}",
            description=description,
            severity=severity,
            status="open",
            source="firewall",
            source_ip=ip,
            ai_analysis={"firewall_event": event},
            raw_alert=event,
            detected_at=datetime.utcnow(),
        )
        db.add(incident)
        count += 1

    if count > 0:
        await db.commit()

    return count


RECONCILE_GRACE_MINUTES = 10  # don't auto-resolve incidents younger than this


async def _reconcile_incidents(db: AsyncSession, pi_blocked_ips: Set[str]) -> int:
    """
    Auto-resolve incidents whose source_ip has been removed from the Pi blocklist.

    Conditions for auto-resolution:
      - Incident status is 'open' or 'investigating'
      - Incident has a related Action with action_type='block_ip' (i.e. was actively blocked)
      - Incident source_ip is NOT currently in the Pi blocklist
      - Incident is older than RECONCILE_GRACE_MINUTES (avoids resolving during transient gaps)

    The resolution note is stored in ai_analysis['resolution_note'] because the
    Incident model has no dedicated text column for it.
    """
    grace_cutoff = datetime.utcnow() - timedelta(minutes=RECONCILE_GRACE_MINUTES)

    stmt = (
        select(Incident)
        .where(
            Incident.status.in_(("open", "investigating")),
            Incident.source_ip.is_not(None),
            Incident.detected_at < grace_cutoff,
            exists().where(
                Action.incident_id == Incident.id,
                Action.action_type == "block_ip",
            ),
        )
    )
    result = await db.execute(stmt)
    candidates = result.scalars().all()

    reconciled = 0
    for incident in candidates:
        if incident.source_ip in pi_blocked_ips:
            # IP is still enforced — leave the incident alone
            continue

        # IP is gone from Pi blocklist: auto-resolve
        note = (
            "Auto-resolved: IP no longer in firewall blocklist "
            "(likely manually unblocked or TTL expired)."
        )
        incident.status = "resolved"
        incident.resolved_at = datetime.utcnow()
        # Merge note into ai_analysis without overwriting existing keys
        existing_analysis = incident.ai_analysis or {}
        existing_analysis["resolution_note"] = note
        incident.ai_analysis = existing_analysis
        reconciled += 1

    if reconciled > 0:
        await db.commit()

    return reconciled


async def _pull_blocklist_from_pi() -> dict:
    """Reconcile Pi blocklist into the local blocked_ips.txt (Pi -> Mac Pro pull).

    For every IP on the Pi that is NOT yet in the local middleware blocklist,
    append it via ip_blocker_service.block_ip() — this keeps the in-memory set,
    the persisted file, and the 403 middleware in sync. Safe IPs (per
    AEGIS_SAFE_IPS / private ranges) and CIDR entries are skipped. Local-only
    entries are never removed; they only emit a warning so a human can review.
    """
    pi_blocked = await firewall_client.get_blocked() or []
    local_blocked = set(ip_blocker_service.list_blocked())
    pi_set = {ip for ip in pi_blocked if ip and "/" not in ip}

    added = 0
    skipped_safe = 0
    for ip in pi_set - local_blocked:
        if _is_safe_ip(ip):
            logger.warning(f"firewall_sync pull: skipping safe IP {ip} from Pi blocklist")
            skipped_safe += 1
            continue
        ip_blocker_service.block_ip(ip)
        added += 1

    local_only = local_blocked - pi_set
    now = datetime.utcnow()
    evicted = 0
    if local_only:
        # v1.6.2: first-seen tracking + auto-eviction after grace window.
        for ip in local_only:
            _LOCAL_ONLY_FIRST_SEEN.setdefault(ip, now)
        cutoff = now - timedelta(hours=_STALE_LOCAL_EVICT_HOURS)
        for ip in list(local_only):
            first_seen = _LOCAL_ONLY_FIRST_SEEN.get(ip, now)
            if first_seen < cutoff:
                try:
                    ip_blocker_service.unblock_ip(ip)
                    _LOCAL_ONLY_FIRST_SEEN.pop(ip, None)
                    evicted += 1
                    logger.info(
                        f"firewall_sync pull: auto-evicted stale local-only IP "
                        f"{ip} (first seen {first_seen.isoformat()}, threshold "
                        f"{_STALE_LOCAL_EVICT_HOURS}h)"
                    )
                except Exception as exc:
                    logger.warning(f"firewall_sync pull: failed to evict {ip}: {exc}")
        # Clear tracker entries for IPs no longer local_only
        for ip in list(_LOCAL_ONLY_FIRST_SEEN.keys()):
            if ip not in local_only:
                _LOCAL_ONLY_FIRST_SEEN.pop(ip, None)
        remaining = {ip for ip in local_only if _LOCAL_ONLY_FIRST_SEEN.get(ip, now) >= cutoff}
        if remaining:
            logger.info(
                f"firewall_sync pull: {len(remaining)} IP(s) in local file but not "
                f"on Pi (within {_STALE_LOCAL_EVICT_HOURS}h grace window): "
                f"{sorted(remaining)[:10]}"
            )

    return {"added": added, "skipped_safe": skipped_safe, "local_only": len(local_only), "evicted": evicted}


async def run_sync():
    async with async_session() as db:
        try:
            client_id = await _get_demo_client_id(db)
            if not client_id:
                logger.warning("Firewall sync: demo client not found, skipping")
                return

            attackers_synced = await _sync_attackers(db, client_id)
            blocked_synced = await _sync_blocked_ips(db)
            events_synced = await _sync_auto_response_events(db, client_id)

            reconciled = 0
            if settings.AEGIS_AUTO_RECONCILE_INCIDENTS:
                # Re-fetch the current Pi blocklist as a set for O(1) lookup
                pi_blocked: list = await firewall_client.get_blocked() or []
                pi_blocked_set: Set[str] = set(filter(None, pi_blocked))
                reconciled = await _reconcile_incidents(db, pi_blocked_set)
                if reconciled:
                    logger.info(f"Reconciled {reconciled} incidents (auto-resolved)")

            pull_result = {}
            if settings.AEGIS_FIREWALL_PULL_FROM_PI:
                try:
                    pull_result = await _pull_blocklist_from_pi()
                    logger.info(f"firewall_sync pull: {pull_result}")
                except Exception as e:
                    logger.error(f"firewall_sync pull failed: {e}", exc_info=True)

            logger.info(
                f"Firewall sync: {attackers_synced} attackers, "
                f"{blocked_synced} blocked IPs, {events_synced} new incidents, "
                f"{reconciled} reconciled, pull={pull_result or 'off'}"
            )
        except Exception as e:
            logger.error(f"Firewall sync failed: {e}", exc_info=True)


class FirewallSyncService:
    def __init__(self):
        self._task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self):
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())
        logger.info(f"Firewall sync service started (interval: {SYNC_INTERVAL_SECONDS}s)")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Firewall sync service stopped")

    async def _loop(self):
        await asyncio.sleep(15)
        while self._running:
            await run_sync()
            await asyncio.sleep(SYNC_INTERVAL_SECONDS)

    async def trigger_manual_sync(self) -> dict:
        try:
            await run_sync()
            return {"status": "ok", "message": "Firewall sync completed"}
        except Exception as e:
            return {"status": "error", "message": str(e)}


firewall_sync = FirewallSyncService()
