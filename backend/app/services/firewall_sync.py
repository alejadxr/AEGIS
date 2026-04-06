import asyncio
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session
from app.core.firewall_client import firewall_client
from app.models.attacker_profile import AttackerProfile
from app.models.threat_intel import ThreatIntel
from app.models.incident import Incident
from app.models.client import Client

logger = logging.getLogger("aegis.firewall_sync")

SYNC_INTERVAL_SECONDS = 300  # 5 minutes


async def _get_demo_client_id(db: AsyncSession) -> Optional[str]:
    result = await db.execute(select(Client).where(Client.slug == "demo"))
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

        result = await db.execute(
            select(AttackerProfile).where(
                AttackerProfile.client_id == client_id,
                AttackerProfile.source_ip == ip,
            )
        )
        profile = result.scalar_one_or_none()

        first_seen_str = atk.get("first_seen")
        last_seen_str = atk.get("last_seen")
        first_seen = datetime.fromisoformat(first_seen_str) if first_seen_str else datetime.utcnow()
        last_seen = datetime.fromisoformat(last_seen_str) if last_seen_str else datetime.utcnow()

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

    count = 0
    for event in events:
        ip = event.get("ip") or event.get("source_ip")
        event_type = event.get("type") or event.get("event_type", "firewall_alert")
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
            logger.info(
                f"Firewall sync: {attackers_synced} attackers, "
                f"{blocked_synced} blocked IPs, {events_synced} new incidents"
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
