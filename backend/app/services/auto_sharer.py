"""
Auto-Sharer — automatically pushes local detections to the threat sharing hub.

Subscribes to:
  - alert_processed (from log_watcher / AI engine)
  - honeypot_interaction (from honeypots)
  - correlation_triggered (from sigma engine)

For each event with a valid source_ip, shares an IOC to the hub.
Deduplicates: won't share the same IP twice within 5 minutes.
"""
import logging
from collections import OrderedDict
from datetime import datetime, timezone

from app.core.bg_tasks import fire_and_forget

logger = logging.getLogger("aegis.auto_sharer")

# Deduplication: don't share the same IOC more than once per 5 min
_DEDUP_TTL = 300
_MAX_DEDUP_ENTRIES = 5000


class AutoSharer:
    def __init__(self):
        self._recent: OrderedDict[str, float] = OrderedDict()
        # "shared" counts IOCs handed off to the background push task, not
        # confirmed hub deliveries (the push itself now happens off the
        # event-bus hot path — see _share_ip). Ground-truth delivery counts
        # live in hub_sync_client.stats (iocs_pushed / errors).
        self._stats = {"shared": 0, "skipped_dedup": 0, "skipped_invalid": 0, "skipped_backpressure": 0}

    def _is_duplicate(self, key: str) -> bool:
        now = datetime.now(timezone.utc).timestamp()
        # Clean old entries
        while self._recent and len(self._recent) > _MAX_DEDUP_ENTRIES:
            self._recent.popitem(last=False)
        # Check
        last = self._recent.get(key)
        if last and (now - last) < _DEDUP_TTL:
            return True
        self._recent[key] = now
        return False

    async def on_alert_processed(self, data: dict):
        """Called when an alert is processed (log_watcher / AI engine)."""
        source_ip = data.get("source_ip")
        if not source_ip:
            return

        threat_type = data.get("threat_type", data.get("incident_severity", "unknown"))
        severity = data.get("incident_severity", data.get("severity", "medium"))
        confidence = {"critical": 0.95, "high": 0.85, "medium": 0.6, "low": 0.3}.get(severity, 0.5)

        await self._share_ip(source_ip, threat_type, confidence, "alert_pipeline")

    async def on_honeypot_interaction(self, data: dict):
        """Called on honeypot interaction — attacker IP shared with high confidence."""
        source_ip = data.get("source_ip") or data.get("ip_address")
        if not source_ip:
            return
        await self._share_ip(source_ip, "honeypot_probe", 0.9, "honeypot")

    async def on_correlation_triggered(self, data: dict):
        """Called when sigma/chain rule fires."""
        source_ip = data.get("source_ip")
        if not source_ip:
            return
        severity = data.get("severity", "medium")
        confidence = {"critical": 0.95, "high": 0.85, "medium": 0.6, "low": 0.3}.get(severity, 0.5)
        threat_type = data.get("rule_title", data.get("threat_type", "sigma_detection"))
        await self._share_ip(source_ip, threat_type, confidence, "sigma_correlation")

    async def _share_ip(self, ip: str, threat_type: str, confidence: float, source: str):
        """Validate and share an IP IOC to the hub."""
        # Dedup check
        dedup_key = f"ip:{ip}"
        if self._is_duplicate(dedup_key):
            self._stats["skipped_dedup"] += 1
            return

        # Validate
        try:
            from app.services.ioc_validator import validate_ioc
            validate_ioc("ip", ip, threat_type, confidence)
        except Exception:
            self._stats["skipped_invalid"] += 1
            return

        # Push to hub — offloaded to a background task (see core/bg_tasks.py).
        # The hub POST used to be awaited right here inside the event-bus
        # handler, paying the full network round-trip (up to the client's
        # 15s timeout) on every shareable event. fire_and_forget schedules it
        # and returns immediately; the event bus is never blocked on it.
        try:
            from app.services.hub_sync_client import hub_sync_client
            task = fire_and_forget(
                hub_sync_client.push_ioc({
                    "ioc_type": "ip",
                    "ioc_value": ip,
                    "threat_type": threat_type,
                    "confidence": confidence,
                    "detection_source": source,
                }),
                label="hub_push_ioc",
            )
            if task is not None:
                self._stats["shared"] += 1
                logger.debug(f"Queued IOC share: {ip} ({threat_type}, confidence={confidence})")
            else:
                self._stats["skipped_backpressure"] += 1
        except Exception as e:
            logger.debug(f"Failed to queue IOC share: {e}")

    @property
    def stats(self) -> dict:
        return dict(self._stats)


auto_sharer = AutoSharer()
