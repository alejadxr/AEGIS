"""
Threat Intel Cloud — Shared community IOC intelligence service.

The network-effect moat: when one AEGIS instance detects a threat, the IOC
is anonymized and shared with ALL other AEGIS users. More users = better
protection for everyone.

Operating modes:
  - CLIENT: Submits IOCs to a remote hub and pulls community IOCs from it.
  - HUB: This instance IS the hub — receives IOCs from clients and serves
    the aggregated feed. Any AEGIS instance can act as the hub.

Opt-in control:
  - intel_sharing_enabled (default: False) — must be explicitly enabled
  - share_mode: "both" | "share_only" | "consume_only"

Auto-submit triggers (integration points — do NOT modify other files):
  - When an IP is blocked via Firewall -> auto-submit to cloud
  - When honeypot captures attacker -> auto-submit IP + TTPs
  - When Sigma chain rule fires -> auto-submit all IOCs involved

STIX 2.1 interoperability:
  - IOCs can be exported as STIX Indicator objects
  - TAXII-like feed endpoint for enterprise SIEM integration
"""

import asyncio
import hashlib
import hmac
import logging
import uuid
from datetime import datetime, timedelta
from typing import Optional

import httpx
from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session
from app.models.shared_intel import SharedIOC

logger = logging.getLogger("aegis.intel_cloud")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SYNC_INTERVAL_SECONDS = 15 * 60  # 15 minutes
CONFIDENCE_DECAY_HOURS = 72      # IOCs older than this start losing confidence
CONFIDENCE_DECAY_RATE = 0.05     # per-hour decay after threshold
IOC_EXPIRY_DAYS = 30             # IOCs expire after 30 days
VERIFICATION_THRESHOLD = 3       # reports needed to mark as verified
HTTP_TIMEOUT = 30.0

VALID_IOC_TYPES = {"ip", "domain", "hash", "url"}
VALID_SHARE_MODES = {"both", "share_only", "consume_only"}


# ---------------------------------------------------------------------------
# STIX 2.1 helpers
# ---------------------------------------------------------------------------

def _ioc_to_stix_indicator(ioc: SharedIOC) -> dict:
    """Convert a SharedIOC to a STIX 2.1 Indicator object."""
    pattern_map = {
        "ip": f"[ipv4-addr:value = '{ioc.ioc_value}']",
        "domain": f"[domain-name:value = '{ioc.ioc_value}']",
        "hash": f"[file:hashes.'SHA-256' = '{ioc.ioc_value}']",
        "url": f"[url:value = '{ioc.ioc_value}']",
    }
    pattern = pattern_map.get(ioc.ioc_type, f"[artifact:payload_bin = '{ioc.ioc_value}']")

    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{ioc.id}",
        "created": ioc.first_seen.isoformat() + "Z" if ioc.first_seen else datetime.utcnow().isoformat() + "Z",
        "modified": ioc.last_seen.isoformat() + "Z" if ioc.last_seen else datetime.utcnow().isoformat() + "Z",
        "name": f"{ioc.threat_type} — {ioc.ioc_type}:{ioc.ioc_value}",
        "description": f"Community-reported {ioc.threat_type} indicator. "
                       f"Confidence: {ioc.confidence:.0%}. "
                       f"Reports: {ioc.report_count}. "
                       f"Verified: {ioc.verified}.",
        "indicator_types": [_threat_type_to_stix_category(ioc.threat_type)],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ioc.first_seen.isoformat() + "Z" if ioc.first_seen else datetime.utcnow().isoformat() + "Z",
        "confidence": int(ioc.confidence * 100),
        "labels": [ioc.threat_type],
    }

    if ioc.expires_at:
        indicator["valid_until"] = ioc.expires_at.isoformat() + "Z"

    if ioc.mitre_techniques:
        indicator["external_references"] = [
            {
                "source_name": "mitre-attack",
                "external_id": tech,
                "url": f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}/",
            }
            for tech in (ioc.mitre_techniques if isinstance(ioc.mitre_techniques, list) else [])
        ]

    return indicator


def _threat_type_to_stix_category(threat_type: str) -> str:
    """Map AEGIS threat types to STIX indicator types."""
    mapping = {
        "brute_force": "malicious-activity",
        "c2": "malicious-activity",
        "botnet_c2": "malicious-activity",
        "phishing": "malicious-activity",
        "malware": "malicious-activity",
        "ransomware": "malicious-activity",
        "scan": "anomalous-activity",
        "port_scan": "anomalous-activity",
        "tor_exit": "anonymization",
        "compromised_host": "compromised",
        "abusive_ip": "malicious-activity",
    }
    return mapping.get(threat_type, "malicious-activity")


def _build_stix_bundle(indicators: list[dict]) -> dict:
    """Wrap STIX indicators in a STIX Bundle."""
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": indicators,
    }


# ---------------------------------------------------------------------------
# IntelCloud service
# ---------------------------------------------------------------------------

class IntelCloud:
    """
    Shared Threat Intelligence Cloud service.

    Manages bidirectional IOC sharing between AEGIS instances.
    One instance can act as both client and hub simultaneously.
    """

    def __init__(self):
        self._running = False
        self._bg_task: Optional[asyncio.Task] = None
        self._http: Optional[httpx.AsyncClient] = None

        # Configuration (can be updated at runtime via API)
        self._config = {
            "intel_sharing_enabled": False,
            "share_mode": "both",          # both | share_only | consume_only
            "hub_url": "",                  # URL of the hub instance (empty = this IS the hub)
            "cloud_secret": settings.AEGIS_SECRET_KEY,  # HMAC signing key
            "auto_submit": True,            # auto-submit IOCs from detections
            "min_confidence": 0.5,          # minimum confidence to share
        }

        # Stats
        self._stats = {
            "iocs_submitted": 0,
            "iocs_received": 0,
            "last_sync": None,
            "unique_contributors": 0,
            "sync_errors": 0,
        }

    # -- lifecycle ----------------------------------------------------------

    async def start(self):
        """Start the background sync loop."""
        if self._running:
            return
        self._running = True
        self._http = httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True)
        self._bg_task = asyncio.create_task(self._sync_loop(), name="intel_cloud_sync")
        logger.info("Intel Cloud service started")

    async def stop(self):
        """Stop the background sync loop."""
        self._running = False
        if self._bg_task and not self._bg_task.done():
            self._bg_task.cancel()
            try:
                await self._bg_task
            except asyncio.CancelledError:
                pass
        if self._http:
            await self._http.aclose()
            self._http = None
        logger.info("Intel Cloud service stopped")

    async def _ensure_http(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True)
        return self._http

    # -- configuration ------------------------------------------------------

    def get_config(self) -> dict:
        """Return current sharing configuration (safe copy, no secrets)."""
        return {
            "intel_sharing_enabled": self._config["intel_sharing_enabled"],
            "share_mode": self._config["share_mode"],
            "hub_url": self._config["hub_url"],
            "auto_submit": self._config["auto_submit"],
            "min_confidence": self._config["min_confidence"],
        }

    def update_config(self, updates: dict):
        """Update sharing configuration at runtime."""
        allowed_keys = {
            "intel_sharing_enabled", "share_mode", "hub_url",
            "auto_submit", "min_confidence", "cloud_secret",
        }
        for key, value in updates.items():
            if key in allowed_keys:
                if key == "share_mode" and value not in VALID_SHARE_MODES:
                    raise ValueError(f"Invalid share_mode: {value}. Must be one of {VALID_SHARE_MODES}")
                if key == "min_confidence":
                    value = max(0.0, min(1.0, float(value)))
                self._config[key] = value
        logger.info(f"Intel Cloud config updated: {list(updates.keys())}")

    @property
    def sharing_enabled(self) -> bool:
        return self._config["intel_sharing_enabled"]

    @property
    def can_share(self) -> bool:
        return self.sharing_enabled and self._config["share_mode"] in ("both", "share_only")

    @property
    def can_consume(self) -> bool:
        return self.sharing_enabled and self._config["share_mode"] in ("both", "consume_only")

    @property
    def is_hub(self) -> bool:
        return not self._config["hub_url"]

    # -- HMAC signing -------------------------------------------------------

    def _sign_ioc(self, ioc_data: dict) -> str:
        """Create HMAC-SHA256 signature for IOC submission."""
        secret = self._config["cloud_secret"].encode()
        message = f"{ioc_data['ioc_type']}:{ioc_data['ioc_value']}:{ioc_data['threat_type']}".encode()
        return hmac.new(secret, message, hashlib.sha256).hexdigest()

    def _verify_signature(self, ioc_data: dict, signature: str) -> bool:
        """Verify HMAC-SHA256 signature of a received IOC."""
        expected = self._sign_ioc(ioc_data)
        return hmac.compare_digest(expected, signature)

    def _hash_client_id(self, client_id: str) -> str:
        """Hash client ID for anonymous but consistent contributor identification."""
        return hashlib.sha256(
            f"{client_id}:{self._config['cloud_secret']}".encode()
        ).hexdigest()

    # -- IOC submission (client mode) ---------------------------------------

    async def submit_ioc(self, ioc_data: dict, client_id: str = "local") -> dict:
        """
        Submit an IOC to the cloud.

        If this instance IS the hub, stores directly.
        If a hub_url is configured, POSTs to the remote hub.

        Args:
            ioc_data: dict with ioc_type, ioc_value, threat_type, confidence,
                      mitre_techniques (optional)
            client_id: the submitting client ID (will be hashed)

        Returns:
            dict with status and ioc_id
        """
        if not self.can_share:
            return {"status": "rejected", "reason": "Sharing is disabled or mode is consume_only"}

        # Validate IOC type
        ioc_type = ioc_data.get("ioc_type", "").lower()
        if ioc_type not in VALID_IOC_TYPES:
            return {"status": "rejected", "reason": f"Invalid ioc_type. Must be one of {VALID_IOC_TYPES}"}

        ioc_value = (ioc_data.get("ioc_value") or "").strip()
        if not ioc_value:
            return {"status": "rejected", "reason": "ioc_value is required"}

        confidence = max(0.0, min(1.0, float(ioc_data.get("confidence", 0.5))))
        if confidence < self._config["min_confidence"]:
            return {"status": "rejected", "reason": f"Confidence {confidence} below minimum {self._config['min_confidence']}"}

        # Build the anonymized submission
        submission = {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "threat_type": ioc_data.get("threat_type", "unknown"),
            "confidence": confidence,
            "mitre_techniques": ioc_data.get("mitre_techniques", []),
            "first_seen": ioc_data.get("first_seen", datetime.utcnow().isoformat()),
            "source_hash": self._hash_client_id(client_id),
        }
        submission["signature"] = self._sign_ioc(submission)

        if self.is_hub:
            # Store directly in local DB
            result = await self._store_ioc(submission)
            self._stats["iocs_submitted"] += 1
            return result
        else:
            # POST to remote hub
            return await self._post_to_hub(submission)

    async def _post_to_hub(self, submission: dict) -> dict:
        """POST an IOC to the remote hub."""
        hub_url = self._config["hub_url"].rstrip("/")
        url = f"{hub_url}/api/v1/intel/hub/submit"

        try:
            http = await self._ensure_http()
            resp = await http.post(url, json=submission)
            resp.raise_for_status()
            self._stats["iocs_submitted"] += 1
            return resp.json()
        except Exception as e:
            logger.error(f"Failed to submit IOC to hub {hub_url}: {e}")
            self._stats["sync_errors"] += 1
            return {"status": "error", "reason": str(e)}

    # -- IOC storage (hub mode) ---------------------------------------------

    async def _store_ioc(self, ioc_data: dict) -> dict:
        """
        Store or update an IOC in the shared_iocs table.
        Deduplicates by ioc_value and increments report_count.
        """
        now = datetime.utcnow()
        expires = now + timedelta(days=IOC_EXPIRY_DAYS)

        try:
            async with async_session() as db:
                # Check for existing IOC
                result = await db.execute(
                    select(SharedIOC).where(
                        SharedIOC.ioc_value == ioc_data["ioc_value"],
                        SharedIOC.ioc_type == ioc_data["ioc_type"],
                    )
                )
                existing = result.scalar_one_or_none()

                if existing:
                    # Update: bump report count, update confidence, extend expiry
                    existing.report_count += 1
                    existing.last_seen = now
                    existing.expires_at = expires
                    # Increase confidence if reported by a different source
                    if existing.source_hash != ioc_data.get("source_hash", ""):
                        existing.confidence = min(1.0, existing.confidence + 0.05)
                    # Mark as verified if enough independent reports
                    if existing.report_count >= VERIFICATION_THRESHOLD:
                        existing.verified = True
                    # Merge MITRE techniques
                    existing_techniques = existing.mitre_techniques or []
                    new_techniques = ioc_data.get("mitre_techniques", [])
                    if isinstance(existing_techniques, list) and isinstance(new_techniques, list):
                        merged = list(set(existing_techniques + new_techniques))
                        existing.mitre_techniques = merged

                    await db.commit()
                    logger.info(
                        f"Updated shared IOC: {ioc_data['ioc_type']}:{ioc_data['ioc_value']} "
                        f"(reports: {existing.report_count}, verified: {existing.verified})"
                    )
                    return {"status": "updated", "ioc_id": existing.id, "report_count": existing.report_count}
                else:
                    # Insert new IOC
                    first_seen = now
                    if ioc_data.get("first_seen"):
                        try:
                            first_seen = datetime.fromisoformat(
                                ioc_data["first_seen"].replace("Z", "+00:00")
                            ).replace(tzinfo=None)
                        except (ValueError, AttributeError):
                            first_seen = now

                    new_ioc = SharedIOC(
                        ioc_type=ioc_data["ioc_type"],
                        ioc_value=ioc_data["ioc_value"],
                        threat_type=ioc_data["threat_type"],
                        confidence=ioc_data.get("confidence", 0.5),
                        mitre_techniques=ioc_data.get("mitre_techniques", []),
                        source_hash=ioc_data.get("source_hash", "unknown"),
                        report_count=1,
                        verified=False,
                        first_seen=first_seen,
                        last_seen=now,
                        expires_at=expires,
                    )
                    db.add(new_ioc)
                    await db.commit()
                    await db.refresh(new_ioc)

                    logger.info(
                        f"Stored new shared IOC: {ioc_data['ioc_type']}:{ioc_data['ioc_value']}"
                    )
                    return {"status": "created", "ioc_id": new_ioc.id, "report_count": 1}

        except Exception as e:
            logger.error(f"Failed to store shared IOC: {e}")
            return {"status": "error", "reason": str(e)}

    # -- IOC consumption (client mode) --------------------------------------

    async def pull_community_iocs(self) -> dict:
        """
        Pull community IOCs from the hub and merge into local DB.

        If this instance IS the hub, applies confidence decay only.
        If a hub_url is configured, GETs from the remote hub.

        Returns:
            dict with counts of new, updated, and decayed IOCs
        """
        result = {"new": 0, "updated": 0, "decayed": 0, "errors": 0}

        # Apply confidence decay regardless of mode
        decayed = await self._apply_confidence_decay()
        result["decayed"] = decayed

        if self.is_hub:
            # Hub mode: we already have all the IOCs locally
            self._stats["last_sync"] = datetime.utcnow().isoformat()
            return result

        if not self.can_consume:
            return result

        # Client mode: pull from remote hub
        hub_url = self._config["hub_url"].rstrip("/")
        url = f"{hub_url}/api/v1/intel/hub/feed"

        try:
            http = await self._ensure_http()
            # Request IOCs updated since last sync
            params = {}
            if self._stats["last_sync"]:
                params["since"] = self._stats["last_sync"]

            resp = await http.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()

            iocs = data.get("iocs", [])
            for ioc_data in iocs:
                store_result = await self._store_ioc(ioc_data)
                if store_result["status"] == "created":
                    result["new"] += 1
                    self._stats["iocs_received"] += 1
                elif store_result["status"] == "updated":
                    result["updated"] += 1
                else:
                    result["errors"] += 1

            self._stats["last_sync"] = datetime.utcnow().isoformat()
            logger.info(
                f"Pulled community IOCs: {result['new']} new, "
                f"{result['updated']} updated, {result['decayed']} decayed"
            )

        except Exception as e:
            logger.error(f"Failed to pull community IOCs from {hub_url}: {e}")
            self._stats["sync_errors"] += 1
            result["errors"] += 1

        return result

    async def _apply_confidence_decay(self) -> int:
        """
        Decay confidence of old IOCs and prune expired ones.

        IOCs older than CONFIDENCE_DECAY_HOURS start losing confidence
        at CONFIDENCE_DECAY_RATE per hour. IOCs past expires_at are deleted.

        Returns:
            Number of IOCs affected (decayed + pruned)
        """
        now = datetime.utcnow()
        decay_threshold = now - timedelta(hours=CONFIDENCE_DECAY_HOURS)
        affected = 0

        try:
            async with async_session() as db:
                # Prune expired IOCs
                from sqlalchemy import delete
                pruned = await db.execute(
                    delete(SharedIOC).where(
                        SharedIOC.expires_at.isnot(None),
                        SharedIOC.expires_at < now,
                    )
                )
                affected += pruned.rowcount

                # Decay confidence on old, non-verified IOCs
                result = await db.execute(
                    select(SharedIOC).where(
                        SharedIOC.last_seen < decay_threshold,
                        SharedIOC.verified == False,  # noqa: E712
                        SharedIOC.confidence > 0.1,
                    )
                )
                for ioc in result.scalars().all():
                    hours_old = (now - ioc.last_seen).total_seconds() / 3600
                    hours_past_threshold = hours_old - CONFIDENCE_DECAY_HOURS
                    decay = hours_past_threshold * CONFIDENCE_DECAY_RATE
                    ioc.confidence = max(0.1, ioc.confidence - decay)
                    affected += 1

                await db.commit()

            if affected > 0:
                logger.info(f"Confidence decay: {affected} IOCs affected ({pruned.rowcount} pruned)")

        except Exception as e:
            logger.error(f"Confidence decay failed: {e}")

        return affected

    # -- background sync loop -----------------------------------------------

    async def _sync_loop(self):
        """Periodically pull community IOCs and apply decay."""
        # Initial delay to let the app finish booting
        await asyncio.sleep(10)

        while self._running:
            try:
                if self.sharing_enabled:
                    await self.pull_community_iocs()
                    await self._update_contributor_count()
                else:
                    # Even if sharing is disabled, run decay on any existing IOCs
                    await self._apply_confidence_decay()

                await asyncio.sleep(SYNC_INTERVAL_SECONDS)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Intel Cloud sync loop error: {e}")
                await asyncio.sleep(60)

    async def _update_contributor_count(self):
        """Count unique anonymous contributors."""
        try:
            async with async_session() as db:
                result = await db.execute(
                    select(func.count(func.distinct(SharedIOC.source_hash)))
                )
                count = result.scalar() or 0
                self._stats["unique_contributors"] = count
        except Exception as e:
            logger.warning(f"Failed to count contributors: {e}")

    # -- manual sync --------------------------------------------------------

    async def manual_sync(self) -> dict:
        """Trigger a manual sync with the cloud (pull + decay)."""
        if not self.sharing_enabled:
            return {"status": "disabled", "message": "Intel sharing is not enabled"}
        return await self.pull_community_iocs()

    # -- query community IOCs -----------------------------------------------

    async def get_community_iocs(
        self,
        page: int = 1,
        per_page: int = 50,
        ioc_type: Optional[str] = None,
        threat_type: Optional[str] = None,
        verified_only: bool = False,
        min_confidence: float = 0.0,
        since: Optional[str] = None,
    ) -> dict:
        """
        Query community IOCs with filtering and pagination.

        Returns:
            dict with iocs list, total count, and pagination info
        """
        try:
            async with async_session() as db:
                # Build query
                query = select(SharedIOC).where(SharedIOC.confidence >= min_confidence)
                count_query = select(func.count(SharedIOC.id)).where(
                    SharedIOC.confidence >= min_confidence
                )

                if ioc_type:
                    query = query.where(SharedIOC.ioc_type == ioc_type)
                    count_query = count_query.where(SharedIOC.ioc_type == ioc_type)
                if threat_type:
                    query = query.where(SharedIOC.threat_type == threat_type)
                    count_query = count_query.where(SharedIOC.threat_type == threat_type)
                if verified_only:
                    query = query.where(SharedIOC.verified == True)  # noqa: E712
                    count_query = count_query.where(SharedIOC.verified == True)  # noqa: E712
                if since:
                    try:
                        since_dt = datetime.fromisoformat(since.replace("Z", "+00:00")).replace(tzinfo=None)
                        query = query.where(SharedIOC.last_seen >= since_dt)
                        count_query = count_query.where(SharedIOC.last_seen >= since_dt)
                    except ValueError:
                        pass

                # Exclude expired
                now = datetime.utcnow()
                query = query.where(
                    or_(SharedIOC.expires_at.is_(None), SharedIOC.expires_at > now)
                )
                count_query = count_query.where(
                    or_(SharedIOC.expires_at.is_(None), SharedIOC.expires_at > now)
                )

                # Count
                total_result = await db.execute(count_query)
                total = total_result.scalar() or 0

                # Paginate
                offset = (page - 1) * per_page
                query = query.order_by(SharedIOC.last_seen.desc()).offset(offset).limit(per_page)

                result = await db.execute(query)
                iocs = []
                for ioc in result.scalars().all():
                    iocs.append({
                        "id": ioc.id,
                        "ioc_type": ioc.ioc_type,
                        "ioc_value": ioc.ioc_value,
                        "threat_type": ioc.threat_type,
                        "confidence": ioc.confidence,
                        "mitre_techniques": ioc.mitre_techniques or [],
                        "source_hash": ioc.source_hash,
                        "report_count": ioc.report_count,
                        "verified": ioc.verified,
                        "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                        "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
                        "expires_at": ioc.expires_at.isoformat() if ioc.expires_at else None,
                    })

                return {
                    "iocs": iocs,
                    "total": total,
                    "page": page,
                    "per_page": per_page,
                    "pages": (total + per_page - 1) // per_page if per_page > 0 else 0,
                }

        except Exception as e:
            logger.error(f"Failed to query community IOCs: {e}")
            return {"iocs": [], "total": 0, "page": page, "per_page": per_page, "pages": 0, "error": str(e)}

    # -- hub feed endpoint helpers ------------------------------------------

    async def get_hub_feed(self, since: Optional[str] = None, limit: int = 500) -> dict:
        """
        Serve IOCs to other instances (hub mode).

        Returns IOCs updated since the given timestamp, limited to `limit` entries.
        """
        try:
            async with async_session() as db:
                query = select(SharedIOC).where(
                    or_(SharedIOC.expires_at.is_(None), SharedIOC.expires_at > datetime.utcnow())
                )

                if since:
                    try:
                        since_dt = datetime.fromisoformat(since.replace("Z", "+00:00")).replace(tzinfo=None)
                        query = query.where(SharedIOC.last_seen >= since_dt)
                    except ValueError:
                        pass

                query = query.order_by(SharedIOC.last_seen.desc()).limit(limit)
                result = await db.execute(query)

                iocs = []
                for ioc in result.scalars().all():
                    iocs.append({
                        "ioc_type": ioc.ioc_type,
                        "ioc_value": ioc.ioc_value,
                        "threat_type": ioc.threat_type,
                        "confidence": ioc.confidence,
                        "mitre_techniques": ioc.mitre_techniques or [],
                        "source_hash": ioc.source_hash,
                        "report_count": ioc.report_count,
                        "verified": ioc.verified,
                        "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                        "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
                        "expires_at": ioc.expires_at.isoformat() if ioc.expires_at else None,
                    })

                return {
                    "iocs": iocs,
                    "count": len(iocs),
                    "served_at": datetime.utcnow().isoformat(),
                }

        except Exception as e:
            logger.error(f"Failed to serve hub feed: {e}")
            return {"iocs": [], "count": 0, "error": str(e)}

    async def get_hub_feed_stix(self, since: Optional[str] = None, limit: int = 500) -> dict:
        """
        Serve IOCs in STIX 2.1 Bundle format (TAXII-like endpoint).

        Compatible with enterprise SIEMs that support STIX ingestion.
        """
        try:
            async with async_session() as db:
                query = select(SharedIOC).where(
                    or_(SharedIOC.expires_at.is_(None), SharedIOC.expires_at > datetime.utcnow())
                )

                if since:
                    try:
                        since_dt = datetime.fromisoformat(since.replace("Z", "+00:00")).replace(tzinfo=None)
                        query = query.where(SharedIOC.last_seen >= since_dt)
                    except ValueError:
                        pass

                query = query.order_by(SharedIOC.last_seen.desc()).limit(limit)
                result = await db.execute(query)

                indicators = []
                for ioc in result.scalars().all():
                    indicators.append(_ioc_to_stix_indicator(ioc))

                return _build_stix_bundle(indicators)

        except Exception as e:
            logger.error(f"Failed to build STIX feed: {e}")
            return _build_stix_bundle([])

    # -- stats --------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return sharing statistics."""
        return {
            **self._stats,
            "sharing_enabled": self.sharing_enabled,
            "share_mode": self._config["share_mode"],
            "is_hub": self.is_hub,
            "hub_url": self._config["hub_url"] or "(this instance)",
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
intel_cloud = IntelCloud()
