"""
Threat Feed Manager — pulls IOCs from multiple free external intelligence sources.

Feeds:
  - AbuseIPDB (free tier, 1000 checks/day)
  - AlienVault OTX (free, optional API key)
  - Emerging Threats (free blocklist, refreshed every 6h)
  - Tor Exit Nodes (free, refreshed every 12h)
  - Feodo Tracker (free, botnet C2 IPs)

Integration points (do NOT modify these files — wire up in main.py lifespan):
  - log_watcher: after _create_incident_from_log(), call
        await threat_feed_manager.auto_enrich_incident({"source_ip": source_ip})
  - honeypot interactions: after recording interaction, call
        await threat_feed_manager.auto_enrich_incident({"source_ip": ip})
  - scanner: after scan_completed, enrich any suspicious IPs found
"""

import asyncio
import ipaddress
import logging
import os
from datetime import datetime, timedelta
from typing import Optional

import httpx
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session
from app.models.threat_intel import ThreatIntel
from app.services.threat_intel_hub import threat_intel_hub

logger = logging.getLogger("cayde6.threat_feeds")

# ---------------------------------------------------------------------------
# In-memory config for API keys (can be updated at runtime via PUT /feeds/config)
# Falls back to env vars on startup.
# ---------------------------------------------------------------------------
_feed_config: dict[str, str] = {}


def _get_key(name: str) -> str:
    return _feed_config.get(name) or os.getenv(name, "")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_BLACKLIST_URL = "https://api.abuseipdb.com/api/v2/blacklist"
OTX_IP_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
OTX_PULSES_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
ET_COMPROMISED_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"

HTTP_TIMEOUT = 30.0

# Refresh intervals (seconds)
BLOCKLIST_REFRESH = 6 * 3600      # 6 hours
TOR_REFRESH = 12 * 3600           # 12 hours

# In-memory caches for fast lookups
_cached_blocklists: dict[str, set[str]] = {
    "emerging_threats": set(),
    "tor_exit_nodes": set(),
    "feodo_tracker": set(),
}
_last_refresh: dict[str, Optional[datetime]] = {
    "emerging_threats": None,
    "tor_exit_nodes": None,
    "feodo_tracker": None,
}


def _is_valid_ip(ip: str) -> bool:
    """Return True if the string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def _parse_text_blocklist(text: str) -> set[str]:
    """Parse a plain-text blocklist (one IP per line, skip comments/blanks)."""
    ips: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Some lists have trailing comments
        token = line.split()[0]
        if _is_valid_ip(token):
            ips.add(token)
    return ips


# ---------------------------------------------------------------------------
# ThreatFeedManager
# ---------------------------------------------------------------------------

class ThreatFeedManager:
    """Pulls IOCs from multiple free threat-intelligence sources."""

    def __init__(self):
        self._bg_task: Optional[asyncio.Task] = None
        self._running = False
        self._http: Optional[httpx.AsyncClient] = None
        self._feed_stats: dict[str, dict] = {
            "abuseipdb": {"last_sync": None, "ioc_count": 0, "status": "idle"},
            "otx": {"last_sync": None, "ioc_count": 0, "status": "idle"},
            "emerging_threats": {"last_sync": None, "ioc_count": 0, "status": "idle"},
            "tor_exit_nodes": {"last_sync": None, "ioc_count": 0, "status": "idle"},
            "feodo_tracker": {"last_sync": None, "ioc_count": 0, "status": "idle"},
        }

    # -- lifecycle ----------------------------------------------------------

    async def start(self):
        """Start the background refresh loop."""
        if self._running:
            return
        self._running = True
        self._http = httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True)
        self._bg_task = asyncio.create_task(self._refresh_loop(), name="threat_feed_refresh")
        logger.info("Threat feed manager started")

    async def stop(self):
        """Stop the background refresh loop and close the HTTP client."""
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
        logger.info("Threat feed manager stopped")

    async def _refresh_loop(self):
        """Periodically download all blocklists."""
        # Initial refresh on startup (small delay to let the app finish booting)
        await asyncio.sleep(5)
        await self.refresh_blocklists()

        while self._running:
            try:
                await asyncio.sleep(60)  # check every minute
                now = datetime.utcnow()

                # Emerging Threats + Feodo — every 6h
                for name in ("emerging_threats", "feodo_tracker"):
                    last = _last_refresh.get(name)
                    if last is None or (now - last).total_seconds() >= BLOCKLIST_REFRESH:
                        await self._refresh_single_blocklist(name)

                # Tor exit nodes — every 12h
                last_tor = _last_refresh.get("tor_exit_nodes")
                if last_tor is None or (now - last_tor).total_seconds() >= TOR_REFRESH:
                    await self._refresh_single_blocklist("tor_exit_nodes")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Refresh loop error: {e}")
                await asyncio.sleep(60)

    # -- blocklist downloads ------------------------------------------------

    async def _ensure_http(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True)
        return self._http

    async def _download_text(self, url: str) -> Optional[str]:
        http = await self._ensure_http()
        try:
            resp = await http.get(url)
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            logger.error(f"Failed to download {url}: {e}")
            return None

    async def _refresh_single_blocklist(self, name: str):
        url_map = {
            "emerging_threats": ET_COMPROMISED_URL,
            "tor_exit_nodes": TOR_EXIT_URL,
            "feodo_tracker": FEODO_URL,
        }
        url = url_map.get(name)
        if not url:
            return

        self._feed_stats[name]["status"] = "syncing"
        logger.info(f"Refreshing blocklist: {name}")

        text = await self._download_text(url)
        if text is None:
            self._feed_stats[name]["status"] = "error"
            return

        ips = _parse_text_blocklist(text)
        _cached_blocklists[name] = ips
        _last_refresh[name] = datetime.utcnow()

        # Persist to threat_intel table (deduplicate)
        await self._persist_blocklist_ips(name, ips)

        self._feed_stats[name]["last_sync"] = datetime.utcnow().isoformat()
        self._feed_stats[name]["ioc_count"] = len(ips)
        self._feed_stats[name]["status"] = "ok"
        logger.info(f"Blocklist {name}: {len(ips)} IPs loaded")

    async def _persist_blocklist_ips(self, source: str, ips: set[str]):
        """Upsert blocklist IPs into threat_intel table."""
        threat_type_map = {
            "emerging_threats": "compromised_host",
            "tor_exit_nodes": "tor_exit",
            "feodo_tracker": "botnet_c2",
        }
        threat_type = threat_type_map.get(source, "unknown")
        now = datetime.utcnow()
        expires = now + timedelta(hours=24)

        try:
            async with async_session() as db:
                # Fetch existing IOCs for this source
                result = await db.execute(
                    select(ThreatIntel.ioc_value).where(ThreatIntel.source == source)
                )
                existing = {row[0] for row in result.all()}

                new_ips = ips - existing
                stale_ips = existing - ips

                # Remove stale entries
                if stale_ips:
                    await db.execute(
                        delete(ThreatIntel).where(
                            ThreatIntel.source == source,
                            ThreatIntel.ioc_value.in_(stale_ips),
                        )
                    )

                # Update last_seen for existing entries
                if existing & ips:
                    result2 = await db.execute(
                        select(ThreatIntel).where(
                            ThreatIntel.source == source,
                            ThreatIntel.ioc_value.in_(existing & ips),
                        )
                    )
                    for ioc in result2.scalars().all():
                        ioc.last_seen = now
                        ioc.expires_at = expires

                # Insert new entries (batch)
                batch: list[ThreatIntel] = []
                for ip in new_ips:
                    batch.append(ThreatIntel(
                        ioc_type="ip",
                        ioc_value=ip,
                        threat_type=threat_type,
                        confidence=0.7,
                        source=source,
                        tags=[source],
                        first_seen=now,
                        last_seen=now,
                        expires_at=expires,
                    ))
                if batch:
                    db.add_all(batch)

                await db.commit()
                logger.info(
                    f"Persisted {source}: +{len(new_ips)} new, "
                    f"-{len(stale_ips)} stale, {len(existing & ips)} updated"
                )

                # Also push to MongoDB external_feeds collection
                try:
                    mongo_iocs = [
                        {
                            "ioc_type": "ip",
                            "ioc_value": ip,
                            "threat_type": threat_type,
                            "confidence": 0.7,
                            "tags": [source],
                        }
                        for ip in ips
                    ]
                    pushed = await threat_intel_hub.push_external(source, mongo_iocs)
                    logger.info(f"Pushed {pushed} IOCs to MongoDB external_feeds from {source}")
                except Exception as me:
                    logger.warning(f"MongoDB push for {source} failed (non-fatal): {me}")

        except Exception as e:
            logger.error(f"Failed to persist blocklist {source}: {e}")

    async def refresh_blocklists(self):
        """Download all blocklists (called on startup and by manual sync)."""
        tasks = [
            self._refresh_single_blocklist("emerging_threats"),
            self._refresh_single_blocklist("tor_exit_nodes"),
            self._refresh_single_blocklist("feodo_tracker"),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Also pull AbuseIPDB blacklist if key is available
        key = _get_key("ABUSEIPDB_API_KEY")
        if key:
            await self._refresh_abuseipdb_blacklist(key)

    async def _refresh_abuseipdb_blacklist(self, api_key: str):
        """Pull AbuseIPDB blacklist (top 100 abusive IPs)."""
        self._feed_stats["abuseipdb"]["status"] = "syncing"
        http = await self._ensure_http()
        try:
            resp = await http.get(
                ABUSEIPDB_BLACKLIST_URL,
                params={"limit": 100, "confidenceMinimum": 90},
                headers={"Key": api_key, "Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json().get("data", [])

            ips: set[str] = set()
            now = datetime.utcnow()
            expires = now + timedelta(hours=24)

            async with async_session() as db:
                for entry in data:
                    ip_addr = entry.get("ipAddress", "")
                    if not _is_valid_ip(ip_addr):
                        continue
                    ips.add(ip_addr)

                    # Upsert
                    result = await db.execute(
                        select(ThreatIntel).where(
                            ThreatIntel.ioc_value == ip_addr,
                            ThreatIntel.source == "abuseipdb",
                        )
                    )
                    existing = result.scalar_one_or_none()
                    if existing:
                        existing.last_seen = now
                        existing.confidence = entry.get("abuseConfidenceScore", 90) / 100
                        existing.expires_at = expires
                    else:
                        db.add(ThreatIntel(
                            ioc_type="ip",
                            ioc_value=ip_addr,
                            threat_type="abusive_ip",
                            confidence=entry.get("abuseConfidenceScore", 90) / 100,
                            source="abuseipdb",
                            tags=["abuseipdb", entry.get("countryCode", "")],
                            first_seen=now,
                            last_seen=now,
                            expires_at=expires,
                        ))
                await db.commit()

            self._feed_stats["abuseipdb"]["last_sync"] = now.isoformat()
            self._feed_stats["abuseipdb"]["ioc_count"] = len(ips)
            self._feed_stats["abuseipdb"]["status"] = "ok"
            logger.info(f"AbuseIPDB blacklist: {len(ips)} IPs loaded")

            # Push to MongoDB external_feeds
            try:
                mongo_iocs = [
                    {
                        "ioc_type": "ip",
                        "ioc_value": ip,
                        "threat_type": "abusive_ip",
                        "confidence": 0.9,
                        "tags": ["abuseipdb"],
                    }
                    for ip in ips
                ]
                pushed = await threat_intel_hub.push_external("abuseipdb", mongo_iocs)
                logger.info(f"Pushed {pushed} AbuseIPDB IOCs to MongoDB external_feeds")
            except Exception as me:
                logger.warning(f"MongoDB push for abuseipdb failed (non-fatal): {me}")

        except Exception as e:
            self._feed_stats["abuseipdb"]["status"] = "error"
            logger.error(f"AbuseIPDB blacklist refresh failed: {e}")

    # -- single-IP enrichment ----------------------------------------------

    async def _check_abuseipdb(self, ip: str) -> Optional[dict]:
        """Query AbuseIPDB for a single IP. Returns enrichment dict or None."""
        key = _get_key("ABUSEIPDB_API_KEY")
        if not key:
            return None

        http = await self._ensure_http()
        try:
            resp = await http.get(
                ABUSEIPDB_CHECK_URL,
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": key, "Accept": "application/json"},
            )
            resp.raise_for_status()
            d = resp.json().get("data", {})
            return {
                "source": "abuseipdb",
                "abuse_confidence": d.get("abuseConfidenceScore", 0),
                "country": d.get("countryCode"),
                "isp": d.get("isp"),
                "domain": d.get("domain"),
                "total_reports": d.get("totalReports", 0),
                "last_reported": d.get("lastReportedAt"),
                "is_tor": d.get("isTor", False),
                "usage_type": d.get("usageType"),
            }
        except Exception as e:
            logger.warning(f"AbuseIPDB check failed for {ip}: {e}")
            return None

    async def _check_otx(self, ip: str) -> Optional[dict]:
        """Query AlienVault OTX for a single IP."""
        http = await self._ensure_http()
        headers: dict[str, str] = {"Accept": "application/json"}
        otx_key = _get_key("OTX_API_KEY")
        if otx_key:
            headers["X-OTX-API-KEY"] = otx_key

        try:
            resp = await http.get(
                OTX_IP_URL.format(ip=ip),
                headers=headers,
            )
            resp.raise_for_status()
            d = resp.json()
            pulse_info = d.get("pulse_info", {})
            return {
                "source": "otx",
                "reputation": d.get("reputation", 0),
                "country": d.get("country_name"),
                "asn": d.get("asn"),
                "pulse_count": pulse_info.get("count", 0),
                "pulses": [
                    {"name": p.get("name"), "created": p.get("created")}
                    for p in (pulse_info.get("pulses") or [])[:5]
                ],
            }
        except Exception as e:
            logger.warning(f"OTX check failed for {ip}: {e}")
            return None

    def _check_cached_blocklists(self, ip: str) -> list[dict]:
        """Check the IP against in-memory cached blocklists (instant)."""
        hits: list[dict] = []
        label_map = {
            "emerging_threats": "Emerging Threats compromised IP list",
            "tor_exit_nodes": "Tor exit node",
            "feodo_tracker": "Feodo Tracker botnet C2",
        }
        for name, cache in _cached_blocklists.items():
            if ip in cache:
                hits.append({
                    "source": name,
                    "label": label_map.get(name, name),
                    "listed": True,
                })
        return hits

    # -- public API ---------------------------------------------------------

    async def check_ip_reputation(self, ip: str) -> dict:
        """
        Quick reputation check against cached blocklists only (no external API call).
        Returns a dict with blocklist hits and a simple risk verdict.
        """
        if not _is_valid_ip(ip):
            return {"ip": ip, "error": "Invalid IP address"}

        hits = self._check_cached_blocklists(ip)

        # Also check the DB for previously enriched data
        db_hits: list[dict] = []
        try:
            async with async_session() as db:
                result = await db.execute(
                    select(ThreatIntel).where(ThreatIntel.ioc_value == ip).limit(10)
                )
                for ioc in result.scalars().all():
                    db_hits.append({
                        "source": ioc.source,
                        "threat_type": ioc.threat_type,
                        "confidence": ioc.confidence,
                        "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
                    })
        except Exception as e:
            logger.warning(f"DB lookup failed for {ip}: {e}")

        total_hits = len(hits) + len(db_hits)
        if total_hits == 0:
            verdict = "clean"
        elif total_hits <= 1:
            verdict = "suspicious"
        else:
            verdict = "malicious"

        return {
            "ip": ip,
            "verdict": verdict,
            "blocklist_hits": hits,
            "db_records": db_hits,
            "checked_at": datetime.utcnow().isoformat(),
        }

    async def enrich_ip(self, ip: str) -> dict:
        """
        Full enrichment of an IP from all available sources (API calls + cache).
        Returns a consolidated dict.
        """
        if not _is_valid_ip(ip):
            return {"ip": ip, "error": "Invalid IP address"}

        # Run API checks in parallel
        abuseipdb_task = asyncio.create_task(self._check_abuseipdb(ip))
        otx_task = asyncio.create_task(self._check_otx(ip))
        blocklist_hits = self._check_cached_blocklists(ip)

        abuseipdb_result = await abuseipdb_task
        otx_result = await otx_task

        # Compute aggregate risk score (0-100)
        scores: list[float] = []
        if abuseipdb_result:
            scores.append(abuseipdb_result.get("abuse_confidence", 0))
        if otx_result and otx_result.get("pulse_count", 0) > 0:
            # More pulses = higher risk, cap at 90
            scores.append(min(otx_result["pulse_count"] * 15, 90))
        if blocklist_hits:
            scores.append(80.0)  # listed on a blocklist = high base risk

        risk_score = max(scores) if scores else 0.0

        if risk_score >= 70:
            verdict = "malicious"
        elif risk_score >= 30:
            verdict = "suspicious"
        else:
            verdict = "clean"

        # Persist enrichment to DB
        await self._persist_enrichment(ip, risk_score, verdict, abuseipdb_result, otx_result, blocklist_hits)

        return {
            "ip": ip,
            "risk_score": risk_score,
            "verdict": verdict,
            "abuseipdb": abuseipdb_result,
            "otx": otx_result,
            "blocklist_hits": blocklist_hits,
            "enriched_at": datetime.utcnow().isoformat(),
        }

    async def _persist_enrichment(
        self,
        ip: str,
        risk_score: float,
        verdict: str,
        abuseipdb: Optional[dict],
        otx: Optional[dict],
        blocklist_hits: list[dict],
    ):
        """Save enrichment results to threat_intel table."""
        now = datetime.utcnow()
        expires = now + timedelta(hours=48)

        try:
            async with async_session() as db:
                # Upsert a consolidated enrichment record
                result = await db.execute(
                    select(ThreatIntel).where(
                        ThreatIntel.ioc_value == ip,
                        ThreatIntel.source == "enrichment",
                    )
                )
                existing = result.scalar_one_or_none()

                tags = [verdict]
                if abuseipdb and abuseipdb.get("country"):
                    tags.append(abuseipdb["country"])
                if blocklist_hits:
                    tags.extend(h["source"] for h in blocklist_hits)

                if existing:
                    existing.confidence = risk_score / 100
                    existing.last_seen = now
                    existing.expires_at = expires
                    existing.tags = tags
                    existing.threat_type = verdict
                else:
                    db.add(ThreatIntel(
                        ioc_type="ip",
                        ioc_value=ip,
                        threat_type=verdict,
                        confidence=risk_score / 100,
                        source="enrichment",
                        tags=tags,
                        first_seen=now,
                        last_seen=now,
                        expires_at=expires,
                    ))
                await db.commit()
        except Exception as e:
            logger.error(f"Failed to persist enrichment for {ip}: {e}")

    async def auto_enrich_incident(self, incident: dict) -> Optional[dict]:
        """
        Automatically enrich an incident's source IP.

        Accepts a dict with at least {"source_ip": "x.x.x.x"}.
        Returns the enrichment result or None if no source IP.

        Integration points (call from these modules without modifying them):
          - log_watcher._create_incident_from_log
          - honeypot interaction handler
          - scanner when suspicious service is found
        """
        source_ip = incident.get("source_ip")
        if not source_ip or not _is_valid_ip(source_ip):
            return None

        logger.info(f"Auto-enriching incident IP: {source_ip}")
        try:
            return await self.enrich_ip(source_ip)
        except Exception as e:
            logger.error(f"Auto-enrichment failed for {source_ip}: {e}")
            return None

    def get_feed_status(self) -> list[dict]:
        """Return status of all configured feeds."""
        feeds = []
        for name, stats in self._feed_stats.items():
            feeds.append({
                "name": name,
                "last_sync": stats["last_sync"],
                "ioc_count": stats["ioc_count"],
                "status": stats["status"],
                "has_api_key": bool(_get_key(f"{name.upper()}_API_KEY"))
                if name in ("abuseipdb", "otx")
                else True,
            })
        return feeds

    def update_config(self, config: dict[str, str]):
        """Update feed API keys at runtime."""
        for key in ("ABUSEIPDB_API_KEY", "OTX_API_KEY"):
            if key in config:
                _feed_config[key] = config[key]
                logger.info(f"Updated feed config: {key}")


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
threat_feed_manager = ThreatFeedManager()
