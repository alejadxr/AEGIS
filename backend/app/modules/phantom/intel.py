import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_intel import ThreatIntel
from app.models.honeypot import HoneypotInteraction
from app.models.attacker_profile import AttackerProfile

logger = logging.getLogger("aegis.phantom.intel")


class ThreatIntelGenerator:
    """Generate threat intelligence IOCs from honeypot data."""

    async def generate_iocs_from_interactions(
        self,
        client_id: str,
        db: AsyncSession,
        hours: int = 24,
    ) -> list[ThreatIntel]:
        """Extract IOCs from recent honeypot interactions."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        result = await db.execute(
            select(HoneypotInteraction)
            .where(
                HoneypotInteraction.client_id == client_id,
                HoneypotInteraction.timestamp >= cutoff,
            )
            .order_by(HoneypotInteraction.timestamp.desc())
        )
        interactions = result.scalars().all()

        iocs_created = []
        seen_values = set()

        for interaction in interactions:
            # IP IOC
            if interaction.source_ip and interaction.source_ip not in seen_values:
                seen_values.add(interaction.source_ip)
                ioc = await self._create_ioc(
                    ioc_type="ip",
                    ioc_value=interaction.source_ip,
                    threat_type="honeypot_attacker",
                    confidence=0.7,
                    source="honeypot",
                    tags=["honeypot", "automated"],
                    db=db,
                )
                iocs_created.append(ioc)

            # Extract IOCs from payloads
            for payload in (interaction.payloads or []):
                if isinstance(payload, str):
                    # Look for URLs, domains, hashes in payloads
                    extracted = self._extract_iocs_from_text(payload)
                    for ioc_type, ioc_value in extracted:
                        if ioc_value not in seen_values:
                            seen_values.add(ioc_value)
                            ioc = await self._create_ioc(
                                ioc_type=ioc_type,
                                ioc_value=ioc_value,
                                threat_type="payload_artifact",
                                confidence=0.6,
                                source="honeypot_payload",
                                tags=["honeypot", "payload", "automated"],
                                db=db,
                            )
                            iocs_created.append(ioc)

            # Credentials as IOCs (for detection of credential reuse)
            for cred in (interaction.credentials_tried or []):
                if isinstance(cred, dict):
                    username = cred.get("username", "")
                    if username and username not in seen_values and len(username) > 3:
                        seen_values.add(username)
                        ioc = await self._create_ioc(
                            ioc_type="email" if "@" in username else "username",
                            ioc_value=username,
                            threat_type="credential_attack",
                            confidence=0.4,
                            source="honeypot_credentials",
                            tags=["honeypot", "credentials", "automated"],
                            db=db,
                        )
                        iocs_created.append(ioc)

        await db.commit()
        logger.info(f"Generated {len(iocs_created)} IOCs from {len(interactions)} interactions")
        return iocs_created

    async def generate_threat_feed(self, db: AsyncSession, format: str = "json") -> dict:
        """Export threat intelligence as a feed."""
        result = await db.execute(
            select(ThreatIntel).order_by(ThreatIntel.last_seen.desc()).limit(1000)
        )
        iocs = result.scalars().all()

        if format == "stix":
            return self._to_stix(iocs)

        return {
            "feed_name": "AEGIS Threat Intel Feed",
            "generated_at": datetime.utcnow().isoformat(),
            "total_indicators": len(iocs),
            "indicators": [
                {
                    "id": ioc.id,
                    "type": ioc.ioc_type,
                    "value": ioc.ioc_value,
                    "threat_type": ioc.threat_type,
                    "confidence": ioc.confidence,
                    "source": ioc.source,
                    "tags": ioc.tags,
                    "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                    "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
                }
                for ioc in iocs
            ],
        }

    async def _create_ioc(
        self,
        ioc_type: str,
        ioc_value: str,
        threat_type: str,
        confidence: float,
        source: str,
        tags: list[str],
        db: AsyncSession,
    ) -> ThreatIntel:
        """Create or update an IOC."""
        # Check if IOC already exists
        result = await db.execute(
            select(ThreatIntel).where(
                ThreatIntel.ioc_type == ioc_type,
                ThreatIntel.ioc_value == ioc_value,
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            existing.last_seen = datetime.utcnow()
            existing.confidence = min(1.0, existing.confidence + 0.05)  # Increase confidence on re-sight
            existing_tags = existing.tags or []
            existing.tags = list(set(existing_tags + tags))
            return existing

        ioc = ThreatIntel(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            threat_type=threat_type,
            confidence=confidence,
            source=source,
            tags=tags,
            expires_at=datetime.utcnow() + timedelta(days=30),
        )
        db.add(ioc)
        return ioc

    def _extract_iocs_from_text(self, text: str) -> list[tuple[str, str]]:
        """Extract IOCs from free text."""
        import re
        iocs = []

        # URLs
        urls = re.findall(r'https?://[^\s<>"\']+', text)
        for url in urls:
            iocs.append(("url", url))

        # Domains
        domains = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text)
        for domain in domains:
            if len(domain) > 5 and "." in domain:
                iocs.append(("domain", domain))

        # MD5 hashes
        md5s = re.findall(r'\b[a-fA-F0-9]{32}\b', text)
        for h in md5s:
            iocs.append(("hash", h))

        # SHA256 hashes
        sha256s = re.findall(r'\b[a-fA-F0-9]{64}\b', text)
        for h in sha256s:
            iocs.append(("hash", h))

        return iocs

    def _to_stix(self, iocs: list) -> dict:
        """Convert IOCs to STIX 2.1 format."""
        stix_type_map = {
            "ip": "ipv4-addr",
            "domain": "domain-name",
            "url": "url",
            "hash": "file",
            "email": "email-addr",
        }
        objects = []
        for ioc in iocs:
            stix_type = stix_type_map.get(ioc.ioc_type, "indicator")
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{ioc.id}",
                "created": ioc.first_seen.isoformat() if ioc.first_seen else datetime.utcnow().isoformat(),
                "modified": ioc.last_seen.isoformat() if ioc.last_seen else datetime.utcnow().isoformat(),
                "name": f"{ioc.ioc_type}: {ioc.ioc_value}",
                "pattern": f"[{stix_type}:value = '{ioc.ioc_value}']",
                "pattern_type": "stix",
                "valid_from": ioc.first_seen.isoformat() if ioc.first_seen else datetime.utcnow().isoformat(),
                "labels": ioc.tags or [],
                "confidence": int((ioc.confidence or 0.5) * 100),
            })

        return {
            "type": "bundle",
            "id": f"bundle--aegis-feed",
            "objects": objects,
        }


threat_intel_generator = ThreatIntelGenerator()
