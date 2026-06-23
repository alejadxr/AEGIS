"""
Threat Intel Hub - MongoDB Atlas shared intelligence service.

DUAL COLLECTION ARCHITECTURE:
  - aegis_threats: IOCs detected by THIS instance (honeypots, attack detector, AI)
  - external_feeds: IOCs from third-party feeds (AbuseIPDB, OTX, ET, Tor, Feodo)

These two collections NEVER mix.

Sync loop runs every 5 minutes:
  1. Pull new IOCs from aegis_threats (since last sync, from other instances)
  2. Merge into local PostgreSQL shared_iocs table
  3. Push locally-detected IOCs to aegis_threats for other instances
"""

import asyncio
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select

from app.config import settings
from app.core.mongo_client import (
    get_mongo_db, get_aegis_collection, get_external_collection, is_connected,
)
from app.database import async_session
from app.models.shared_intel import SharedIOC

logger = logging.getLogger("cayde6.threat_intel_hub")

SYNC_INTERVAL = 300  # 5 minutes


def _utcnow_naive() -> datetime:
    """UTC now without tzinfo for PostgreSQL DateTime columns."""
    return datetime.utcnow()


class ThreatIntelHub:
    def __init__(self):
        self.instance_id = self._generate_instance_id()
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._last_sync: Optional[datetime] = None
        self._stats = {
            "iocs_shared": 0,
            "iocs_pulled": 0,
            "external_pushed": 0,
            "sync_count": 0,
            "sync_errors": 0,
        }

    def _generate_instance_id(self) -> str:
        """Generate a stable instance ID based on machine + config hash."""
        seed = f"{settings.AEGIS_SECRET_KEY}-{settings.DATABASE_URL}"
        return hashlib.sha256(seed.encode()).hexdigest()[:16]

    async def start(self):
        """Start the sync loop if MongoDB is connected."""
        if not is_connected():
            logger.info("Threat intel hub not starting - MongoDB not connected")
            return
        self._running = True
        self._task = asyncio.create_task(self._sync_loop())
        logger.info(f"Threat intel hub started (instance={self.instance_id[:8]}...)")

    async def stop(self):
        """Stop the sync loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Threat intel hub stopped")

    async def _sync_loop(self):
        """Main sync loop - pull and push IOCs every 5 minutes."""
        while self._running:
            try:
                await self._do_sync()
                self._stats["sync_count"] += 1
            except Exception as e:
                logger.error(f"Sync error: {e}")
                self._stats["sync_errors"] += 1
            await asyncio.sleep(SYNC_INTERVAL)

    async def _do_sync(self):
        """Execute one sync cycle: pull from aegis_threats, push local IOCs."""
        collection = get_aegis_collection()
        if collection is None:
            return

        pulled = await self._pull_iocs_from_collection(collection)
        pushed = await self._push_local_iocs(collection)
        self._last_sync = datetime.utcnow()
        logger.info(f"Sync complete: pulled={pulled}, pushed={pushed}")

    async def _pull_iocs_from_collection(self, collection) -> int:
        """Pull new IOCs from aegis_threats and merge into local PostgreSQL."""
        query = {"source_instance": {"$ne": self.instance_id}}

        if self._last_sync:
            query["last_seen"] = {"$gte": self._last_sync}

        count = 0
        async for doc in collection.find(query).sort("last_seen", -1).limit(500):
            try:
                await self._merge_ioc_to_postgres(doc)
                count += 1
            except Exception as e:
                logger.warning(f"Failed to merge IOC {doc.get('ioc_value')}: {e}")

        self._stats["iocs_pulled"] += count
        return count

    async def _merge_ioc_to_postgres(self, doc: dict):
        """Upsert a MongoDB IOC into local PostgreSQL shared_iocs table."""
        async with async_session() as session:
            result = await session.execute(
                select(SharedIOC).where(
                    SharedIOC.ioc_type == doc["ioc_type"],
                    SharedIOC.ioc_value == doc["ioc_value"],
                )
            )
            existing = result.scalar_one_or_none()

            if existing:
                if doc.get("confidence", 0) > existing.confidence:
                    existing.confidence = doc["confidence"]
                existing.report_count = max(existing.report_count, doc.get("report_count", 1))
                existing.last_seen = datetime.utcnow()
                if doc.get("report_count", 1) >= 3:
                    existing.verified = True
            else:
                ioc = SharedIOC(
                    ioc_type=doc["ioc_type"],
                    ioc_value=doc["ioc_value"],
                    threat_type=doc.get("threat_type", "unknown"),
                    confidence=doc.get("confidence", 0.5),
                    mitre_techniques=doc.get("mitre_techniques", []),
                    source_hash=doc.get("source_instance", "unknown"),
                    report_count=doc.get("report_count", 1),
                    verified=doc.get("report_count", 1) >= 3,
                    first_seen=doc.get("first_seen", datetime.utcnow()),
                    last_seen=datetime.utcnow(),
                )
                session.add(ioc)

            await session.commit()

    async def _push_local_iocs(self, collection) -> int:
        """Push locally-detected IOCs to aegis_threats for other instances."""
        since = _utcnow_naive() - timedelta(hours=24)
        async with async_session() as session:
            result = await session.execute(
                select(SharedIOC).where(
                    SharedIOC.last_seen >= since,
                    SharedIOC.confidence >= 0.6,
                )
            )
            local_iocs = result.scalars().all()

        count = 0
        for ioc in local_iocs:
            try:
                await collection.update_one(
                    {"ioc_type": ioc.ioc_type, "ioc_value": ioc.ioc_value},
                    {
                        "$set": {
                            "threat_type": ioc.threat_type,
                            "confidence": ioc.confidence,
                            "mitre_techniques": ioc.mitre_techniques or [],
                            "source_instance": self.instance_id,
                            "last_seen": datetime.utcnow(),
                        },
                        "$setOnInsert": {
                            "first_seen": ioc.first_seen or datetime.utcnow(),
                            "report_count": 1,
                        },
                    },
                    upsert=True,
                )
                count += 1
            except Exception as e:
                logger.warning(f"Failed to push IOC {ioc.ioc_value}: {e}")

        self._stats["iocs_shared"] += count
        return count

    # ------------------------------------------------------------------
    # AEGIS THREATS (own detections only)
    # ------------------------------------------------------------------

    async def share_ioc(self, data: dict) -> dict:
        """Share an IOC to aegis_threats collection (own detections ONLY)."""
        collection = get_aegis_collection()
        if collection is None:
            return {"status": "error", "reason": "MongoDB not connected"}

        doc = {
            "ioc_type": data["ioc_type"],
            "ioc_value": data["ioc_value"],
            "threat_type": data.get("threat_type", "unknown"),
            "confidence": data.get("confidence", 0.5),
            "mitre_techniques": data.get("mitre_techniques", []),
            "detection_source": data.get("detection_source", "manual"),
            "source_instance": self.instance_id,
            "first_seen": datetime.utcnow(),
            "last_seen": datetime.utcnow(),
            "report_count": 1,
        }

        result = await collection.update_one(
            {"ioc_type": doc["ioc_type"], "ioc_value": doc["ioc_value"]},
            {"$set": doc},
            upsert=True,
        )

        self._stats["iocs_shared"] += 1
        return {"status": "shared", "upserted": result.upserted_id is not None}

    async def pull_iocs(self, since: Optional[datetime] = None) -> list[dict]:
        """Pull IOCs from aegis_threats ONLY."""
        collection = get_aegis_collection()
        if collection is None:
            return []

        query = {}
        if since:
            query["last_seen"] = {"$gte": since}

        results = []
        async for doc in collection.find(query).sort("last_seen", -1).limit(500):
            doc["_id"] = str(doc["_id"])
            doc["collection"] = "aegis_threats"
            results.append(doc)

        return results

    # ------------------------------------------------------------------
    # EXTERNAL FEEDS (third-party only)
    # ------------------------------------------------------------------

    async def push_external(self, source: str, iocs: list[dict]) -> int:
        """Push IOCs from a third-party feed to external_feeds collection.

        Args:
            source: Feed name (e.g. 'abuseipdb', 'emerging_threats', 'tor_exit_nodes')
            iocs: List of dicts with at least ioc_type, ioc_value, threat_type
        Returns:
            Number of IOCs upserted
        """
        collection = get_external_collection()
        if collection is None:
            return 0

        count = 0
        now = datetime.utcnow()
        for ioc in iocs:
            try:
                await collection.update_one(
                    {
                        "ioc_type": ioc["ioc_type"],
                        "ioc_value": ioc["ioc_value"],
                        "feed_source": source,
                    },
                    {
                        "$set": {
                            "threat_type": ioc.get("threat_type", "unknown"),
                            "confidence": ioc.get("confidence", 0.7),
                            "feed_source": source,
                            "tags": ioc.get("tags", [source]),
                            "last_seen": now,
                        },
                        "$setOnInsert": {
                            "first_seen": now,
                        },
                    },
                    upsert=True,
                )
                count += 1
            except Exception as e:
                logger.warning(f"Failed to push external IOC {ioc.get('ioc_value')}: {e}")

        self._stats["external_pushed"] += count
        logger.info(f"Pushed {count} IOCs to external_feeds from {source}")
        return count

    async def pull_external(self, source: Optional[str] = None) -> list[dict]:
        """Pull IOCs from external_feeds ONLY.

        Args:
            source: Optional feed source filter (e.g. 'abuseipdb')
        Returns:
            List of IOC dicts
        """
        collection = get_external_collection()
        if collection is None:
            return []

        query = {}
        if source:
            query["feed_source"] = source

        results = []
        async for doc in collection.find(query).sort("last_seen", -1).limit(500):
            doc["_id"] = str(doc["_id"])
            doc["collection"] = "external_feeds"
            results.append(doc)

        return results

    async def get_dual_stats(self) -> dict:
        """Get separate counts for aegis_threats and external_feeds."""
        aegis_col = get_aegis_collection()
        external_col = get_external_collection()

        aegis_count = 0
        external_count = 0
        external_by_source: dict[str, int] = {}

        if aegis_col is not None:
            aegis_count = await aegis_col.count_documents({})

        if external_col is not None:
            external_count = await external_col.count_documents({})
            # Breakdown by feed source
            pipeline = [
                {"$group": {"_id": "$feed_source", "count": {"$sum": 1}}}
            ]
            async for doc in external_col.aggregate(pipeline):
                external_by_source[doc["_id"] or "unknown"] = doc["count"]

        return {
            "aegis_threats": aegis_count,
            "external_feeds": external_count,
            "external_by_source": external_by_source,
            "total": aegis_count + external_count,
        }

    def get_stats(self) -> dict:
        """Return hub statistics."""
        return {
            "instance_id": self.instance_id[:8] + "...",
            "connected": is_connected(),
            "last_sync": self._last_sync.isoformat() if self._last_sync else None,
            **self._stats,
        }


# Module-level singleton
threat_intel_hub = ThreatIntelHub()
