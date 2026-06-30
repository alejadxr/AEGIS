"""
MongoDB Atlas client for shared threat intelligence hub.

Uses motor (async MongoDB driver) to connect to Atlas.
Only connects if AEGIS_MONGODB_URI is configured in .env.

Database: aegis_intel
Collections:
  - aegis_threats: IOCs detected by THIS AEGIS instance (honeypots, attack detector, AI)
  - external_feeds: IOCs pulled from third-party feeds (AbuseIPDB, OTX, ET, Tor, Feodo)
  - attack_patterns: MITRE ATT&CK patterns observed
  - attacker_profiles: Aggregated attacker behavior profiles

IMPORTANT: aegis_threats and external_feeds NEVER mix.
"""

import logging
from typing import Optional

import certifi
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase

from app.config import settings

logger = logging.getLogger("cayde6.mongo")

_client: Optional[AsyncIOMotorClient] = None
_db: Optional[AsyncIOMotorDatabase] = None

DATABASE_NAME = "aegis_intel"

# Collection names - single source of truth
AEGIS_THREATS_COLLECTION = "aegis_threats"
EXTERNAL_FEEDS_COLLECTION = "external_feeds"


async def connect_mongo() -> bool:
    """Connect to MongoDB Atlas. Returns True if connected, False if not configured."""
    global _client, _db

    if not settings.AEGIS_MONGODB_URI:
        logger.info("AEGIS_MONGODB_URI not set - MongoDB disabled")
        return False

    try:
        _client = AsyncIOMotorClient(
            settings.AEGIS_MONGODB_URI,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
            tlsCAFile=certifi.where(),
        )
        # Verify connection
        await _client.admin.command("ping")
        _db = _client[DATABASE_NAME]
        logger.info(f"Connected to MongoDB Atlas database '{DATABASE_NAME}'")

        # Ensure indexes
        await _ensure_indexes()
        return True
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB Atlas: {e}")
        _client = None
        _db = None
        return False


async def _ensure_indexes():
    """Create indexes for performance on key query patterns."""
    if _db is None:
        return

    # --- aegis_threats indexes (own detections) ---
    aegis = _db[AEGIS_THREATS_COLLECTION]
    await aegis.create_index([("ioc_type", 1), ("ioc_value", 1)], unique=True)
    await aegis.create_index("last_seen")
    await aegis.create_index("source_instance")
    await aegis.create_index("threat_type")
    await aegis.create_index("detection_source")

    # --- external_feeds indexes (third-party feeds) ---
    external = _db[EXTERNAL_FEEDS_COLLECTION]
    await external.create_index([("ioc_type", 1), ("ioc_value", 1), ("feed_source", 1)], unique=True)
    await external.create_index("last_seen")
    await external.create_index("feed_source")
    await external.create_index("threat_type")

    # --- Legacy collections (kept for backward compat) ---
    patterns = _db.attack_patterns
    await patterns.create_index("mitre_id", unique=True)
    await patterns.create_index("last_observed")

    profiles = _db.attacker_profiles
    await profiles.create_index("ip_address", unique=True)
    await profiles.create_index("threat_score")
    await profiles.create_index("last_seen")

    logger.info("MongoDB indexes ensured (aegis_threats + external_feeds)")


def get_mongo_db() -> Optional[AsyncIOMotorDatabase]:
    """Get the aegis_intel database. Returns None if not connected."""
    return _db


def get_aegis_collection() -> Optional[AsyncIOMotorCollection]:
    """Get the aegis_threats collection (own detections ONLY). Returns None if not connected."""
    if _db is None:
        return None
    return _db[AEGIS_THREATS_COLLECTION]


def get_external_collection() -> Optional[AsyncIOMotorCollection]:
    """Get the external_feeds collection (third-party feeds ONLY). Returns None if not connected."""
    if _db is None:
        return None
    return _db[EXTERNAL_FEEDS_COLLECTION]


def is_connected() -> bool:
    """Check if MongoDB is connected."""
    return _db is not None


async def close_mongo():
    """Close the MongoDB connection."""
    global _client, _db
    if _client:
        _client.close()
        _client = None
        _db = None
        logger.info("MongoDB connection closed")
