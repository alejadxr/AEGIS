"""
Threat Intel Hub API - MongoDB Atlas shared intelligence endpoints.

DUAL COLLECTION ARCHITECTURE:
  - /intel/mongo/feed -> aegis_threats only (own detections)
  - /intel/mongo/external -> external_feeds only (third-party)
  - /intel/mongo/all -> both combined, labeled with "collection" field
  - /intel/mongo/stats -> separate counts for each

Router prefix: /intel/mongo (mounted under /api/v1 in main.py)
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core.auth import AuthContext, require_analyst, require_viewer
from app.core.mongo_client import is_connected
from app.services.threat_intel_hub import threat_intel_hub

logger = logging.getLogger("cayde6.api.threat_intel_hub")

router = APIRouter(prefix="/intel/mongo", tags=["intel-mongo-hub"])


# --- Schemas ---

class MongoIOCShare(BaseModel):
    ioc_type: str = Field(..., description="ip | domain | hash | url")
    ioc_value: str = Field(..., description="The indicator value")
    threat_type: str = Field("unknown", description="brute_force, c2, phishing, malware, etc.")
    confidence: float = Field(0.75, ge=0.0, le=1.0)
    mitre_techniques: list[str] = Field(default_factory=list)
    detection_source: str = Field("manual", description="Source: manual, attack_detector, honeypot, ai_engine")


class MongoIOCResponse(BaseModel):
    status: str
    upserted: Optional[bool] = None
    reason: Optional[str] = None


class MongoFeedResponse(BaseModel):
    iocs: list[dict]
    count: int
    source: str = "mongodb_atlas"
    collection: str = "aegis_threats"


class MongoDualStatsResponse(BaseModel):
    instance_id: str
    connected: bool
    last_sync: Optional[str] = None
    iocs_shared: int
    iocs_pulled: int
    external_pushed: int
    sync_count: int
    sync_errors: int
    collections: dict


# --- Endpoints ---

@router.post("/share", response_model=MongoIOCResponse)
async def share_ioc_to_mongo(
    body: MongoIOCShare,
    auth: AuthContext = Depends(require_analyst),
):
    """Share an IOC to aegis_threats (own detections ONLY)."""
    if not is_connected():
        raise HTTPException(status_code=503, detail="MongoDB Atlas not connected")

    result = await threat_intel_hub.share_ioc(body.model_dump())
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("reason"))

    return MongoIOCResponse(**result)


@router.get("/feed", response_model=MongoFeedResponse)
async def get_aegis_feed(
    since: Optional[str] = Query(None, description="ISO 8601 timestamp"),
    auth: AuthContext = Depends(require_viewer),
):
    """Get IOCs from aegis_threats ONLY (own detections)."""
    if not is_connected():
        raise HTTPException(status_code=503, detail="MongoDB Atlas not connected")

    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid ISO 8601 timestamp")

    iocs = await threat_intel_hub.pull_iocs(since=since_dt)

    for ioc in iocs:
        for key in ("first_seen", "last_seen"):
            if isinstance(ioc.get(key), datetime):
                ioc[key] = ioc[key].isoformat()

    return MongoFeedResponse(iocs=iocs, count=len(iocs), collection="aegis_threats")


@router.get("/external")
async def get_external_feed(
    source: Optional[str] = Query(None, description="Filter by feed source (e.g. abuseipdb, emerging_threats)"),
    auth: AuthContext = Depends(require_viewer),
):
    """Get IOCs from external_feeds ONLY (third-party feeds)."""
    if not is_connected():
        raise HTTPException(status_code=503, detail="MongoDB Atlas not connected")

    iocs = await threat_intel_hub.pull_external(source=source)

    for ioc in iocs:
        for key in ("first_seen", "last_seen"):
            if isinstance(ioc.get(key), datetime):
                ioc[key] = ioc[key].isoformat()

    return {"iocs": iocs, "count": len(iocs), "source": "mongodb_atlas", "collection": "external_feeds"}


@router.get("/all")
async def get_all_intel(
    auth: AuthContext = Depends(require_viewer),
):
    """Get IOCs from BOTH collections, each labeled with 'collection' field."""
    if not is_connected():
        raise HTTPException(status_code=503, detail="MongoDB Atlas not connected")

    aegis_iocs = await threat_intel_hub.pull_iocs()
    external_iocs = await threat_intel_hub.pull_external()

    all_iocs = aegis_iocs + external_iocs

    for ioc in all_iocs:
        for key in ("first_seen", "last_seen"):
            if isinstance(ioc.get(key), datetime):
                ioc[key] = ioc[key].isoformat()

    return {
        "iocs": all_iocs,
        "count": len(all_iocs),
        "aegis_count": len(aegis_iocs),
        "external_count": len(external_iocs),
    }


@router.get("/stats", response_model=MongoDualStatsResponse)
async def get_mongo_hub_stats(
    auth: AuthContext = Depends(require_viewer),
):
    """Get MongoDB threat intel hub statistics with dual collection counts."""
    if not is_connected():
        raise HTTPException(status_code=503, detail="MongoDB Atlas not connected")

    stats = threat_intel_hub.get_stats()
    dual = await threat_intel_hub.get_dual_stats()

    return MongoDualStatsResponse(
        instance_id=stats["instance_id"],
        connected=stats["connected"],
        last_sync=stats.get("last_sync"),
        iocs_shared=stats["iocs_shared"],
        iocs_pulled=stats["iocs_pulled"],
        external_pushed=stats["external_pushed"],
        sync_count=stats["sync_count"],
        sync_errors=stats["sync_errors"],
        collections=dual,
    )
