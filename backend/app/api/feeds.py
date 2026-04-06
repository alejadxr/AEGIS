"""
Threat Intelligence Feeds API — external IOC enrichment and blocklist management.

Router prefix: /feeds (mounted under /api/v1 in main.py)

Endpoints:
  GET    /feeds              — list configured feeds with sync status
  POST   /feeds/sync         — trigger manual refresh of all blocklists
  GET    /feeds/enrich/{ip}  — full enrichment of a single IP
  GET    /feeds/check/{ip}   — quick reputation check (cached blocklists only)
  PUT    /feeds/config       — update API keys for AbuseIPDB / OTX
"""

import ipaddress
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, field_validator

from app.core.auth import AuthContext, require_admin, require_analyst, require_viewer
from app.services.threat_feeds import threat_feed_manager

logger = logging.getLogger("aegis.api.feeds")

router = APIRouter(prefix="/feeds", tags=["feeds"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class FeedStatus(BaseModel):
    name: str
    last_sync: Optional[str] = None
    ioc_count: int = 0
    status: str = "idle"
    has_api_key: bool = False


class FeedSyncResponse(BaseModel):
    message: str
    status: str


class EnrichmentResponse(BaseModel):
    ip: str
    risk_score: float = 0.0
    verdict: str = "unknown"
    abuseipdb: Optional[dict] = None
    otx: Optional[dict] = None
    blocklist_hits: list[dict] = []
    enriched_at: Optional[str] = None
    error: Optional[str] = None


class ReputationResponse(BaseModel):
    ip: str
    verdict: str = "unknown"
    blocklist_hits: list[dict] = []
    db_records: list[dict] = []
    checked_at: Optional[str] = None
    error: Optional[str] = None


class FeedConfigUpdate(BaseModel):
    ABUSEIPDB_API_KEY: Optional[str] = None
    OTX_API_KEY: Optional[str] = None

    @field_validator("ABUSEIPDB_API_KEY", "OTX_API_KEY", mode="before")
    @classmethod
    def strip_whitespace(cls, v):
        if isinstance(v, str):
            return v.strip()
        return v


class FeedConfigResponse(BaseModel):
    message: str
    updated_keys: list[str]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_ip(ip: str) -> str:
    """Validate and return the IP, or raise 400."""
    try:
        addr = ipaddress.ip_address(ip.strip())
        return str(addr)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("", response_model=list[FeedStatus])
async def list_feeds(
    auth: AuthContext = Depends(require_viewer),
):
    """List all configured threat feeds with their sync status and IOC counts."""
    return threat_feed_manager.get_feed_status()


@router.post("/sync", response_model=FeedSyncResponse)
async def sync_feeds(
    background_tasks: BackgroundTasks,
    auth: AuthContext = Depends(require_analyst),
):
    """
    Trigger a manual refresh of all external blocklists.

    The refresh runs in the background; the response returns immediately.
    """
    background_tasks.add_task(threat_feed_manager.refresh_blocklists)
    logger.info(f"Manual feed sync triggered by {auth.email or 'api-key'}")
    return FeedSyncResponse(
        message="Feed sync started in background",
        status="syncing",
    )


@router.get("/enrich/{ip}", response_model=EnrichmentResponse)
async def enrich_ip(
    ip: str,
    auth: AuthContext = Depends(require_analyst),
):
    """
    Full enrichment of a single IP address from all available sources.

    Queries AbuseIPDB (if key configured), AlienVault OTX, and checks
    against cached blocklists. Returns a consolidated risk score and verdict.

    Rate note: AbuseIPDB free tier allows 1000 checks/day.
    """
    validated_ip = _validate_ip(ip)
    result = await threat_feed_manager.enrich_ip(validated_ip)
    return EnrichmentResponse(**result)


@router.get("/check/{ip}", response_model=ReputationResponse)
async def check_ip(
    ip: str,
    auth: AuthContext = Depends(require_viewer),
):
    """
    Quick reputation check against cached blocklists and the local DB.

    No external API calls are made — this is instant and does not consume
    any API quota.
    """
    validated_ip = _validate_ip(ip)
    result = await threat_feed_manager.check_ip_reputation(validated_ip)
    return ReputationResponse(**result)


@router.put("/config", response_model=FeedConfigResponse)
async def update_feed_config(
    body: FeedConfigUpdate,
    auth: AuthContext = Depends(require_admin),
):
    """
    Update API keys for AbuseIPDB and/or OTX at runtime.

    Admin only. Keys are stored in memory (not persisted to .env).
    Set in .env or pass here for the current session.
    """
    config: dict[str, str] = {}
    updated: list[str] = []

    if body.ABUSEIPDB_API_KEY is not None:
        config["ABUSEIPDB_API_KEY"] = body.ABUSEIPDB_API_KEY
        updated.append("ABUSEIPDB_API_KEY")
    if body.OTX_API_KEY is not None:
        config["OTX_API_KEY"] = body.OTX_API_KEY
        updated.append("OTX_API_KEY")

    if not config:
        raise HTTPException(status_code=400, detail="No keys provided to update")

    threat_feed_manager.update_config(config)
    logger.info(f"Feed config updated by {auth.email or 'api-key'}: {updated}")

    return FeedConfigResponse(
        message="Feed configuration updated",
        updated_keys=updated,
    )
