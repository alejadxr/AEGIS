"""
Threat Intel Cloud API — Community IOC sharing and hub endpoints.

Router prefix: /intel (mounted under /api/v1 in main.py)

Client endpoints (any AEGIS instance):
  POST   /intel/share            — submit an IOC to the cloud (requires opt-in)
  GET    /intel/community        — get community IOCs (paginated, filtered)
  GET    /intel/community/stats  — sharing statistics
  PUT    /intel/sharing/config   — enable/disable sharing, set preferences
  GET    /intel/sharing/config   — current sharing config
  POST   /intel/sync             — manual sync with cloud

Hub endpoints (when this instance IS the cloud):
  POST   /intel/hub/submit       — receive IOC from another instance
  GET    /intel/hub/feed         — serve IOCs to other instances (JSON)
  GET    /intel/hub/feed/stix    — STIX 2.1 format export (TAXII-like)
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.core.auth import AuthContext, require_admin, require_analyst, require_viewer
from app.services.intel_cloud import intel_cloud

logger = logging.getLogger("aegis.api.intel_cloud")

router = APIRouter(prefix="/intel", tags=["intel-cloud"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class IOCSubmission(BaseModel):
    """Schema for submitting an IOC to the cloud."""
    ioc_type: str = Field(..., description="ip | domain | hash | url")
    ioc_value: str = Field(..., description="The indicator value")
    threat_type: str = Field(..., description="brute_force, c2, phishing, malware, etc.")
    confidence: float = Field(0.75, ge=0.0, le=1.0, description="Confidence score 0.0-1.0")
    mitre_techniques: list[str] = Field(default_factory=list, description="MITRE ATT&CK IDs")
    first_seen: Optional[str] = Field(None, description="ISO 8601 timestamp of first observation")


class IOCSubmissionResponse(BaseModel):
    status: str
    ioc_id: Optional[str] = None
    report_count: Optional[int] = None
    reason: Optional[str] = None


class CommunityIOC(BaseModel):
    id: str
    ioc_type: str
    ioc_value: str
    threat_type: str
    confidence: float
    mitre_techniques: list[str] = []
    source_hash: str
    report_count: int
    verified: bool
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    expires_at: Optional[str] = None


class CommunityIOCsResponse(BaseModel):
    iocs: list[CommunityIOC]
    total: int
    page: int
    per_page: int
    pages: int


class SharingStats(BaseModel):
    iocs_submitted: int
    iocs_received: int
    last_sync: Optional[str] = None
    unique_contributors: int
    sync_errors: int
    sharing_enabled: bool
    share_mode: str
    is_hub: bool
    hub_url: str


class SharingConfigUpdate(BaseModel):
    intel_sharing_enabled: Optional[bool] = None
    share_mode: Optional[str] = Field(None, description="both | share_only | consume_only")
    hub_url: Optional[str] = Field(None, description="URL of hub instance (empty = this IS the hub)")
    auto_submit: Optional[bool] = None
    min_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    cloud_secret: Optional[str] = Field(None, description="HMAC signing key for IOC submissions")


class SharingConfigResponse(BaseModel):
    intel_sharing_enabled: bool
    share_mode: str
    hub_url: str
    auto_submit: bool
    min_confidence: float


class SyncResponse(BaseModel):
    status: str
    new: int = 0
    updated: int = 0
    decayed: int = 0
    errors: int = 0
    message: Optional[str] = None


class HubSubmission(BaseModel):
    """Schema for IOC received from another AEGIS instance (hub endpoint)."""
    ioc_type: str
    ioc_value: str
    threat_type: str
    confidence: float = 0.5
    mitre_techniques: list[str] = []
    first_seen: Optional[str] = None
    source_hash: str
    signature: str


# ---------------------------------------------------------------------------
# Client endpoints
# ---------------------------------------------------------------------------

@router.post("/share", response_model=IOCSubmissionResponse)
async def share_ioc(
    body: IOCSubmission,
    auth: AuthContext = Depends(require_analyst),
):
    """
    Submit an IOC to the shared threat intelligence cloud.

    Requires intel sharing to be enabled (opt-in). The IOC is anonymized
    before submission -- no client-identifying data is transmitted, only
    a hashed contributor ID for deduplication.
    """
    if not intel_cloud.can_share:
        raise HTTPException(
            status_code=403,
            detail="Intel sharing is disabled or configured as consume-only. "
                   "Enable sharing via PUT /api/v1/intel/sharing/config",
        )

    result = await intel_cloud.submit_ioc(
        ioc_data=body.model_dump(),
        client_id=auth.client_id,
    )

    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("reason", "Internal error"))

    return IOCSubmissionResponse(**result)


@router.get("/community", response_model=CommunityIOCsResponse)
async def get_community_iocs(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=200, description="Items per page"),
    ioc_type: Optional[str] = Query(None, description="Filter by IOC type"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    verified_only: bool = Query(False, description="Only verified IOCs"),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0, description="Minimum confidence"),
    since: Optional[str] = Query(None, description="ISO 8601 timestamp — only IOCs updated since"),
    auth: AuthContext = Depends(require_viewer),
):
    """
    Get community-shared IOCs with pagination and filtering.

    Returns IOCs that have been shared by the AEGIS community.
    Verified IOCs have been independently confirmed by multiple sources.
    """
    result = await intel_cloud.get_community_iocs(
        page=page,
        per_page=per_page,
        ioc_type=ioc_type,
        threat_type=threat_type,
        verified_only=verified_only,
        min_confidence=min_confidence,
        since=since,
    )
    return CommunityIOCsResponse(**result)


@router.get("/community/stats", response_model=SharingStats)
async def get_sharing_stats(
    auth: AuthContext = Depends(require_viewer),
):
    """
    Get sharing statistics: total shared, total received, contributor count.
    """
    stats = intel_cloud.get_stats()
    return SharingStats(**stats)


@router.put("/sharing/config", response_model=SharingConfigResponse)
async def update_sharing_config(
    body: SharingConfigUpdate,
    auth: AuthContext = Depends(require_admin),
):
    """
    Enable/disable intel sharing and configure preferences.

    Admin only. Changes take effect immediately.

    - intel_sharing_enabled: master toggle (default: false, opt-in required)
    - share_mode: "both" (share and consume), "share_only", or "consume_only"
    - hub_url: URL of the hub instance (leave empty if this IS the hub)
    - min_confidence: minimum confidence threshold for sharing
    - cloud_secret: HMAC signing key for IOC submissions
    """
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No configuration fields provided")

    try:
        intel_cloud.update_config(updates)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    logger.info(f"Intel sharing config updated by {auth.email or 'api-key'}: {list(updates.keys())}")
    config = intel_cloud.get_config()
    return SharingConfigResponse(**config)


@router.get("/sharing/config", response_model=SharingConfigResponse)
async def get_sharing_config(
    auth: AuthContext = Depends(require_viewer),
):
    """Get current intel sharing configuration."""
    config = intel_cloud.get_config()
    return SharingConfigResponse(**config)


@router.post("/sync", response_model=SyncResponse)
async def manual_sync(
    auth: AuthContext = Depends(require_analyst),
):
    """
    Trigger a manual sync with the cloud.

    Pulls latest community IOCs and applies confidence decay to old entries.
    Automatic sync runs every 15 minutes when sharing is enabled.
    """
    result = await intel_cloud.manual_sync()
    if isinstance(result, dict) and result.get("status") == "disabled":
        return SyncResponse(status="disabled", message=result.get("message", "Sharing is disabled"))

    return SyncResponse(
        status="completed",
        new=result.get("new", 0),
        updated=result.get("updated", 0),
        decayed=result.get("decayed", 0),
        errors=result.get("errors", 0),
    )


# ---------------------------------------------------------------------------
# Hub endpoints (when this instance IS the cloud)
# ---------------------------------------------------------------------------

@router.post("/hub/submit", response_model=IOCSubmissionResponse)
async def hub_receive_ioc(body: HubSubmission):
    """
    Receive an IOC from another AEGIS instance.

    This endpoint is called by remote AEGIS clients that have configured
    this instance as their hub. No auth required (HMAC signature verification
    provides authentication).

    The signature is verified against the shared cloud secret. If the signature
    is invalid, the submission is rejected.
    """
    # Verify HMAC signature
    ioc_data = body.model_dump()
    signature = ioc_data.pop("signature", "")

    if not intel_cloud._verify_signature(ioc_data, signature):
        raise HTTPException(status_code=403, detail="Invalid HMAC signature")

    result = await intel_cloud._store_ioc(ioc_data)

    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("reason", "Storage error"))

    return IOCSubmissionResponse(**result)


@router.get("/hub/feed")
async def hub_serve_feed(
    since: Optional[str] = Query(None, description="ISO 8601 — only IOCs updated since"),
    limit: int = Query(500, ge=1, le=5000, description="Maximum IOCs to return"),
):
    """
    Serve community IOCs to other AEGIS instances (JSON format).

    This is the primary feed endpoint that clients poll every 15 minutes.
    Supports incremental sync via the `since` parameter.

    No auth required — IOCs are already anonymized.
    """
    return await intel_cloud.get_hub_feed(since=since, limit=limit)


@router.get("/hub/feed/stix")
async def hub_serve_stix_feed(
    since: Optional[str] = Query(None, description="ISO 8601 — only IOCs updated since"),
    limit: int = Query(500, ge=1, le=5000, description="Maximum indicators to return"),
):
    """
    Serve community IOCs in STIX 2.1 Bundle format.

    Compatible with enterprise SIEMs and threat intelligence platforms
    that support STIX ingestion. Each IOC is converted to a STIX Indicator
    object with proper pattern syntax and MITRE ATT&CK references.

    This endpoint provides TAXII-like functionality for interoperability
    with tools like Splunk, QRadar, Sentinel, and OpenCTI.
    """
    return await intel_cloud.get_hub_feed_stix(since=since, limit=limit)
