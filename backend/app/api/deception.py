"""Honey-AI Deception at Scale — REST API.

All endpoints are gated behind the ``honey_ai_deception`` enterprise feature.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthContext, require_analyst, require_viewer
from app.database import get_db
from app.models.honey_breadcrumb import HoneyBreadcrumb
from app.services.honey_ai import (
    Campaign,
    ServiceMix,
    THEMES,
    breadcrumb_tracker,
    deception_orchestrator,
)
from app.services.subscription import require_feature

router = APIRouter(prefix="/deception", tags=["deception"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ServiceMixIn(BaseModel):
    web: int = 40
    db: int = 30
    files: int = 20
    admin: int = 10

    @field_validator("web", "db", "files", "admin")
    @classmethod
    def _check_pct(cls, v: int) -> int:
        if v < 0 or v > 100:
            raise ValueError("Service mix percentages must be between 0 and 100")
        return v


class CampaignCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    theme: str = Field("fintech", max_length=50)
    decoy_count: int = Field(50, ge=1, le=500)
    service_mix: ServiceMixIn = Field(default_factory=ServiceMixIn)
    rotation_hours: int = Field(6, ge=1, le=168)


class CampaignOut(BaseModel):
    id: str
    name: str
    theme: str
    decoy_count: int
    service_mix: dict
    rotation_hours: int
    status: str
    created_at: str
    deployed_at: Optional[str] = None
    last_rotated_at: Optional[str] = None
    stopped_at: Optional[str] = None
    honeypot_count: int
    breadcrumb_count: int
    error: Optional[str] = None


class BreadcrumbHitOut(BaseModel):
    id: str
    campaign_id: str
    breadcrumb_uuid: str
    planted_in: str
    bait_kind: str
    hit_count: int
    last_hit_at: Optional[str] = None
    last_hit_source: Optional[str] = None
    planted_at: str


class ThemeOut(BaseModel):
    name: str
    label: str
    description: str
    industry: str
    bait_kinds: list[str]


# ---------------------------------------------------------------------------
# Themes
# ---------------------------------------------------------------------------


@router.get("/themes", response_model=list[ThemeOut])
async def list_themes(auth: AuthContext = Depends(require_viewer)):
    """Return the built-in deception themes."""
    require_feature(auth.client, "honey_ai_deception", "enterprise")
    return [
        ThemeOut(
            name=t.name,
            label=t.label,
            description=t.description,
            industry=t.industry,
            bait_kinds=t.bait_kinds,
        )
        for t in THEMES.values()
    ]


# ---------------------------------------------------------------------------
# Campaigns
# ---------------------------------------------------------------------------


@router.get("/campaigns", response_model=list[CampaignOut])
async def list_campaigns(auth: AuthContext = Depends(require_viewer)):
    """List all deception campaigns for the current client."""
    require_feature(auth.client, "honey_ai_deception", "enterprise")
    campaigns = deception_orchestrator.list_campaigns(client_id=auth.client.id)
    return [CampaignOut(**c.to_dict()) for c in campaigns]


@router.post("/campaigns", response_model=CampaignOut, status_code=201)
async def create_campaign(
    body: CampaignCreate,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Create and deploy a new deception campaign."""
    require_feature(auth.client, "honey_ai_deception", "enterprise")

    if body.theme not in THEMES:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown theme '{body.theme}'. Available: {list(THEMES.keys())}",
        )

    try:
        service_mix = ServiceMix(
            web=body.service_mix.web,
            db=body.service_mix.db,
            files=body.service_mix.files,
            admin=body.service_mix.admin,
        )
        service_mix.validate()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    campaign = Campaign(
        name=body.name,
        client_id=auth.client.id,
        theme=body.theme,
        decoy_count=body.decoy_count,
        service_mix=service_mix,
        rotation_hours=body.rotation_hours,
    )

    try:
        await deception_orchestrator.deploy_campaign(
            campaign, db, client=auth.client
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:  # pragma: no cover
        raise HTTPException(status_code=500, detail=f"Deploy failed: {e}")

    return CampaignOut(**campaign.to_dict())


@router.get("/campaigns/{campaign_id}", response_model=CampaignOut)
async def get_campaign(
    campaign_id: str,
    auth: AuthContext = Depends(require_viewer),
):
    """Return a single campaign."""
    require_feature(auth.client, "honey_ai_deception", "enterprise")
    campaign = deception_orchestrator.get(campaign_id)
    if not campaign or campaign.client_id != auth.client.id:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return CampaignOut(**campaign.to_dict())


@router.post("/campaigns/{campaign_id}/rotate", response_model=CampaignOut)
async def rotate_campaign(
    campaign_id: str,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Rotate a campaign — tears down and redeploys with fresh breadcrumbs."""
    require_feature(auth.client, "honey_ai_deception", "enterprise")
    campaign = deception_orchestrator.get(campaign_id)
    if not campaign or campaign.client_id != auth.client.id:
        raise HTTPException(status_code=404, detail="Campaign not found")
    rotated = await deception_orchestrator.rotate_campaign(
        campaign_id, db, client=auth.client
    )
    if not rotated:
        raise HTTPException(status_code=404, detail="Campaign not found after rotate")
    return CampaignOut(**rotated.to_dict())


@router.delete("/campaigns/{campaign_id}", status_code=204)
async def delete_campaign(
    campaign_id: str,
    auth: AuthContext = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Stop a campaign and tear down its decoys."""
    require_feature(auth.client, "honey_ai_deception", "enterprise")
    campaign = deception_orchestrator.get(campaign_id)
    if not campaign or campaign.client_id != auth.client.id:
        raise HTTPException(status_code=404, detail="Campaign not found")
    await deception_orchestrator.stop_campaign(campaign_id, db)


# ---------------------------------------------------------------------------
# Breadcrumb hits
# ---------------------------------------------------------------------------


@router.get("/breadcrumb-hits", response_model=list[BreadcrumbHitOut])
async def list_breadcrumb_hits(
    limit: int = 50,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Return recent breadcrumb hits — attackers re-using stolen bait."""
    require_feature(auth.client, "honey_ai_deception", "enterprise")
    hits = await breadcrumb_tracker.recent_hits(
        db, client_id=auth.client.id, limit=max(1, min(limit, 200))
    )
    return [
        BreadcrumbHitOut(
            id=h.id,
            campaign_id=h.campaign_id,
            breadcrumb_uuid=h.breadcrumb_uuid,
            planted_in=h.planted_in,
            bait_kind=h.bait_kind,
            hit_count=h.hit_count or 0,
            last_hit_at=h.last_hit_at.isoformat() if h.last_hit_at else None,
            last_hit_source=h.last_hit_source,
            planted_at=h.planted_at.isoformat() if h.planted_at else "",
        )
        for h in hits
    ]


@router.get("/breadcrumbs", response_model=list[BreadcrumbHitOut])
async def list_all_breadcrumbs(
    campaign_id: Optional[str] = None,
    limit: int = 100,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List all breadcrumbs (hit or not) for inspection/debugging."""
    require_feature(auth.client, "honey_ai_deception", "enterprise")
    query = select(HoneyBreadcrumb).where(
        HoneyBreadcrumb.client_id == auth.client.id
    )
    if campaign_id:
        query = query.where(HoneyBreadcrumb.campaign_id == campaign_id)
    query = query.order_by(HoneyBreadcrumb.planted_at.desc()).limit(
        max(1, min(limit, 500))
    )
    result = await db.execute(query)
    rows = result.scalars().all()
    return [
        BreadcrumbHitOut(
            id=h.id,
            campaign_id=h.campaign_id,
            breadcrumb_uuid=h.breadcrumb_uuid,
            planted_in=h.planted_in,
            bait_kind=h.bait_kind,
            hit_count=h.hit_count or 0,
            last_hit_at=h.last_hit_at.isoformat() if h.last_hit_at else None,
            last_hit_source=h.last_hit_source,
            planted_at=h.planted_at.isoformat() if h.planted_at else "",
        )
        for h in rows
    ]
