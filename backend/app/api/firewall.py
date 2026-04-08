"""
Configurable Firewall API — CRUD, test, templates.

Endpoints
---------
GET    /firewall/rules             → list all rules for the tenant
POST   /firewall/rules             → create a rule
GET    /firewall/rules/{id}        → get a single rule
PUT    /firewall/rules/{id}        → update a rule
DELETE /firewall/rules/{id}        → delete a rule
POST   /firewall/rules/{id}/test   → test an existing rule against a synthetic event
POST   /firewall/test              → test ad-hoc YAML against a synthetic event
GET    /firewall/templates         → list shipped templates
"""
from datetime import datetime
from typing import Any, Optional

import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthContext, require_admin, require_viewer
from app.database import get_db
from app.models.firewall_rule import FirewallRule
from app.services.firewall_engine import DEFAULT_TEMPLATES, firewall_engine

router = APIRouter(prefix="/firewall", tags=["firewall"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class FirewallRuleOut(BaseModel):
    id: str
    client_id: str
    name: str
    enabled: bool
    yaml_def: str
    priority: int
    hits: int
    last_hit_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FirewallRuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    enabled: bool = True
    yaml_def: str = Field(..., min_length=1)
    priority: int = 100


class FirewallRuleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    enabled: Optional[bool] = None
    yaml_def: Optional[str] = None
    priority: Optional[int] = None


class FirewallRuleTestRequest(BaseModel):
    event: dict[str, Any] = Field(default_factory=dict)
    yaml_def: Optional[str] = None  # override the stored definition for what-if testing


class FirewallRuleTestResponse(BaseModel):
    ok: bool
    matched: bool
    structural_match: Optional[bool] = None
    rate_limit: Optional[dict] = None
    action: Optional[str] = None
    rule_name: Optional[str] = None
    error: Optional[str] = None


class FirewallTemplate(BaseModel):
    id: str
    name: str
    description: str
    yaml_def: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _validate_yaml(yaml_def: str) -> None:
    """Raise 400 if the YAML is malformed or missing required fields."""
    try:
        parsed = yaml.safe_load(yaml_def)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}")
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="Rule YAML must be a mapping")
    if "action" not in parsed:
        raise HTTPException(status_code=400, detail="Rule must declare an `action`")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/rules", response_model=list[FirewallRuleOut])
async def list_rules(
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """List all firewall rules for the tenant, sorted by priority descending."""
    result = await db.execute(
        select(FirewallRule)
        .where(FirewallRule.client_id == auth.client_id)
        .order_by(FirewallRule.priority.desc(), FirewallRule.created_at.desc())
    )
    return list(result.scalars().all())


@router.post("/rules", response_model=FirewallRuleOut, status_code=201)
async def create_rule(
    body: FirewallRuleCreate,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Create a new firewall rule. Invalidates the engine cache for this tenant."""
    _validate_yaml(body.yaml_def)

    rule = FirewallRule(
        client_id=auth.client_id,
        name=body.name,
        enabled=body.enabled,
        yaml_def=body.yaml_def,
        priority=body.priority,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)

    firewall_engine.invalidate(auth.client_id)
    return rule


@router.get("/rules/{rule_id}", response_model=FirewallRuleOut)
async def get_rule(
    rule_id: str,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    rule = await db.get(FirewallRule, rule_id)
    if not rule or rule.client_id != auth.client_id:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.put("/rules/{rule_id}", response_model=FirewallRuleOut)
async def update_rule(
    rule_id: str,
    body: FirewallRuleUpdate,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    rule = await db.get(FirewallRule, rule_id)
    if not rule or rule.client_id != auth.client_id:
        raise HTTPException(status_code=404, detail="Rule not found")

    if body.yaml_def is not None:
        _validate_yaml(body.yaml_def)
        rule.yaml_def = body.yaml_def
    if body.name is not None:
        rule.name = body.name
    if body.enabled is not None:
        rule.enabled = body.enabled
    if body.priority is not None:
        rule.priority = body.priority

    await db.commit()
    await db.refresh(rule)

    firewall_engine.invalidate(auth.client_id)
    return rule


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    rule = await db.get(FirewallRule, rule_id)
    if not rule or rule.client_id != auth.client_id:
        raise HTTPException(status_code=404, detail="Rule not found")

    await db.delete(rule)
    await db.commit()

    firewall_engine.invalidate(auth.client_id)
    return None


@router.post("/rules/{rule_id}/test", response_model=FirewallRuleTestResponse)
async def test_rule(
    rule_id: str,
    body: FirewallRuleTestRequest,
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Test an existing rule (or override YAML) against a synthetic event."""
    rule = await db.get(FirewallRule, rule_id)
    if not rule or rule.client_id != auth.client_id:
        raise HTTPException(status_code=404, detail="Rule not found")

    yaml_def = body.yaml_def if body.yaml_def is not None else rule.yaml_def
    result = await firewall_engine.test_rule(
        yaml_def=yaml_def, event=body.event, client_id=auth.client_id
    )
    return FirewallRuleTestResponse(**result)


@router.post("/test", response_model=FirewallRuleTestResponse)
async def test_yaml(
    body: FirewallRuleTestRequest,
    auth: AuthContext = Depends(require_viewer),
):
    """Test ad-hoc YAML (not yet saved) against a synthetic event."""
    if not body.yaml_def:
        raise HTTPException(status_code=400, detail="yaml_def is required")
    result = await firewall_engine.test_rule(
        yaml_def=body.yaml_def, event=body.event, client_id=auth.client_id
    )
    return FirewallRuleTestResponse(**result)


@router.get("/templates", response_model=list[FirewallTemplate])
async def list_templates(auth: AuthContext = Depends(require_viewer)):
    """Return the shipped rule templates the UI can clone from."""
    return [FirewallTemplate(**t) for t in DEFAULT_TEMPLATES]
