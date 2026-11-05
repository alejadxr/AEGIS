"""
Configurable Firewall API — CRUD, test, templates, live blocking state.

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
GET    /firewall/blocked           → live blocked IPs (Pi iptables + local in-memory)
GET    /firewall/stats             → aggregate firewall counts
DELETE /firewall/blocked/{ip}      → unblock an IP from Pi + local
POST   /firewall/blocked           → block an IP (operator; Pi + 403 list + system fw)
GET    /firewall/safelist          → every safelist entry, env and runtime
GET    /firewall/safelist/{cat}    → one category (safe | internal | shared_egress)
POST   /firewall/safelist/{cat}    → add an entry; live at once, kept across restarts
DELETE /firewall/safelist/{cat}    → remove a runtime entry (?value=...); env entries are pinned
"""
import os
from datetime import datetime, timedelta
from typing import Any, Literal, Optional

import httpx
import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.auth import AuthContext, require_admin, require_viewer
from app.core.firewall_client import firewall_auth_headers
from app.core.ip_blocker import BLOCKED_IPS_FILE, ip_blocker_service
from app.database import get_db
from app.models.action import Action
from app.models.firewall_rule import FirewallRule
from app.services import operator_block as op_block
from app.services import safelist as safelist_svc
from app.services.firewall_engine import DEFAULT_TEMPLATES, firewall_engine
from app.core.safelist_store import SafelistError

_PI_BASE = (settings.AEGIS_FIREWALL_URL or "").rstrip("/")
_PI_TIMEOUT = 5.0

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


# ---------------------------------------------------------------------------
# Live blocking state — new in v1.6.1
# ---------------------------------------------------------------------------

class BlockedIPItem(BaseModel):
    ip: str
    source: str  # "pi", "local", or "pi+local"
    added_at: Optional[datetime] = None


class BlockedIPsResponse(BaseModel):
    items: list[BlockedIPItem]
    count: int
    pi_reachable: bool
    local_path: str


class FirewallStatsResponse(BaseModel):
    blocked_ips_count: int
    active_rules: int
    enabled_rules: int
    total_hits: int
    attackers_24h: int
    pi_reachable: bool
    real_firewall_active: bool
    local_fw: str = "disabled"


async def _fetch_pi_blocked() -> tuple[list[str], bool]:
    """Fetch blocked IPs from Pi firewall agent.
    Returns (list_of_ips, reachable).
    """
    if not _PI_BASE:
        return [], False
    try:
        async with httpx.AsyncClient(timeout=_PI_TIMEOUT, headers=firewall_auth_headers()) as client:
            resp = await client.get(f"{_PI_BASE}/blocked")
            resp.raise_for_status()
            data = resp.json()
            return data.get("blocked", []), True
    except Exception:
        return [], False


@router.get("/blocked", response_model=BlockedIPsResponse)
async def list_blocked_ips(
    auth: AuthContext = Depends(require_viewer),
):
    """Live list of blocked IPs — Pi iptables AEGIS_BLOCK chain + local in-memory."""
    pi_ips, pi_reachable = await _fetch_pi_blocked()
    local_ips = set(ip_blocker_service.list_blocked())
    pi_set = set(pi_ips)

    # Merge with source tagging
    all_ips = pi_set | local_ips
    items: list[BlockedIPItem] = []
    for ip in sorted(all_ips):
        in_pi = ip in pi_set
        in_local = ip in local_ips
        if in_pi and in_local:
            source = "pi+local"
        elif in_pi:
            source = "pi"
        else:
            source = "local"
        items.append(BlockedIPItem(ip=ip, source=source, added_at=None))

    return BlockedIPsResponse(
        items=items,
        count=len(items),
        pi_reachable=pi_reachable,
        local_path=str(BLOCKED_IPS_FILE),
    )


@router.get("/stats", response_model=FirewallStatsResponse)
async def firewall_stats(
    auth: AuthContext = Depends(require_viewer),
    db: AsyncSession = Depends(get_db),
):
    """Aggregate firewall counts — DSL rules (tenant-scoped) + live blocks (global)."""
    # DSL rules stats (tenant-scoped)
    rules_result = await db.execute(
        select(
            func.count(FirewallRule.id).label("total"),
            func.count(FirewallRule.id).filter(FirewallRule.enabled == True).label("enabled"),  # noqa: E712
            func.coalesce(func.sum(FirewallRule.hits), 0).label("hits"),
        ).where(FirewallRule.client_id == auth.client_id)
    )
    row = rules_result.one()
    active_rules = int(row.total)
    enabled_rules = int(row.enabled)
    total_hits = int(row.hits)

    # Attackers blocked in last 24h (actions with action_type='block_ip')
    # Use naive UTC to match the column (created_at stored as naive datetime)
    since = datetime.utcnow() - timedelta(hours=24)
    attackers_result = await db.execute(
        select(func.count(Action.id)).where(
            Action.client_id == auth.client_id,
            Action.action_type == "block_ip",
            Action.created_at >= since,
        )
    )
    attackers_24h = int(attackers_result.scalar() or 0)

    # Live blocked IPs (global, not tenant-scoped)
    pi_ips, pi_reachable = await _fetch_pi_blocked()
    local_ips = set(ip_blocker_service.list_blocked())
    blocked_count = len(set(pi_ips) | local_ips)

    local_fw = "disabled"
    if os.environ.get("AEGIS_REAL_FW") == "1":
        from app.services import firewall_local as _fw_local
        local_fw = _fw_local.get_firewall().status()
    real_firewall_active = bool(
        (os.environ.get("AEGIS_REAL_FW") and local_fw == "active")
        or settings.AEGIS_FIREWALL_URL
    )

    return FirewallStatsResponse(
        blocked_ips_count=blocked_count,
        active_rules=active_rules,
        enabled_rules=enabled_rules,
        total_hits=total_hits,
        attackers_24h=attackers_24h,
        pi_reachable=pi_reachable,
        real_firewall_active=real_firewall_active,
        local_fw=local_fw,
    )


@router.delete("/blocked/{ip}", status_code=200)
async def unblock_ip(
    ip: str,
    auth: AuthContext = Depends(require_admin),
):
    """Unblock an IP from Pi iptables and local in-memory list."""
    import ipaddress as _ipaddress
    try:
        normalized = str(_ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip!r}")

    results: dict[str, Any] = {"ip": normalized, "pi": None, "local": None}

    # Unblock from Pi
    if _PI_BASE:
        try:
            async with httpx.AsyncClient(timeout=_PI_TIMEOUT, headers=firewall_auth_headers()) as client:
                resp = await client.delete(f"{_PI_BASE}/block/{normalized}")
                results["pi"] = {"success": resp.status_code < 300, "status_code": resp.status_code}
        except Exception as exc:
            results["pi"] = {"success": False, "error": str(exc)}

    # Unblock locally
    local_result = ip_blocker_service.unblock_ip(normalized)
    results["local"] = local_result

    return results


# ---------------------------------------------------------------------------
# Operator block
# ---------------------------------------------------------------------------

class BlockRequest(BaseModel):
    ip: str = Field(..., min_length=2, max_length=45)
    # Required free text: it lands in the Pi's attacker record, the Action and the
    # audit trail, which is the only way to tell later why an address was blocked.
    reason: str = Field(..., min_length=3, max_length=500)
    threat_type: Optional[str] = Field(None, max_length=50)
    severity: Optional[Literal["low", "medium", "high", "critical"]] = None
    # Omitted = permanent. Bounded by the Pi agent's own 30-day cap.
    duration_s: Optional[int] = Field(None, ge=op_block.MIN_DURATION_S, le=op_block.MAX_DURATION_S)
    # Attach to an existing incident instead of creating a closed stub.
    incident_id: Optional[str] = Field(None, max_length=36)


def _actor(auth: AuthContext) -> str:
    return str(auth.email or auth.user_id or auth.client.name or "api-key")


@router.post("/blocked", status_code=201)
async def block_ip(
    body: BlockRequest,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Block an IP on all three layers, as the operator.

    Refuses (409) a safelisted, internal, built-in-protected or shared-egress
    address, and (400) anything that is not a single routable IP: the Pi agent
    takes single addresses only, so a CIDR is rejected rather than half-applied.
    """
    try:
        result = await op_block.operator_block(
            db, client_id=auth.client_id, actor=_actor(auth), ip=body.ip, reason=body.reason,
            threat_type=body.threat_type, severity=body.severity, duration_s=body.duration_s,
            incident_id=body.incident_id,
        )
    except op_block.BlockRefused as exc:
        raise HTTPException(status_code=exc.status, detail={"code": exc.code, "message": exc.message})
    if not result["blocked"]:
        raise HTTPException(status_code=502, detail={"code": "block_failed", **result})
    return result


# ---------------------------------------------------------------------------
# Safelist (env layer read-only, runtime layer managed here)
# ---------------------------------------------------------------------------

SafelistCategory = Literal["safe", "internal", "shared_egress"]


class SafelistAdd(BaseModel):
    value: str = Field(..., min_length=2, max_length=64, description="IP address or CIDR (no wider than /16 IPv4, /32 IPv6)")
    note: str = Field("", max_length=300)
    # Opt-in: lifting an existing block is a second decision, not a side effect.
    unblock_if_blocked: bool = False


@router.get("/safelist")
async def list_safelist(auth: AuthContext = Depends(require_viewer)):
    """Every category, env and runtime entries together. Built-in ranges (private,
    Tailscale, crawler/CDN networks) are always on and not listed."""
    return {"categories": safelist_svc.list_all(), "meaning": safelist_svc.CATEGORY_MEANING}


@router.get("/safelist/{category}")
async def list_safelist_category(category: SafelistCategory, auth: AuthContext = Depends(require_viewer)):
    return {"category": category, "meaning": safelist_svc.CATEGORY_MEANING[category],
            "entries": safelist_svc.list_category(category)}


@router.post("/safelist/{category}", status_code=201)
async def add_safelist_entry(
    category: SafelistCategory,
    body: SafelistAdd,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Add an entry. Takes effect on the next request, no restart; persisted.

    Scope: Mac Pro side only. The Pi firewall agent keeps its own env-pinned
    safelist and is not told about additions made here (no push to the Pi).
    """
    try:
        result = await safelist_svc.add(
            category, body.value, added_by=_actor(auth), note=body.note,
            unblock_if_blocked=body.unblock_if_blocked, db=db,
        )
    except SafelistError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError as exc:
        # Not persisted means it would silently vanish on restart: say so loudly.
        raise HTTPException(status_code=500, detail=f"could not persist the safelist: {exc}")
    from app.core.audit import log_audit
    await log_audit(db, "safelist_add", f"{category} += {result['value']} ({body.note[:100]})",
                    client_id=auth.client_id, user_id=auth.user_id)
    await db.commit()
    return result


@router.delete("/safelist/{category}")
async def remove_safelist_entry(
    category: SafelistCategory,
    value: str,
    auth: AuthContext = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Remove a runtime entry (`?value=203.0.113.7`). An entry defined by the
    server environment is pinned: 409 with the variable to edit, never a silent no-op."""
    try:
        result = safelist_svc.remove(category, value)
    except safelist_svc.EnvPinned as exc:
        raise HTTPException(status_code=409, detail={"code": "env_pinned", "var": exc.var, "message": str(exc)})
    except safelist_svc.NotListed:
        raise HTTPException(status_code=404, detail="Not in the runtime safelist for that category")
    except SafelistError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"could not persist the safelist: {exc}")
    from app.core.audit import log_audit
    await log_audit(db, "safelist_remove", f"{category} -= {result['value']}",
                    client_id=auth.client_id, user_id=auth.user_id)
    await db.commit()
    return result
