"""
Correlation engine API routes.

Endpoints
---------
GET  /api/v1/correlation/rules        — list all active rules
POST /api/v1/correlation/rules        — add a custom rule
DELETE /api/v1/correlation/rules/{id} — remove a rule by id
GET  /api/v1/correlation/stats        — engine stats
POST /api/v1/correlation/test         — submit a test event for evaluation (analyst+)
"""

from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from fastapi.params import Depends
from pydantic import BaseModel, field_validator

from app.core.auth import AuthContext, require_admin, require_analyst, require_viewer
from app.services.correlation_engine import correlation_engine

router = APIRouter(prefix="/correlation", tags=["correlation"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class ConditionSchema(BaseModel):
    event_type: str
    count_threshold: Optional[int] = None
    time_window_seconds: Optional[int] = None
    group_by: Optional[str] = None
    unique_field: Optional[str] = None
    filter: Optional[dict[str, Any]] = None


class RuleCreate(BaseModel):
    id: str
    title: str
    description: Optional[str] = ""
    severity: str
    mitre: Optional[list[str]] = []
    enabled: Optional[bool] = True
    condition: ConditionSchema

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        if v not in allowed:
            raise ValueError(f"severity must be one of: {', '.join(sorted(allowed))}")
        return v

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Rule id must not be empty")
        if " " in v:
            raise ValueError("Rule id must not contain spaces")
        return v.strip()


class RuleOut(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    mitre: list[str]
    enabled: bool
    source: str
    condition: dict[str, Any]


class StatsOut(BaseModel):
    events_processed: int
    rules_triggered: int
    custom_rules: int
    rules_total: int
    rules_enabled: int
    window_size: int
    started_at: str


class TestEventIn(BaseModel):
    event: dict[str, Any]


class TestEventOut(BaseModel):
    triggered_rules: list[str]
    triggered_count: int


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/rules", response_model=list[RuleOut])
async def list_rules(
    enabled: Optional[bool] = None,
    severity: Optional[str] = None,
    auth: AuthContext = Depends(require_viewer),
):
    """
    List all active correlation rules.

    Optional query params:
    - enabled: filter by enabled state (true/false)
    - severity: filter by severity level
    """
    rules = correlation_engine.list_rules()

    if enabled is not None:
        rules = [r for r in rules if r.get("enabled", True) == enabled]
    if severity:
        rules = [r for r in rules if r.get("severity") == severity]

    return [
        RuleOut(
            id=r["id"],
            title=r["title"],
            description=r.get("description", ""),
            severity=r["severity"],
            mitre=r.get("mitre", []),
            enabled=r.get("enabled", True),
            source=r.get("source", "builtin"),
            condition=r["condition"],
        )
        for r in rules
    ]


@router.post("/rules", response_model=RuleOut, status_code=201)
async def add_rule(
    body: RuleCreate,
    auth: AuthContext = Depends(require_analyst),
):
    """
    Add a custom correlation rule. Analyst or admin only.

    The rule id must be unique and must not contain spaces.
    """
    rule_dict = {
        "id": body.id,
        "title": body.title,
        "description": body.description or "",
        "severity": body.severity,
        "mitre": body.mitre or [],
        "enabled": body.enabled if body.enabled is not None else True,
        "condition": body.condition.model_dump(exclude_none=True),
    }

    try:
        created = correlation_engine.add_rule(rule_dict)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return RuleOut(
        id=created["id"],
        title=created["title"],
        description=created.get("description", ""),
        severity=created["severity"],
        mitre=created.get("mitre", []),
        enabled=created.get("enabled", True),
        source=created.get("source", "custom"),
        condition=created["condition"],
    )


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    auth: AuthContext = Depends(require_admin),
):
    """
    Remove a correlation rule by id. Admin only.

    Built-in rules can also be removed (they live in memory only and are
    restored on next service restart).
    """
    removed = correlation_engine.remove_rule(rule_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")


@router.get("/stats", response_model=StatsOut)
async def get_stats(
    auth: AuthContext = Depends(require_viewer),
):
    """
    Return correlation engine runtime statistics.

    Fields
    ------
    - events_processed : total events evaluated since startup
    - rules_triggered  : total rule firings since startup
    - custom_rules     : number of rules added via the API
    - rules_total      : total rules (built-in + custom)
    - rules_enabled    : number of enabled rules
    - window_size      : current size of the sliding event window
    - started_at       : ISO 8601 timestamp when the engine started
    """
    s = correlation_engine.stats()
    return StatsOut(
        events_processed=s["events_processed"],
        rules_triggered=s["rules_triggered"],
        custom_rules=s["custom_rules"],
        rules_total=s["rules_total"],
        rules_enabled=s["rules_enabled"],
        window_size=s["window_size"],
        started_at=s["started_at"],
    )


@router.post("/test", response_model=TestEventOut)
async def test_event(
    body: TestEventIn,
    auth: AuthContext = Depends(require_analyst),
):
    """
    Submit a synthetic event to the correlation engine and return which rules
    would have fired, without persisting anything or creating incidents.

    Useful for rule development and smoke-testing. Analyst or admin only.
    """
    triggered = await correlation_engine.evaluate(body.event)
    return TestEventOut(
        triggered_rules=[r["id"] for r in triggered],
        triggered_count=len(triggered),
    )
