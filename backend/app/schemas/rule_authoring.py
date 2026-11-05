"""Request/response models for the rule-authoring API (/api/v1/rules).

These are the contract the dashboard renders against; keep field names stable.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Origin = Literal["operator", "ai"]
IpCategory = Literal["owner_or_customer", "customer", "shared_egress", "safelisted"]
Verdict = Literal["clean", "blocked", "insufficient_evidence"]


# --- rule body ---------------------------------------------------------------

class ConditionIn(BaseModel):
    event_type: str
    count_threshold: Optional[int] = Field(None, ge=1)
    time_window_seconds: Optional[int] = Field(None, ge=1)
    group_by: Optional[str] = None
    unique_field: Optional[str] = None
    filter: dict[str, Any] = Field(default_factory=dict)


class RuleDraft(BaseModel):
    """A rule as the author writes it. ``id`` is optional on propose/create:
    when absent one is derived from ``name`` in the ``authored_`` namespace."""
    id: Optional[str] = None
    name: str = Field(..., min_length=3, max_length=200)
    severity: Literal["informational", "low", "medium", "high", "critical"] = "low"
    description: Optional[str] = None
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=lambda: ["web_log"])
    condition: ConditionIn


# --- validation --------------------------------------------------------------

class IssueOut(BaseModel):
    code: str
    message: str
    field: str = ""
    severity: Literal["error", "warning"] = "error"


class ValidationOut(BaseModel):
    ok: bool
    errors: list[IssueOut] = Field(default_factory=list)
    warnings: list[IssueOut] = Field(default_factory=list)
    exploit_signature: bool = False
    signature_reason: str = ""


# --- dry run -----------------------------------------------------------------

class CorpusOut(BaseModel):
    source: Literal["pm2_logs", "live_window", "incidents"]
    events: int
    oldest: Optional[datetime] = None
    newest: Optional[datetime] = None
    covers_seconds: Optional[float] = None
    note: str = ""


class FlaggedIpOut(BaseModel):
    ip: str
    category: IpCategory
    matches: int
    sample_paths: list[str] = Field(default_factory=list)


class SampleMatchOut(BaseModel):
    source: str
    source_ip: Optional[str] = None
    category: Optional[IpCategory] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    user_agent: Optional[str] = None
    timestamp: Optional[datetime] = None


class TopIpOut(BaseModel):
    ip: str
    matches: int
    category: Optional[IpCategory] = None


class BaselineOut(BaseModel):
    """Requests the normalizer saw nothing wrong with (2xx/3xx, no pattern) plus
    every request from an owner/safelisted/shared-egress address."""
    events: int
    matched: int
    ratio: float
    too_generic: bool


class DryRunOut(BaseModel):
    verdict: Verdict
    # False = enabling needs ``override`` (flagged IPs / no evidence) or is
    # impossible (too_generic is never overridable).
    can_enable: bool
    overridable: bool
    reasons: list[str] = Field(default_factory=list)
    events_scanned: int
    corpora: list[CorpusOut] = Field(default_factory=list)
    matches: int                      # events the filter matched
    distinct_ips: int
    firing_ips: int                   # IPs that would actually raise an incident
    threshold_note: str = ""
    flagged_ips: list[FlaggedIpOut] = Field(default_factory=list)
    flagged_matches: int = 0
    baseline: BaselineOut
    top_ips: list[TopIpOut] = Field(default_factory=list)
    sample_matches: list[SampleMatchOut] = Field(default_factory=list)
    generated_at: datetime


# --- operations --------------------------------------------------------------

class ProposeIn(BaseModel):
    rule: RuleDraft
    origin: Origin = "operator"


class ProposalOut(BaseModel):
    rule_id: str
    yaml: str
    validation: ValidationOut
    dry_run: Optional[DryRunOut] = None
    can_create: bool
    can_enable: bool
    blockers: list[str] = Field(default_factory=list)


class OverrideIn(BaseModel):
    override: bool = False
    override_reason: Optional[str] = Field(None, max_length=1000)


class CreateIn(OverrideIn):
    rule: RuleDraft
    origin: Origin = "operator"
    enable: bool = False
    # Operator-only: ask for blocking behaviour at creation. Ignored (forced to
    # alert-only) when origin == "ai".
    blocking: bool = False
    request_text: Optional[str] = Field(None, max_length=4000)


class UpdateIn(OverrideIn):
    rule: RuleDraft
    origin: Origin = "operator"
    request_text: Optional[str] = Field(None, max_length=4000)


class EnableIn(OverrideIn):
    note: Optional[str] = Field(None, max_length=1000)


class PromoteIn(BaseModel):
    """Operator approval for a rule to auto-block. Bound to the current body."""
    block_class: Literal["ambiguous", "confirmed"] = "ambiguous"
    note: Optional[str] = Field(None, max_length=1000)
    override: bool = False
    override_reason: Optional[str] = Field(None, max_length=1000)


class RevertIn(OverrideIn):
    to_version: Optional[int] = Field(None, ge=1)


class RuleVersionOut(BaseModel):
    version: int
    saved_at: datetime
    saved_by: str
    change: str                       # create | update | enable | disable | promote | revert | delete
    deleted: bool = False


class RuleSummaryOut(BaseModel):
    id: str
    name: str
    severity: str
    event_type: Optional[str] = None
    enabled: bool
    origin: Literal["shipped", "operator", "ai"]
    # What block_policy says a match by this rule earns.
    classification: Literal["confirmed", "ambiguous"]
    # authored rules only; shipped rules report "n/a"
    mode: Literal["alert_only", "blocking", "n/a"] = "n/a"
    awaiting_approval: bool = False
    unverified: bool = False
    version: Optional[int] = None
    updated_at: Optional[datetime] = None


class RuleDetailOut(RuleSummaryOut):
    yaml: str
    description: Optional[str] = None
    history: list[RuleVersionOut] = Field(default_factory=list)
    approved: bool = False
    block_class_recorded: Optional[str] = None


class WriteOut(BaseModel):
    rule: RuleDetailOut
    validation: ValidationOut
    dry_run: Optional[DryRunOut] = None
    override_applied: bool = False
    audit_id: Optional[str] = None
    message: str = ""


# --- vulnerability flow ------------------------------------------------------

class ProtectIn(BaseModel):
    cve_id: Optional[str] = Field(None, pattern=r"^CVE-\d{4}-\d{4,7}$")
    description: Optional[str] = Field(None, max_length=6000)
    software: list[str] = Field(default_factory=list)
    # Paths the caller already knows are exploited (e.g. from the advisory).
    known_paths: list[str] = Field(default_factory=list)
    # Overrides the stack inventory (tests, or "what if I ran X").
    stack: Optional[list[str]] = None
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    origin: Origin = "operator"
    create: bool = False


class IndicatorOut(BaseModel):
    kind: Literal["path", "method", "header", "parameter"]
    value: str
    detectable_in_http_logs: bool
    why: str


class ProtectOut(BaseModel):
    applicability: Literal["applicable", "not_applicable", "unknown"]
    applicability_reason: str
    targeted_software: list[str] = Field(default_factory=list)
    stack_matched: list[str] = Field(default_factory=list)
    stack_known: bool
    # verified_local_rule: derived from a rule already shipped for that CVE.
    # unverified_description: derived from text/paths the caller supplied.
    verification: Literal["verified_local_rule", "unverified_description", "none"]
    unverified_notice: Optional[str] = None
    already_covered_by: list[str] = Field(default_factory=list)
    indicators: list[IndicatorOut] = Field(default_factory=list)
    proposal: Optional[ProposalOut] = None
    created: Optional[WriteOut] = None
    audit_id: Optional[str] = None
    summary: str
