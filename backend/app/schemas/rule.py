"""Pydantic v2 models for AEGIS YAML rule pack (Sigma + chain rules)."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, field_validator, model_validator

Severity = Literal["informational", "low", "medium", "high", "critical"]

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_RULE_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]+$")


class RuleCondition(BaseModel):
    event_type: str
    count_threshold: int | None = None
    time_window_seconds: int | None = None
    group_by: str | None = None
    unique_field: str | None = None
    filter: dict[str, Any] = {}

    model_config = {"extra": "allow"}

    def get(self, key: str, default: Any = None) -> Any:
        try:
            val = getattr(self, key)
            return val if val is not None else default
        except AttributeError:
            return default

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key) and getattr(self, key) is not None


class EntityMapping(BaseModel):
    # "File" was missing, and its absence silently killed two rules: the
    # ransomware extension detectors (prinz_eugen, shinysp1d3r) declared
    # `type: File` for a `file_path` field, failed validation, and were skipped
    # by the loader from the day they were written (2026-06-23) — leaving the
    # entire sigma/ransomware/ directory loading zero rules.
    #
    # "FileHash" was NOT the right fix: those rules map a path, not a digest.
    # Nothing reads entityMappings today (it is declarative metadata with no
    # consumer), so the only thing its validation achieved here was to reject
    # otherwise-correct detections.
    type: Literal["Account", "Host", "IP", "DNS", "File", "FileHash"]
    field: str


class Rule(BaseModel):
    id: str
    name: str
    severity: Severity
    tactics: list[str] = []
    techniques: list[str] = []
    data_sources: list[str] = []
    condition: RuleCondition
    entityMappings: list[EntityMapping] = []
    customDetails: dict[str, Any] = {}
    description: str | None = None
    references: list[str] = []
    enabled: bool = True
    kind: Literal["sigma"] = "sigma"
    # A chain-only rule still evaluates and still records into the chain
    # fire-log, but never opens an incident of its own. It exists so a chain can
    # be built from a stage that is individually benign — a successful login, a
    # POST to an upload endpoint — without turning that benign stage into alert
    # noise. Every rule used to create an incident when it fired, which is why
    # no chain could use a low-signal stage.
    chain_only: bool = False

    # Legacy compat fields (from raw dicts still in the engine)
    title: str | None = None
    mitre: list[str] = []
    source: str | None = None
    category: str | None = None

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:
        if not _RULE_ID_RE.match(v):
            raise ValueError(f"Rule id '{v}' must match [a-zA-Z0-9_-]+")
        return v

    @field_validator("techniques")
    @classmethod
    def validate_techniques(cls, v: list[str]) -> list[str]:
        for t in v:
            if not _TECHNIQUE_RE.match(t):
                raise ValueError(f"Invalid technique ID '{t}' — expected T####[.###]")
        return v

    @model_validator(mode="after")
    def sync_legacy_fields(self) -> Rule:
        # Keep 'title' and 'name' in sync so dict-access code works
        if self.title is None and self.name:
            self.title = self.name
        elif self.name == "" and self.title:
            self.name = self.title
        # Sync mitre from techniques if not set
        if not self.mitre and self.techniques:
            self.mitre = self.techniques
        elif not self.techniques and self.mitre:
            self.techniques = self.mitre
        return self

    # ------------------------------------------------------------------
    # Dict-like access so existing engine code (rule["id"] etc.) works
    # without modification.
    # ------------------------------------------------------------------

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            val = getattr(self, key)
            return val if val is not None else default
        except AttributeError:
            return default

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key) and getattr(self, key) is not None

    @property
    def condition_dict(self) -> dict:
        return self.condition.model_dump(exclude_none=True)


class ChainStep(BaseModel):
    sigma_rule: str | None = None
    event_type: str | None = None
    # `any_of` is satisfied when ANY of the named sigma rules fired. A stage of
    # a real attack is almost never one signature: "exploitation attempt"
    # against this estate means one of ~90 CVE rules, and "recovery inhibition"
    # means vssadmin OR wbadmin OR bcdedit OR tmutil. Without a disjunction a
    # useful chain would have to be written once per signature, so every chain
    # shipped before v1.6.4.10 named a single rule and described a stage far
    # narrower than the one its title claimed.
    any_of: list[str] = []
    within: int = 3600
    # Human label for the stage, used in the incident's evidence trail. Falls
    # back to the rule/type name when omitted.
    label: str | None = None

    def get(self, key: str, default: Any = None) -> Any:
        try:
            val = getattr(self, key)
            return val if val is not None else default
        except AttributeError:
            return default

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    @property
    def rule_ids(self) -> list[str]:
        """Every sigma rule id that can satisfy this step."""
        if self.sigma_rule:
            return [self.sigma_rule]
        return list(self.any_of)

    @property
    def describe(self) -> str:
        if self.label:
            return self.label
        if self.sigma_rule:
            return self.sigma_rule
        if self.any_of:
            return " | ".join(self.any_of)
        return self.event_type or "?"


class ChainRule(Rule):
    kind: Literal["chain"] = "chain"  # type: ignore[assignment]
    sequence: list[str] = []
    max_window_seconds: int = 7200
    chain: list[ChainStep] = []
    group_by: str = "source_ip"
    # Per-chain cooldown. `None` keeps the engine default (5x COOLDOWN_SECONDS).
    cooldown_seconds: int | None = None

    @model_validator(mode="after")
    def sync_sequence_from_chain(self) -> ChainRule:
        if not self.sequence and self.chain:
            self.sequence = [s.describe for s in self.chain if s.rule_ids or s.event_type]
        return self

    @model_validator(mode="after")
    def validate_steps(self) -> ChainRule:
        """Every step must name something the engine can evaluate.

        A step with neither `sigma_rule`, `any_of` nor `event_type` silently
        satisfied itself in the old evaluator (the `if/elif` fell through with
        `all_steps_met` still True), turning a 3-stage chain into a 2-stage one.
        """
        for idx, step in enumerate(self.chain):
            if not step.rule_ids and not step.event_type:
                raise ValueError(
                    f"chain '{self.id}' step {idx} names no sigma_rule, any_of or event_type"
                )
            if step.sigma_rule and step.any_of:
                raise ValueError(
                    f"chain '{self.id}' step {idx} sets both sigma_rule and any_of"
                )
        return self

    # ChainRule also needs dict-like "condition" access but chain rules
    # don't have a condition in the traditional sense — provide a stub.
    @model_validator(mode="before")
    @classmethod
    def inject_stub_condition(cls, values: dict) -> dict:
        if "condition" not in values:
            values["condition"] = {"event_type": "__chain__"}
        return values
