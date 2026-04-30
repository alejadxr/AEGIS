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
    type: Literal["Account", "Host", "IP", "DNS", "FileHash"]
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
    within: int = 3600

    def get(self, key: str, default: Any = None) -> Any:
        try:
            val = getattr(self, key)
            return val if val is not None else default
        except AttributeError:
            return default

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)


class ChainRule(Rule):
    kind: Literal["chain"] = "chain"  # type: ignore[assignment]
    sequence: list[str] = []
    max_window_seconds: int = 7200
    chain: list[ChainStep] = []
    group_by: str = "source_ip"

    @model_validator(mode="after")
    def sync_sequence_from_chain(self) -> ChainRule:
        if not self.sequence and self.chain:
            self.sequence = [
                s.sigma_rule or s.event_type or ""
                for s in self.chain
                if s.sigma_rule or s.event_type
            ]
        return self

    # ChainRule also needs dict-like "condition" access but chain rules
    # don't have a condition in the traditional sense — provide a stub.
    @model_validator(mode="before")
    @classmethod
    def inject_stub_condition(cls, values: dict) -> dict:
        if "condition" not in values:
            values["condition"] = {"event_type": "__chain__"}
        return values
