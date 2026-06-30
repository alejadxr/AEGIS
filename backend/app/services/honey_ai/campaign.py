"""Dataclasses describing a deception campaign configuration.

Kept intentionally lightweight (plain dataclasses, no SQLAlchemy) so the
orchestrator can manipulate them in memory without touching the DB on every
tick.  Persistence happens via the ``Honeypot`` and ``HoneyBreadcrumb`` models.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class CampaignStatus(str, Enum):
    PENDING = "pending"
    DEPLOYING = "deploying"
    RUNNING = "running"
    ROTATING = "rotating"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass
class ServiceMix:
    """How many of each decoy type a campaign should spin up.

    Percentages must sum to 100.  ``decoy_count`` from :class:`Campaign` is
    distributed across these slots.
    """
    web: int = 40
    db: int = 30
    files: int = 20
    admin: int = 10

    def validate(self) -> None:
        total = self.web + self.db + self.files + self.admin
        if total != 100:
            raise ValueError(
                f"ServiceMix percentages must sum to 100, got {total}"
            )

    def distribute(self, total_count: int) -> dict[str, int]:
        """Return a mapping ``{kind: count}`` that sums to ``total_count``."""
        self.validate()
        raw = {
            "web": total_count * self.web / 100,
            "db": total_count * self.db / 100,
            "files": total_count * self.files / 100,
            "admin": total_count * self.admin / 100,
        }
        # Round down then fix drift
        distrib = {k: int(v) for k, v in raw.items()}
        drift = total_count - sum(distrib.values())
        # Assign drift to the largest slots first
        order = sorted(raw.keys(), key=lambda k: raw[k] - int(raw[k]), reverse=True)
        i = 0
        while drift > 0 and order:
            distrib[order[i % len(order)]] += 1
            drift -= 1
            i += 1
        return distrib


@dataclass
class ThemeConfig:
    """Content theme used by :class:`ContentGenerator` to shape fake data."""
    name: str
    label: str
    description: str
    industry: str
    fake_domains: list[str] = field(default_factory=list)
    fake_products: list[str] = field(default_factory=list)
    prompt_seed: str = ""
    # Bait kinds especially valuable for this theme — drives breadcrumb minting
    bait_kinds: list[str] = field(default_factory=lambda: ["email", "api_key"])


@dataclass
class Campaign:
    """One deployed deception campaign."""
    name: str
    client_id: str
    theme: str = "fintech"
    decoy_count: int = 50
    service_mix: ServiceMix = field(default_factory=ServiceMix)
    rotation_hours: int = 6
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: CampaignStatus = CampaignStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    deployed_at: Optional[datetime] = None
    last_rotated_at: Optional[datetime] = None
    stopped_at: Optional[datetime] = None
    honeypot_ids: list[str] = field(default_factory=list)
    breadcrumb_ids: list[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "client_id": self.client_id,
            "theme": self.theme,
            "decoy_count": self.decoy_count,
            "service_mix": {
                "web": self.service_mix.web,
                "db": self.service_mix.db,
                "files": self.service_mix.files,
                "admin": self.service_mix.admin,
            },
            "rotation_hours": self.rotation_hours,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "deployed_at": self.deployed_at.isoformat() if self.deployed_at else None,
            "last_rotated_at": (
                self.last_rotated_at.isoformat() if self.last_rotated_at else None
            ),
            "stopped_at": self.stopped_at.isoformat() if self.stopped_at else None,
            "honeypot_count": len(self.honeypot_ids),
            "breadcrumb_count": len(self.breadcrumb_ids),
            "error": self.error,
        }
