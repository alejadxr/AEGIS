"""HoneyBreadcrumb model — tracks deception markers planted in fake services.

Each breadcrumb has a unique UUID embedded in fake data (emails, API keys, row
ids, etc.) produced by a Honey-AI deception campaign.  If that UUID ever shows
up in logs of REAL services, it means an attacker consumed the bait and is
re-using stolen artifacts → CRITICAL incident.
"""
from datetime import datetime
from typing import Optional

from sqlalchemy import String, Integer, DateTime, ForeignKey, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin


class HoneyBreadcrumb(Base, UUIDMixin):
    __tablename__ = "honey_breadcrumbs"

    client_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("clients.id"), nullable=False, index=True
    )
    campaign_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    breadcrumb_uuid: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    # Human-readable surface where the breadcrumb was planted
    # (e.g. "fake_api:/api/users[23].email", "fake_db:users.id=1042")
    planted_in: Mapped[str] = mapped_column(String(500), nullable=False)
    # Kind of bait: email, api_key, password, card_number, row_id, file_name, ...
    bait_kind: Mapped[str] = mapped_column(String(50), default="generic")
    # Free-form metadata (the actual fake value, the service name, theme, etc.)
    context: Mapped[dict] = mapped_column(JSON, default=dict)

    planted_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    last_hit_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_hit_source: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    __table_args__ = (
        Index("ix_breadcrumb_client_campaign", "client_id", "campaign_id"),
    )
