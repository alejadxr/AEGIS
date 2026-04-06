from datetime import datetime
from typing import Optional
from sqlalchemy import String, Text, JSON, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin


class Incident(Base, UUIDMixin):
    __tablename__ = "incidents"

    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("clients.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="open")
    source: Mapped[Optional[str]] = mapped_column(String(100))
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(20))
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(50))
    source_ip: Mapped[Optional[str]] = mapped_column(String(45))
    target_asset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("assets.id"), nullable=True)
    ai_analysis: Mapped[Optional[dict]] = mapped_column(JSON)
    raw_alert: Mapped[Optional[dict]] = mapped_column(JSON)
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    contained_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # Relationships
    client = relationship("Client", back_populates="incidents")
    target_asset = relationship("Asset", back_populates="incidents")
    actions = relationship("Action", back_populates="incident", cascade="all, delete-orphan")
