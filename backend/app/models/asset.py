from datetime import datetime
from typing import Optional
from sqlalchemy import String, Float, JSON, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin, TimestampMixin


class Asset(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "assets"

    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("clients.id"), nullable=False)
    hostname: Mapped[Optional[str]] = mapped_column(String(500))
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    asset_type: Mapped[Optional[str]] = mapped_column(String(50))  # web, server, api, dns, cloud
    ports: Mapped[dict] = mapped_column(JSON, default=list)
    technologies: Mapped[dict] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), default="active")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)

    # Relationships
    client = relationship("Client", back_populates="assets")
    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="target_asset")
