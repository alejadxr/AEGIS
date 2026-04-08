"""Antivirus detection + quarantine model (Task #6)."""

from datetime import datetime

from sqlalchemy import String, JSON, Boolean, DateTime, ForeignKey, func, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin


class AvDetection(Base, UUIDMixin):
    __tablename__ = "av_detections"

    client_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False,
    )
    agent_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("endpoint_agents.id", ondelete="CASCADE"), nullable=False,
    )
    incident_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True,
    )

    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule: Mapped[str | None] = mapped_column(String(256), nullable=True)
    engine: Mapped[str] = mapped_column(String(64), default="yara")
    quarantined: Mapped[bool] = mapped_column(Boolean, default=False)
    released: Mapped[bool] = mapped_column(Boolean, default=False)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)

    detected_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), default=datetime.utcnow,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), default=datetime.utcnow,
    )
