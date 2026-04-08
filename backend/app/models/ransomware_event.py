"""Ransomware incident model — persisted forensic chains from the Rust agent."""

from datetime import datetime

from sqlalchemy import String, JSON, Integer, DateTime, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin


class RansomwareEvent(Base, UUIDMixin):
    """
    A ransomware incident reported by an endpoint agent.

    Created by the Rust agent's ransomware module when 2+ signals correlate.
    The Response engine upgrades this into a CRITICAL Incident automatically.
    """

    __tablename__ = "ransomware_events"

    client_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False,
    )
    agent_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("endpoint_agents.id", ondelete="CASCADE"), nullable=False,
    )
    incident_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True,
    )

    # Forensic chain fields
    process_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    process_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    signals: Mapped[list] = mapped_column(JSON, default=list)
    affected_files: Mapped[list] = mapped_column(JSON, default=list)
    killed_pids: Mapped[list] = mapped_column(JSON, default=list)
    rollback_status: Mapped[str] = mapped_column(String(64), default="pending")
    rollback_files_restored: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(16), default="critical")
    detected_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), default=datetime.utcnow,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), default=datetime.utcnow,
    )

    # Relationships
    incident = relationship("Incident", foreign_keys=[incident_id])
