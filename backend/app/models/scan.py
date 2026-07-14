from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, JSON, DateTime, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin, TimestampMixin


class Scan(Base, UUIDMixin, TimestampMixin):
    """Persistent record of a surface scan.

    Previously scans lived only in ``ScanOrchestrator._active_scans`` (an
    in-memory dict) and were wiped on every ``cayde6-api`` restart, so the
    /api/v1/surface/scans list rendered empty. This model persists scan
    history to PostgreSQL so it survives restarts and can be queried per
    tenant. The orchestrator still keeps a hot in-memory copy for a running
    scan; on completion/failure it upserts the row here.
    """

    __tablename__ = "scans"

    # The orchestrator's human-readable scan id (e.g. scan_20260626_..._1_2_3_4)
    # is used as the primary key so DB rows and in-memory entries share ids.
    id: Mapped[str] = mapped_column(String(120), primary_key=True)

    client_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("clients.id"), nullable=False
    )
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(50), default="full")
    status: Mapped[str] = mapped_column(String(20), default="running")  # running/completed/failed
    error: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    results: Mapped[dict] = mapped_column(JSON, default=dict)
    assets_found: Mapped[int] = mapped_column(Integer, default=0)

    client = relationship("Client")

    __table_args__ = (
        Index("ix_scans_client_created", "client_id", "created_at"),
    )
