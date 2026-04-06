from datetime import datetime
from typing import Optional
from sqlalchemy import String, Float, JSON, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from app.models.base import Base, UUIDMixin


class ThreatIntel(Base, UUIDMixin):
    __tablename__ = "threat_intel"

    ioc_type: Mapped[str] = mapped_column(String(50), nullable=False)
    ioc_value: Mapped[str] = mapped_column(String(500), nullable=False)
    threat_type: Mapped[Optional[str]] = mapped_column(String(100))
    confidence: Mapped[Optional[float]] = mapped_column(Float)
    source: Mapped[Optional[str]] = mapped_column(String(100))
    tags: Mapped[dict] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
