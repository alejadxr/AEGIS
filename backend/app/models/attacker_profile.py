from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, Text, JSON, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin


class AttackerProfile(Base, UUIDMixin):
    __tablename__ = "attacker_profiles"

    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("clients.id"), nullable=False)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45))
    known_ips: Mapped[dict] = mapped_column(JSON, default=list)
    tools_used: Mapped[dict] = mapped_column(JSON, default=list)
    techniques: Mapped[dict] = mapped_column(JSON, default=list)
    sophistication: Mapped[Optional[str]] = mapped_column(String(20))
    geo_data: Mapped[Optional[dict]] = mapped_column(JSON)
    first_seen: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime)
    total_interactions: Mapped[int] = mapped_column(Integer, default=0)
    ai_assessment: Mapped[Optional[str]] = mapped_column(Text)

    # Relationships
    client = relationship("Client", back_populates="attacker_profiles")
    interactions = relationship("HoneypotInteraction", back_populates="attacker_profile")
