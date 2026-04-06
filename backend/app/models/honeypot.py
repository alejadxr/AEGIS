from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, JSON, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin


class Honeypot(Base, UUIDMixin):
    __tablename__ = "honeypots"

    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("clients.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    honeypot_type: Mapped[str] = mapped_column(String(50), nullable=False)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="stopped")
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    port: Mapped[Optional[int]] = mapped_column(Integer)
    last_rotation: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    interactions_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    client = relationship("Client", back_populates="honeypots")
    interactions = relationship("HoneypotInteraction", back_populates="honeypot", cascade="all, delete-orphan")


class HoneypotInteraction(Base, UUIDMixin):
    __tablename__ = "honeypot_interactions"

    honeypot_id: Mapped[str] = mapped_column(String(36), ForeignKey("honeypots.id"), nullable=False)
    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("clients.id"), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    source_port: Mapped[Optional[int]] = mapped_column(Integer)
    protocol: Mapped[Optional[str]] = mapped_column(String(20))
    commands: Mapped[dict] = mapped_column(JSON, default=list)
    credentials_tried: Mapped[dict] = mapped_column(JSON, default=list)
    payloads: Mapped[dict] = mapped_column(JSON, default=list)
    session_duration: Mapped[Optional[int]] = mapped_column(Integer)
    attacker_profile_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("attacker_profiles.id"), nullable=True
    )
    raw_log: Mapped[Optional[str]] = mapped_column(String(10000))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    honeypot = relationship("Honeypot", back_populates="interactions")
    client = relationship("Client", back_populates="honeypot_interactions")
    attacker_profile = relationship("AttackerProfile", back_populates="interactions")
