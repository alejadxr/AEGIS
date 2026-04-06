from sqlalchemy import String, Integer, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin, TimestampMixin


class Client(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "clients"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    api_key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    guardrails: Mapped[dict] = mapped_column(JSON, default=dict)

    # Subscription / freemium tiers
    tier: Mapped[str] = mapped_column(String(20), default="free", nullable=False)
    max_nodes: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    max_assets: Mapped[int] = mapped_column(Integer, default=25, nullable=False)
    max_users: Mapped[int] = mapped_column(Integer, default=3, nullable=False)

    # Relationships
    assets = relationship("Asset", back_populates="client", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="client", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="client", cascade="all, delete-orphan")
    actions = relationship("Action", back_populates="client", cascade="all, delete-orphan")
    honeypots = relationship("Honeypot", back_populates="client", cascade="all, delete-orphan")
    honeypot_interactions = relationship("HoneypotInteraction", back_populates="client", cascade="all, delete-orphan")
    attacker_profiles = relationship("AttackerProfile", back_populates="client", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="client", cascade="all, delete-orphan")
