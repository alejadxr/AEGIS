"""Models for EDR-lite endpoint agents and their events."""

import enum
from datetime import datetime

from sqlalchemy import (
    String, JSON, Integer, DateTime, Enum, ForeignKey, Text, func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDMixin, TimestampMixin


class AgentStatus(str, enum.Enum):
    online = "online"
    offline = "offline"
    stale = "stale"          # no heartbeat for > 2 minutes
    deregistered = "deregistered"


class EventSeverity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class EventCategory(str, enum.Enum):
    process = "process"
    network = "network"
    fim = "fim"
    breadcrumb = "breadcrumb"
    forensic = "forensic"


class EndpointAgent(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "endpoint_agents"

    client_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False,
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    os_info: Mapped[str] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)
    agent_version: Mapped[str] = mapped_column(String(32), default="1.0.0")
    status: Mapped[AgentStatus] = mapped_column(
        Enum(AgentStatus), default=AgentStatus.online,
    )
    last_heartbeat: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), default=datetime.utcnow,
    )
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    node_type: Mapped[str] = mapped_column(String(32), default="workspace")  # "server" | "workspace"
    tags: Mapped[dict] = mapped_column(JSON, default=list)   # list stored as JSON

    # Relationships
    events = relationship(
        "AgentEvent", back_populates="agent", cascade="all, delete-orphan",
        order_by="AgentEvent.timestamp.desc()",
    )
    forensic_snapshots = relationship(
        "ForensicSnapshot", back_populates="agent", cascade="all, delete-orphan",
        order_by="ForensicSnapshot.captured_at.desc()",
    )


class AgentEvent(Base, UUIDMixin):
    __tablename__ = "agent_events"

    agent_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("endpoint_agents.id", ondelete="CASCADE"), nullable=False,
    )
    client_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False,
    )
    category: Mapped[EventCategory] = mapped_column(Enum(EventCategory), nullable=False)
    severity: Mapped[EventSeverity] = mapped_column(
        Enum(EventSeverity), default=EventSeverity.info,
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), default=datetime.utcnow,
    )

    # Relationships
    agent = relationship("EndpointAgent", back_populates="events")


class ForensicSnapshot(Base, UUIDMixin):
    __tablename__ = "forensic_snapshots"

    agent_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("endpoint_agents.id", ondelete="CASCADE"), nullable=False,
    )
    client_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False,
    )
    trigger: Mapped[str] = mapped_column(String(255), default="manual")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), default=datetime.utcnow,
    )

    # Relationships
    agent = relationship("EndpointAgent", back_populates="forensic_snapshots")
