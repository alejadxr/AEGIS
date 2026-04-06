from datetime import datetime
from typing import Optional
from sqlalchemy import String, Boolean, Text, JSON, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin


class Action(Base, UUIDMixin):
    __tablename__ = "actions"

    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=False)
    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("clients.id"), nullable=False)
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target: Mapped[Optional[str]] = mapped_column(String(500))
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(100))
    ai_reasoning: Mapped[Optional[str]] = mapped_column(Text)
    result: Mapped[Optional[dict]] = mapped_column(JSON)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    incident = relationship("Incident", back_populates="actions")
    client = relationship("Client", back_populates="actions")
