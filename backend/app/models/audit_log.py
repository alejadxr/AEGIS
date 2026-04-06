from datetime import datetime
from typing import Optional
from sqlalchemy import String, Float, Integer, Text, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base, UUIDMixin


class AuditLog(Base, UUIDMixin):
    __tablename__ = "audit_log"

    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("clients.id"), nullable=False)
    incident_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("incidents.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    model_used: Mapped[Optional[str]] = mapped_column(String(100))
    input_summary: Mapped[Optional[str]] = mapped_column(Text)
    ai_reasoning: Mapped[Optional[str]] = mapped_column(Text)
    decision: Mapped[Optional[str]] = mapped_column(Text)
    confidence: Mapped[Optional[float]] = mapped_column(Float)
    tokens_used: Mapped[Optional[int]] = mapped_column(Integer)
    cost_usd: Mapped[Optional[float]] = mapped_column(Float)
    latency_ms: Mapped[Optional[int]] = mapped_column(Integer)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    # Relationships
    client = relationship("Client", back_populates="audit_logs")
