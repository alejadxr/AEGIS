"""
SharedIOC — Community-shared threat intelligence model.

Stores IOCs submitted by AEGIS instances to the shared threat intel cloud.
Each IOC is anonymized (no client-identifying data, only a hashed source ID)
and enriched with MITRE ATT&CK technique references.

Table: shared_iocs
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, Integer, JSON, String, Index
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDMixin


class SharedIOC(Base, UUIDMixin):
    __tablename__ = "shared_iocs"

    # --- IOC identity ---
    ioc_type: Mapped[str] = mapped_column(
        String(50), nullable=False, comment="ip | domain | hash | url"
    )
    ioc_value: Mapped[str] = mapped_column(
        String(500), nullable=False, index=True,
        comment="The actual indicator value"
    )

    # --- Threat context ---
    threat_type: Mapped[str] = mapped_column(
        String(100), nullable=False,
        comment="brute_force, c2, phishing, malware, etc."
    )
    confidence: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.5,
        comment="0.0 - 1.0 confidence score"
    )
    mitre_techniques: Mapped[Optional[dict]] = mapped_column(
        JSON, default=list,
        comment="List of MITRE ATT&CK technique IDs, e.g. ['T1110.001']"
    )

    # --- Provenance (anonymous) ---
    source_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True,
        comment="SHA-256 of contributor client ID — anonymous but consistent"
    )
    report_count: Mapped[int] = mapped_column(
        Integer, default=1,
        comment="Number of independent reporters for this IOC"
    )
    verified: Mapped[bool] = mapped_column(
        Boolean, default=False,
        comment="True if confirmed by multiple independent sources"
    )

    # --- Timestamps ---
    first_seen: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True,
        comment="After this time, confidence decays and IOC may be pruned"
    )

    # --- Table indexes for query performance ---
    __table_args__ = (
        Index("ix_shared_iocs_type_value", "ioc_type", "ioc_value"),
        Index("ix_shared_iocs_threat_type", "threat_type"),
        Index("ix_shared_iocs_expires", "expires_at"),
    )
