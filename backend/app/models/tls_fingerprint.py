"""TLS fingerprint (JA4) capture table.

Populated by the TLS honeypot listener on port 8889 (Mac Pro) and the Pi
TLS decoy (port 8443). Each row is one observed JA4 fingerprint per
(ip, ja4) pair; we increment `count` and bump `last_seen` on repeat hits.
"""
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDMixin


class TlsFingerprint(Base, UUIDMixin):
    __tablename__ = "tls_fingerprints"

    ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    ja4: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    ja4_known_tool: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    ja4_category: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    ja4_confidence: Mapped[Optional[float]] = mapped_column(nullable=True)
    honeypot_source: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    sni: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    count: Mapped[int] = mapped_column(Integer, default=1)
