"""
HoneypotCanary — leak captures collected by defensive JS embedded in
HTTP honeypot decoy pages.

Defensive only. Records voluntarily-disclosed browser features (WebRTC
candidates, canvas/WebGL/audio fingerprint, screen/UA/timezone, headless
markers). NEVER attached to the real AEGIS dashboard — only to honeypot
templates (`http_honeypot.py`, `pi-deploy/aegis_honeypot.py`).
"""
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, UUIDMixin


class HoneypotCanary(Base, UUIDMixin):
    __tablename__ = "honeypot_canaries"

    # Multi-tenant: the AEGIS client whose honeypot served the canary.
    # Nullable because the Pi honeypot may POST before we have client resolution.
    client_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("clients.id"), nullable=True
    )

    # Network-level source IP (what AEGIS / Pi observed on the connection).
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)

    # WebRTC-leaked candidate. If a public IP different from source_ip is
    # observed, it strongly implies VPN/proxy circumvention by the browser.
    real_ip_webrtc: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    # All RTCIceCandidate IPs (local + reflexive). JSON list.
    webrtc_candidates: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Stable fingerprint hash (canvas+webgl+audio+screen+tz). Useful for
    # correlating multiple visits from the same browser.
    fingerprint_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Was a known headless / automation marker detected?
    headless_detected: Mapped[Optional[bool]] = mapped_column(Boolean, default=False, nullable=True)

    # Raw browser metadata (UA, plugins, timezone, screen, language, ...).
    browser_meta: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Which honeypot served the bait (mac_http_8888 / pi_http_8081 / db UUID).
    honeypot_source: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Optional cross-link to a HoneypotInteraction row.
    interaction_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("honeypot_interactions.id"), nullable=True
    )

    captured_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )

    __table_args__ = (
        Index("ix_honeypot_canaries_source_ip", "source_ip"),
        Index("ix_honeypot_canaries_fingerprint", "fingerprint_hash"),
        Index("ix_honeypot_canaries_captured_at", "captured_at"),
    )
