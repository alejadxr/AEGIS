"""
Honeypot Canary capture endpoint — AEGIS Phantom.

DEFENSIVE-ONLY. This endpoint receives information voluntarily disclosed
by browsers visiting AEGIS HTTP honeypot decoy pages. The JS payload that
collects this data is embedded ONLY in honeypot templates
(`http_honeypot.py`, `pi-deploy/aegis_honeypot.py`). It is never served by
the real AEGIS dashboard.

Rationale: honeypot visitors are by definition probing infrastructure they
are not authorised to access. Capturing leaked WebRTC candidates, browser
fingerprints, and automation markers is a recognised defensive technique
(see Thinkst Canary tokens, Honeynet Project). The endpoint:

  - POST /api/v1/phantom/canary
      Open-auth (no API key) because attackers' browsers must reach it.
      Records source IP, WebRTC candidates, fingerprint, browser meta.
      If a public WebRTC candidate differs from the source IP, a HIGH-
      severity incident is filed and the AttackerProfile is updated.

  - GET /api/v1/phantom/canaries (and /canary/{ip})
      API-key-protected. Lists captures for the analyst view.

Ethical scope: limited to honeypot context only. The dashboard renders the
captured data in `/dashboard/ip-intel` (read-side, auth required) and
`/dashboard/phantom` (Real IP? column).

Honest limits documented for operators:
  - Tor Browser users: WebRTC is disabled (`media.peerconnection.enabled
    = false`); canvas/audio fingerprint randomised. Tor users will produce
    ONLY the proxy IP — the canary cannot defeat Tor by design.
  - Raw scrapers (curl, python-requests, scrapy): never execute the JS,
    so no canary. The interaction is still logged via the standard
    honeypot path, but no real IP is leaked.
  - Headless Chrome / Puppeteer / Playwright: execute the JS, leak the
    fingerprint, and trigger the `headless_detected` flag.
  - VPN-only browser users (no Tor): WebRTC over a remote HTTP origin is
    restricted to public/srflx candidates in modern Chrome; the user's
    *VPN-public* IP leaks, not the inner real IP. Still useful for
    correlation when combined with fingerprint.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthContext, require_viewer
from app.database import get_db
from app.models.attacker_profile import AttackerProfile
from app.models.honeypot_canary import HoneypotCanary

logger = logging.getLogger("aegis.phantom.canary")

router = APIRouter(tags=["phantom-canary"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_private
        or addr.is_unspecified
        or addr.is_reserved
    ):
        return False
    # Tailscale CGNAT (100.64.0.0/10)
    if isinstance(addr, ipaddress.IPv4Address):
        if int(addr) >> 22 == int(ipaddress.IPv4Address("100.64.0.0")) >> 22:
            return False
    return True


def _client_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return (request.client.host if request.client else "0.0.0.0") or "0.0.0.0"


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class CanaryIn(BaseModel):
    """JS payload from honeypot decoy pages."""
    webrtc_candidates: list[str] = Field(default_factory=list)
    fingerprint_hash: Optional[str] = None
    headless_detected: bool = False
    browser_meta: dict[str, Any] = Field(default_factory=dict)
    honeypot_source: Optional[str] = None  # e.g. "mac_http_8888" / "pi_http_8081"
    # Optional explicit source_ip override (Pi POSTs the original attacker IP
    # when forwarding to the central AEGIS API). Only honored when the request
    # itself originates from a trusted/internal CIDR.
    source_ip_override: Optional[str] = None


class CanaryOut(BaseModel):
    id: str
    source_ip: str
    real_ip_webrtc: Optional[str] = None
    fingerprint_hash: Optional[str] = None
    headless_detected: bool = False
    honeypot_source: Optional[str] = None
    captured_at: str


# ---------------------------------------------------------------------------
# POST — open auth (the attacker's browser is the caller)
# ---------------------------------------------------------------------------

@router.post("/canary", response_model=CanaryOut, status_code=201)
async def submit_canary(
    body: CanaryIn,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Receive a canary payload from an attacker's browser on a honeypot page.
    Open auth: the attacker's browser cannot present an AEGIS API key. Rate-
    limited implicitly by the upstream honeypot's connection caps.
    """
    network_ip = _client_ip(request)

    # If the Pi honeypot forwards the capture, it sets source_ip_override
    # AND the connection itself comes from a private/internal CIDR.
    source_ip = network_ip
    if body.source_ip_override:
        if not _is_public_ip(network_ip):
            # Trusted internal forwarder — accept the override
            source_ip = body.source_ip_override

    # If the connecting IP is internal AND no override given, skip (self-scan)
    if not _is_public_ip(source_ip) and not body.source_ip_override:
        return CanaryOut(
            id="skipped-internal",
            source_ip=source_ip,
            captured_at=datetime.utcnow().isoformat(),
        )

    # Pick the first reflexive/public candidate that differs from source_ip
    real_ip = None
    for cand in body.webrtc_candidates or []:
        if not isinstance(cand, str):
            continue
        cand = cand.strip()
        if _is_public_ip(cand) and cand != source_ip:
            real_ip = cand
            break

    canary = HoneypotCanary(
        client_id=None,
        source_ip=source_ip,
        real_ip_webrtc=real_ip,
        webrtc_candidates=(body.webrtc_candidates or [])[:32],
        fingerprint_hash=(body.fingerprint_hash or "")[:64] or None,
        headless_detected=bool(body.headless_detected),
        browser_meta=body.browser_meta or {},
        honeypot_source=(body.honeypot_source or "unknown")[:64],
        captured_at=datetime.utcnow(),
    )
    db.add(canary)

    # If the real IP differs from the connecting one, raise an incident on
    # the AttackerProfile (best-effort; do not fail the canary write).
    if real_ip and real_ip != source_ip:
        try:
            result = await db.execute(
                select(AttackerProfile).where(AttackerProfile.source_ip == source_ip)
            )
            prof = result.scalar_one_or_none()
            if prof:
                known = list(prof.known_ips or [])
                if real_ip not in known:
                    known.append(real_ip)
                    prof.known_ips = known
                # Stamp the assessment with the leak
                tail = f"WEBRTC LEAK {datetime.utcnow().isoformat()}: {source_ip} -> real {real_ip}"
                prof.ai_assessment = ((prof.ai_assessment or "") + "\n" + tail).strip()[:4000]
        except Exception as exc:
            logger.warning("attacker profile update failed for canary %s: %s", source_ip, exc)

    try:
        await db.commit()
    except Exception as exc:
        await db.rollback()
        logger.error("canary commit failed: %s", exc)
        raise HTTPException(status_code=500, detail="canary store failed")

    logger.info(
        "[canary] captured src=%s real=%s fp=%s headless=%s source=%s",
        source_ip, real_ip, canary.fingerprint_hash, canary.headless_detected,
        canary.honeypot_source,
    )

    return CanaryOut(
        id=canary.id,
        source_ip=canary.source_ip,
        real_ip_webrtc=canary.real_ip_webrtc,
        fingerprint_hash=canary.fingerprint_hash,
        headless_detected=bool(canary.headless_detected),
        honeypot_source=canary.honeypot_source,
        captured_at=canary.captured_at.isoformat(),
    )


# ---------------------------------------------------------------------------
# GET — analyst read-side (API key required)
# ---------------------------------------------------------------------------

@router.get("/canaries", response_model=list[CanaryOut])
async def list_canaries(
    limit: int = Query(50, ge=1, le=500),
    source_ip: Optional[str] = Query(None),
    auth: AuthContext = Depends(require_viewer),  # noqa: ARG001 (auth gate)
    db: AsyncSession = Depends(get_db),
):
    q = select(HoneypotCanary).order_by(desc(HoneypotCanary.captured_at)).limit(limit)
    if source_ip:
        q = q.where(HoneypotCanary.source_ip == source_ip)
    result = await db.execute(q)
    rows = result.scalars().all()
    return [
        CanaryOut(
            id=r.id,
            source_ip=r.source_ip,
            real_ip_webrtc=r.real_ip_webrtc,
            fingerprint_hash=r.fingerprint_hash,
            headless_detected=bool(r.headless_detected),
            honeypot_source=r.honeypot_source,
            captured_at=r.captured_at.isoformat(),
        )
        for r in rows
    ]


async def canaries_for_ip(db: AsyncSession, ip: str, limit: int = 10) -> list[dict]:
    """Helper used by ip_intel deep response. Returns plain dicts."""
    try:
        result = await db.execute(
            select(HoneypotCanary)
            .where(HoneypotCanary.source_ip == ip)
            .order_by(desc(HoneypotCanary.captured_at))
            .limit(limit)
        )
        rows = result.scalars().all()
    except Exception as exc:
        logger.debug("canaries_for_ip failed for %s: %s", ip, exc)
        return []
    return [
        {
            "id": r.id,
            "captured_at": r.captured_at.isoformat(),
            "real_ip_webrtc": r.real_ip_webrtc,
            "fingerprint_hash": r.fingerprint_hash,
            "headless_detected": bool(r.headless_detected),
            "browser_meta": r.browser_meta or {},
            "honeypot_source": r.honeypot_source,
        }
        for r in rows
    ]
