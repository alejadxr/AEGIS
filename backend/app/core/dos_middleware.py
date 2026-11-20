"""DoS Shield middleware (v1.6.4.0).

Two thin ASGI/Starlette middlewares registered by main.py (owner B) OUTSIDE the
heavy AttackDetectorMiddleware so floods are shed with minimal work:

    DoSShieldMiddleware   — consults the ``dos_shield`` singleton per request.
                            monitor mode: never blocks (detect + emit only).
                            active mode:  429 + Retry-After on THROTTLE/BLOCK.
    BodySizeLimitMiddleware — rejects Content-Length > DOS_MAX_BODY_BYTES (413)
                            before the body is read into RAM.

The middleware is intentionally cheap: it short-circuits health/internal
SKIP_PATHS and safe IPs before touching dos_shield, derives the counting key
via a trusted-proxy-aware ``_client_ip`` helper (defeating X-Forwarded-For
spoofing from untrusted peers), and wraps the downstream call in
begin_request/end_request for slow-loris concurrency accounting.

Reuses (never reinvents): ``_is_safe_ip`` and ``SKIP_PATHS`` from
app.core.attack_detector, ``settings`` from app.config, and the ``dos_shield``
singleton from app.services.dos_shield.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.config import settings
from app.core.attack_detector import _is_safe_ip, SKIP_PATHS

logger = logging.getLogger("cayde6.dos")

# The core singleton. Import guarded so the app still boots if the (parallel)
# dos_shield module is missing during partial deploys — the middleware then
# degrades to a pure pass-through.
try:  # pragma: no cover - trivial import guard
    from app.services.dos_shield import (
        dos_shield,
        ACTION_THROTTLE,
        ACTION_BLOCK,
        MODE_ACTIVE,
    )
    _DOS_AVAILABLE = True
except Exception as _exc:  # noqa: BLE001
    dos_shield = None  # type: ignore[assignment]
    ACTION_THROTTLE = "throttle"
    ACTION_BLOCK = "block"
    MODE_ACTIVE = "active"
    _DOS_AVAILABLE = False
    logging.getLogger("cayde6.dos").warning(
        "dos_shield unavailable — DoSShieldMiddleware degraded to pass-through: %s",
        _exc,
    )


# ---------------------------------------------------------------------------
# Trusted-proxy parsing for _client_ip
# ---------------------------------------------------------------------------

from app.core.client_ip import (  # noqa: E402
    client_ip_from_request,
    is_trusted_proxy as _is_trusted_proxy,
    parse_trusted_proxies as _parse_trusted_proxies,
)


def _client_ip(request) -> str:
    """Derive the client IP. See ``app.core.client_ip`` for the rules.

    Forwarding headers are honoured ONLY when the direct socket peer is a
    configured trusted proxy, and then never the attacker-writable first
    X-Forwarded-For value: ``CF-Connecting-IP`` first, else the right-most
    non-proxy hop.
    """
    return client_ip_from_request(request)


# ---------------------------------------------------------------------------
# BodySizeLimitMiddleware
# ---------------------------------------------------------------------------

class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized requests by Content-Length before the body is read.

    Mitigates slow-POST/RUDY and large-payload memory exhaustion. Gated purely
    on the advertised Content-Length header (cheap; no body read).
    """

    async def dispatch(self, request, call_next):
        max_bytes = int(getattr(settings, "AEGIS_DOS_MAX_BODY_BYTES", 10485760))
        cl = request.headers.get("content-length")
        if cl:
            try:
                if int(cl) > max_bytes:
                    return JSONResponse(
                        {"detail": "request_entity_too_large",
                         "max_bytes": max_bytes},
                        status_code=413,
                    )
            except (ValueError, TypeError):
                # Malformed Content-Length — let downstream handle it.
                pass
        return await call_next(request)


# ---------------------------------------------------------------------------
# DoSShieldMiddleware
# ---------------------------------------------------------------------------

class DoSShieldMiddleware(BaseHTTPMiddleware):
    """Outermost flood-shedding middleware.

    On each request:
      1. Fast-exit health/internal SKIP_PATHS.
      2. Derive counting key via _client_ip(); fast-exit safe IPs.
      3. dos_shield.record_request(ip, path, method) -> Verdict.
      4. In ACTIVE mode with a THROTTLE/BLOCK verdict, return 429 (+ Retry-After;
         BLOCK additionally fire-and-forgets escalate()). In monitor mode always
         pass through (detection only).
      5. Bracket the downstream call in begin_request/end_request for slow-loris
         concurrency accounting.
    """

    async def dispatch(self, request, call_next):
        path = request.url.path

        # (1) Skip health / internal endpoints entirely — no accounting.
        if path in SKIP_PATHS:
            return await call_next(request)

        # Degraded mode (dos_shield missing): pure pass-through.
        if not _DOS_AVAILABLE or dos_shield is None:
            return await call_next(request)

        # (2) Safe-IP fast-exit (crawlers / Tailscale / localhost / AEGIS_SAFE_IPS).
        ip = _client_ip(request)
        if _is_safe_ip(ip, request.headers.get("user-agent", "")):
            return await call_next(request)

        # (3) Hot-path record.
        try:
            verdict = dos_shield.record_request(ip, path, request.method)
        except Exception as exc:  # never let the shield break the request path
            logger.debug("dos_shield.record_request error (fail-open): %s", exc)
            return await call_next(request)

        # (4) Enforcement — active mode only.
        if verdict.mode == MODE_ACTIVE and verdict.action in (
            ACTION_THROTTLE,
            ACTION_BLOCK,
        ):
            if verdict.action == ACTION_BLOCK:
                # Fire-and-forget escalation so the response is not blocked on
                # ip_blocker + firewall_client round-trips.
                try:
                    asyncio.create_task(dos_shield.escalate(ip, verdict.reason))
                except Exception as exc:  # noqa: BLE001
                    logger.debug("dos_shield.escalate schedule failed: %s", exc)
            return JSONResponse(
                {"detail": "rate_limited", "reason": verdict.reason},
                status_code=429,
                headers={"Retry-After": str(verdict.retry_after or 1)},
            )

        # (5) Pass through, bracketed for concurrency / slow-loris accounting.
        try:
            dos_shield.begin_request(ip)
        except Exception as exc:  # noqa: BLE001
            logger.debug("dos_shield.begin_request error: %s", exc)
        try:
            return await call_next(request)
        finally:
            try:
                dos_shield.end_request(ip)
            except Exception as exc:  # noqa: BLE001
                logger.debug("dos_shield.end_request error: %s", exc)
