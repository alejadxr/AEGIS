"""Single source of truth for "which IP sent this request".

Every component that needs the client address (attack detector, DoS shield,
rate limiter, honeypots, canary) resolves it here, so a spoofed header cannot
mean one thing to the blocklist and another to the detector.

Rules:

* If the direct socket peer is NOT a configured trusted proxy, the peer IS the
  client. Forwarding headers are ignored entirely.
* If the peer is a trusted proxy (cloudflared on localhost, by default):
    1. ``CF-Connecting-IP`` wins. Cloudflare overwrites it on every request, so
       a client cannot set it through the tunnel.
    2. Otherwise walk ``X-Forwarded-For`` from the RIGHT and take the first
       address that is not itself a trusted proxy. Proxies append; the
       left-hand side is whatever the client typed. Never the first value.
    3. Otherwise the peer.

A header value that does not parse as an IP address is never returned.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Mapping, Optional

from app.config import settings

logger = logging.getLogger(__name__)

_DEFAULT_TRUSTED = "127.0.0.1,::1,100.64.0.0/10"


def parse_trusted_proxies(raw: str) -> tuple[frozenset[str], tuple]:
    """Split a comma-separated proxy list into (literal ips, networks)."""
    literals: set[str] = set()
    networks: list = []
    for token in (raw or "").split(","):
        token = token.strip()
        if not token:
            continue
        if "/" in token:
            try:
                networks.append(ipaddress.ip_network(token, strict=False))
            except ValueError:
                logger.debug("ignoring malformed trusted-proxy CIDR: %s", token)
        else:
            literals.add(token)
    return frozenset(literals), tuple(networks)


_TRUSTED_LITERALS, _TRUSTED_NETWORKS = parse_trusted_proxies(
    getattr(settings, "AEGIS_DOS_TRUSTED_PROXIES", _DEFAULT_TRUSTED)
)


def is_trusted_proxy(peer: Optional[str]) -> bool:
    if not peer:
        return False
    if peer in _TRUSTED_LITERALS:
        return True
    try:
        addr = ipaddress.ip_address(peer)
    except (ValueError, TypeError):
        return False
    # ::ffff:127.0.0.1 and friends: judge the embedded IPv4 address.
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        if str(mapped) in _TRUSTED_LITERALS:
            return True
        addr = mapped
    return any(addr.version == net.version and addr in net for net in _TRUSTED_NETWORKS)


def _valid_ip(value: Optional[str]) -> Optional[str]:
    """Return the canonical form of ``value`` if it is an IP address."""
    if not value:
        return None
    candidate = value.strip()
    # Tolerate "[2001:db8::1]" and "203.0.113.5:4321" as some proxies emit.
    if candidate.startswith("["):
        candidate = candidate[1:].split("]", 1)[0]
    elif candidate.count(":") == 1 and "." in candidate:
        candidate = candidate.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def resolve_client_ip(peer: Optional[str], headers: Mapping[str, str]) -> str:
    """Resolve the real client IP from the socket peer and request headers.

    ``headers`` may be any case-insensitive mapping (Starlette, aiohttp) or a
    plain dict with lower-case keys.
    """
    peer = peer or "unknown"
    if not is_trusted_proxy(peer):
        return peer

    cf = _valid_ip(headers.get("cf-connecting-ip") or headers.get("CF-Connecting-IP"))
    if cf:
        return cf

    forwarded = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For")
    if forwarded:
        for hop in reversed(forwarded.split(",")):
            ip = _valid_ip(hop)
            if ip is None:
                # A malformed hop means everything to its left is untrustworthy.
                break
            if not is_trusted_proxy(ip):
                return ip
    return peer


def client_ip_from_request(request) -> str:
    """Starlette/FastAPI request -> client IP."""
    peer = request.client.host if getattr(request, "client", None) else None
    return resolve_client_ip(peer, request.headers)


def client_ip_from_aiohttp(request) -> str:
    """aiohttp request (honeypots) -> client IP."""
    return resolve_client_ip(getattr(request, "remote", None), request.headers)


def rate_limit_key(request) -> str:
    """slowapi ``key_func``: limit per real client, not per proxy.

    ``slowapi.util.get_remote_address`` returns the socket peer, which behind
    the tunnel is always localhost: one global bucket shared by everyone.
    """
    return client_ip_from_request(request)
