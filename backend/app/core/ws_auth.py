"""Authentication for the live-event WebSocket.

HTTP middleware does not see the ``websocket`` scope, so ``/ws`` enforces its
own gate: the blocklist is checked on connect, and the first frame must be

    {"type": "auth", "token": "<JWT>"}      or
    {"type": "auth", "api_key": "<key>"}

The credential travels in a frame, never in the URL (URLs end up in proxy and
access logs). Until that frame validates, the socket is not registered with the
push manager and receives no events.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Optional

from fastapi import HTTPException
from sqlalchemy import select

from app.core.client_ip import resolve_client_ip

logger = logging.getLogger("aegis.ws_auth")

AUTH_TIMEOUT_SECONDS = 10.0
CLOSE_UNAUTHORIZED = 4401
CLOSE_FORBIDDEN = 4403


@dataclass(frozen=True)
class WSIdentity:
    tenant_id: str
    role: str
    label: str


async def identity_from_credentials(
    db, token: Optional[str] = None, api_key: Optional[str] = None
) -> Optional[WSIdentity]:
    """Validate an API key or JWT. Returns None when neither is valid."""
    from app.core.auth import decode_jwt_token
    from app.models.client import Client

    if api_key and isinstance(api_key, str):
        row = await db.execute(select(Client).where(Client.api_key == api_key))
        client = row.scalar_one_or_none()
        if client:
            return WSIdentity(tenant_id=client.id, role="admin", label=f"apikey:{client.slug}")

    if token and isinstance(token, str):
        try:
            payload = decode_jwt_token(token)
        except HTTPException:
            return None
        if payload.get("type", "client") == "user":
            from app.models.user import User

            row = await db.execute(select(User).where(User.id == payload.get("sub")))
            user = row.scalar_one_or_none()
            if not user or not user.is_active or not user.client_id:
                return None
            role = user.role.value if hasattr(user.role, "value") else str(user.role)
            return WSIdentity(tenant_id=user.client_id, role=role, label=f"user:{user.id}")
        row = await db.execute(select(Client).where(Client.id == payload.get("sub")))
        client = row.scalar_one_or_none()
        if client:
            return WSIdentity(tenant_id=client.id, role="admin", label=f"client:{client.slug}")
    return None


def websocket_client_ip(websocket) -> str:
    peer = websocket.client.host if getattr(websocket, "client", None) else None
    return resolve_client_ip(peer, websocket.headers)


def websocket_ip_is_blocked(websocket) -> bool:
    """The 403 blocklist, applied to a scope the HTTP middleware never sees."""
    try:
        from app.core import attack_detector

        return websocket_client_ip(websocket) in attack_detector._blocked_ips
    except Exception:  # pragma: no cover - never fail open on import trouble
        logger.exception("blocklist check failed for websocket")
        return False


async def authenticate_websocket(websocket, session_factory) -> Optional[WSIdentity]:
    """Wait for the auth frame on an ACCEPTED socket.

    Returns the identity, or None after closing the socket with 4401.
    """
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=AUTH_TIMEOUT_SECONDS)
        msg = json.loads(raw)
    except (asyncio.TimeoutError, json.JSONDecodeError, TypeError, ValueError):
        msg = None
    identity = None
    if isinstance(msg, dict) and msg.get("type") == "auth":
        async with session_factory() as db:
            identity = await identity_from_credentials(
                db, token=msg.get("token"), api_key=msg.get("api_key")
            )
    if identity is None:
        try:
            await websocket.close(code=CLOSE_UNAUTHORIZED)
        except Exception:
            pass
    return identity
