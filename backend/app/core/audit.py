"""Audit logging helper for security-relevant events."""

import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog

logger = logging.getLogger("aegis.audit")


async def log_audit(
    db: AsyncSession,
    action: str,
    details: str,
    client_id: str,
    user_id: Optional[str] = None,
) -> None:
    """Write a security audit log entry.

    Parameters
    ----------
    db : AsyncSession
        Active database session (caller is responsible for commit).
    action : str
        Short action label, e.g. "user_login", "signup", "ip_blocked".
    details : str
        Human-readable description of what happened.
    client_id : str
        The tenant this event belongs to.
    user_id : str | None
        The acting user, if applicable.
    """
    try:
        entry = AuditLog(
            client_id=client_id,
            action=action,
            input_summary=details,
            # Store user_id in ai_reasoning field (repurposed for security audit context)
            ai_reasoning=f"user_id={user_id}" if user_id else None,
        )
        db.add(entry)
        await db.flush()
        logger.info(f"AUDIT: {action} | {details}")
    except Exception as e:
        # Never let audit logging break the main flow
        logger.error(f"Failed to write audit log: {e}")
