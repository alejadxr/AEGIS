"""Which tenant owns platform-level events.

Detections raised by the platform itself (inline detector, log watcher, switch
monitor, notifier) are not tied to a request, so they need a home tenant.
``select(Client).limit(1)`` has no ORDER BY: which row comes back is up to the
database, and it changes the moment a second tenant exists. The primary tenant
is defined explicitly instead: the oldest organisation that is not the seeded
``demo`` one, falling back to ``demo`` on an unconfigured install.
"""

from __future__ import annotations

from sqlalchemy import case, select

from app.models.client import Client


def primary_client_query():
    return (
        select(Client)
        .order_by(case((Client.slug == "demo", 1), else_=0), Client.created_at.asc(), Client.id.asc())
        .limit(1)
    )


async def primary_client(db):
    """The tenant that receives platform-level incidents and notifications."""
    return (await db.execute(primary_client_query())).scalar_one_or_none()
