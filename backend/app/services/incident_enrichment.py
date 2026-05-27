"""Incident enrichment hook — auto-attaches IP intel to every new incident.

Registers an SQLAlchemy `after_insert` event listener on the Incident model.
When the listener fires, it schedules a background asyncio task that:
  1. Calls ip_intel.lookup(source_ip)
  2. Updates the row's ai_analysis JSON with {"ip_intel": {...}}

The listener itself is sync and does NOT block the INSERT. The actual HTTP
lookups + DB update happen in a fire-and-forget task. If the asyncio loop
isn't available (e.g. sync context), enrichment is silently skipped — the
incident still gets created cleanly.

Opt-out via env var: AEGIS_INCIDENT_ENRICH=0 disables the listener.
Default ON (any value other than "0"/"false"/"no" enables it).

To activate at process startup, import this module once from app/main.py.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os

from sqlalchemy import event, update

from app.database import async_session
from app.models.incident import Incident
from app.services.ip_intel import lookup

logger = logging.getLogger("aegis.incident_enrichment")


def _enabled() -> bool:
    raw = os.environ.get("AEGIS_INCIDENT_ENRICH", "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def _is_lookupable(ip: str | None) -> bool:
    """Skip enrichment for private/loopback/CGNAT — ip_intel filters them too,
    but doing it here avoids spawning unnecessary tasks."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_loopback or addr.is_private or addr.is_link_local)
    except (ValueError, TypeError):
        return False


async def _enrich(incident_id: str, src_ip: str) -> None:
    try:
        intel = await lookup(src_ip)
    except Exception as exc:
        logger.warning(f"ip_intel.lookup failed for {src_ip}: {exc}")
        return
    if not intel or intel.get("internal"):
        return
    try:
        async with async_session() as db:
            row = await db.get(Incident, incident_id)
            if row is None:
                return
            analysis = dict(row.ai_analysis or {})
            analysis["ip_intel"] = intel
            await db.execute(
                update(Incident)
                .where(Incident.id == incident_id)
                .values(ai_analysis=analysis)
            )
            await db.commit()
        logger.info(
            f"enriched incident {incident_id} src_ip={src_ip} "
            f"asn={intel.get('asn')} country={intel.get('country')}"
        )
    except Exception as exc:
        logger.warning(
            f"failed to write ip_intel for incident {incident_id}: {exc}"
        )


# Strong references so asyncio doesn't GC our fire-and-forget tasks.
_pending_tasks: set[asyncio.Task] = set()


def _schedule(incident_id: str, src_ip: str) -> None:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # No running loop (sync context, e.g. during startup or sync tests).
        logger.debug(f"no running loop — skipping enrichment for {src_ip}")
        return
    task = loop.create_task(_enrich(incident_id, src_ip))
    _pending_tasks.add(task)
    task.add_done_callback(_pending_tasks.discard)
    logger.debug(f"scheduled enrichment task for incident {incident_id} ip={src_ip}")


def _maybe_enrich(target: Incident) -> None:
    if not _enabled():
        return
    src_ip = target.source_ip
    if not _is_lookupable(src_ip):
        return
    _schedule(str(target.id), src_ip)


# Listen on BOTH events. `after_insert` (Mapper) fires inside the flush —
# reliable for sync sessions, sometimes silent under async session greenlets.
# `do_orm_execute` (Session) fires for ORM INSERTs and reliably works under
# async sessions. We dedupe with the incident id below.
@event.listens_for(Incident, "after_insert")
def _on_incident_insert(mapper, connection, target: Incident) -> None:  # noqa: ARG001
    _maybe_enrich(target)


# Session-level fallback: capture freshly-persisted incidents on commit.
# `pending_to_persistent` fires per object as the session flushes inserts,
# even under AsyncSession. This guarantees we never miss an incident.
from sqlalchemy.orm import Session  # noqa: E402


@event.listens_for(Session, "pending_to_persistent")
def _on_session_pending_to_persistent(session, instance):  # noqa: ARG001
    if isinstance(instance, Incident):
        _maybe_enrich(instance)


logger.info(
    "incident enrichment listener registered (AEGIS_INCIDENT_ENRICH=%s)",
    os.environ.get("AEGIS_INCIDENT_ENRICH", "1"),
)
