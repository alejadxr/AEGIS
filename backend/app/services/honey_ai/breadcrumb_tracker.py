"""Breadcrumb tracker — the part that turns deception into *intelligence*.

Every piece of fake data handed out by a deception campaign includes a
trackable breadcrumb UUID.  If that UUID later shows up in the logs of a
*real* service protected by AEGIS, it proves the attacker consumed the
bait and is now trying to monetize it.  We fire a CRITICAL incident and
emit an event to the WebSocket bus so the dashboard lights up immediately.
"""
from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime
from typing import Callable, Iterable, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.honey_breadcrumb import HoneyBreadcrumb

logger = logging.getLogger("aegis.honey_ai.breadcrumb")


# Regex that matches the UUIDs we mint (8-4-4-4-12 hex with dashes OR compact
# 32-char hex) so we can scan arbitrary log text.
UUID_RE = re.compile(
    r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|hb[0-9a-f]{30})",
    re.IGNORECASE,
)


class BreadcrumbTracker:
    """Mint, persist and match breadcrumbs for deception campaigns."""

    # ------------------------------------------------------------------
    # Minting
    # ------------------------------------------------------------------

    @staticmethod
    def mint() -> str:
        """Return a fresh breadcrumb identifier.

        We prefer the ``hb`` prefix + 30 hex chars form because it survives
        CSV exports, URL encodings and partial log truncation better than
        the dashed UUID form — but both are matched by :data:`UUID_RE`.
        """
        return f"hb{uuid.uuid4().hex[:30]}"

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    async def save_breadcrumbs(
        self,
        db: AsyncSession,
        client_id: str,
        campaign_id: str,
        entries: Iterable[dict],
    ) -> list[str]:
        """Persist a batch of breadcrumbs and return the new row ids.

        Each entry dict should contain at minimum ``breadcrumb_uuid``,
        ``planted_in`` and ``bait_kind``.
        """
        ids: list[str] = []
        for e in entries:
            bc = HoneyBreadcrumb(
                client_id=client_id,
                campaign_id=campaign_id,
                breadcrumb_uuid=e["breadcrumb_uuid"],
                planted_in=e.get("planted_in", "unknown"),
                bait_kind=e.get("bait_kind", "generic"),
                context=e.get("context", {}),
                planted_at=datetime.utcnow(),
            )
            db.add(bc)
            ids.append(bc.id)
        await db.commit()
        return ids

    # ------------------------------------------------------------------
    # Log scanning
    # ------------------------------------------------------------------

    async def scan_text(
        self,
        db: AsyncSession,
        text: str,
        source: str,
        client_id: Optional[str] = None,
        incident_cb: Optional[Callable] = None,
    ) -> list[HoneyBreadcrumb]:
        """Scan an arbitrary log line for known breadcrumb UUIDs.

        If *any* match is found the breadcrumb row is updated (hit_count +1,
        last_hit_at, last_hit_source) and ``incident_cb(breadcrumb, source)``
        is invoked if provided.  Returns the list of matched breadcrumbs.
        """
        if not text:
            return []

        candidates = set(UUID_RE.findall(text))
        if not candidates:
            return []

        # Normalize case so lookups hit the DB index
        candidates_norm = {c.lower() for c in candidates}

        query = select(HoneyBreadcrumb).where(
            HoneyBreadcrumb.breadcrumb_uuid.in_(candidates_norm)
        )
        if client_id:
            query = query.where(HoneyBreadcrumb.client_id == client_id)

        result = await db.execute(query)
        matches = result.scalars().all()

        if not matches:
            return []

        now = datetime.utcnow()
        for bc in matches:
            bc.hit_count = (bc.hit_count or 0) + 1
            bc.last_hit_at = now
            bc.last_hit_source = source[:500]
            logger.critical(
                "[honey_ai] Breadcrumb HIT campaign=%s bait=%s planted_in=%s source=%s",
                bc.campaign_id, bc.bait_kind, bc.planted_in, source[:120],
            )
            if incident_cb:
                try:
                    await incident_cb(bc, source)
                except Exception as e:  # pragma: no cover
                    logger.error(f"incident_cb failed: {e}")

        await db.commit()
        return list(matches)

    async def recent_hits(
        self,
        db: AsyncSession,
        client_id: str,
        limit: int = 50,
    ) -> list[HoneyBreadcrumb]:
        """Return recent hits (hit_count >= 1) ordered by ``last_hit_at``."""
        result = await db.execute(
            select(HoneyBreadcrumb)
            .where(
                HoneyBreadcrumb.client_id == client_id,
                HoneyBreadcrumb.hit_count > 0,
            )
            .order_by(HoneyBreadcrumb.last_hit_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Incident helper — used as ``incident_cb`` in scan_text
    # ------------------------------------------------------------------

    async def raise_breadcrumb_incident(
        self,
        db: AsyncSession,
        breadcrumb: HoneyBreadcrumb,
        source: str,
    ) -> None:
        """Create a CRITICAL incident linking the campaign to a hit.

        We import locally so the tracker stays usable in unit tests that
        don't wire up the full Incident model.
        """
        try:
            from app.models.incident import Incident
        except Exception:  # pragma: no cover
            return

        incident = Incident(
            client_id=breadcrumb.client_id,
            title=(
                f"HONEY-AI BREADCRUMB HIT — {breadcrumb.bait_kind} "
                f"from campaign {breadcrumb.campaign_id[:8]}"
            ),
            description=(
                f"A breadcrumb planted in '{breadcrumb.planted_in}' was "
                f"observed in real service logs: {source[:400]}. "
                "This means an attacker consumed bait data from a deception "
                "campaign and is now re-using it against a real asset."
            ),
            severity="critical",
            source="honey_ai",
            raw_alert={
                "campaign_id": breadcrumb.campaign_id,
                "breadcrumb_uuid": breadcrumb.breadcrumb_uuid,
                "bait_kind": breadcrumb.bait_kind,
                "planted_in": breadcrumb.planted_in,
                "source": source[:500],
            },
        )
        db.add(incident)

        # Fire an event for WebSocket consumers (dashboard live alert)
        try:
            from app.core.events import event_bus
            await event_bus.publish("honey_ai.breadcrumb_hit", {
                "client_id": breadcrumb.client_id,
                "campaign_id": breadcrumb.campaign_id,
                "breadcrumb_uuid": breadcrumb.breadcrumb_uuid,
                "bait_kind": breadcrumb.bait_kind,
                "planted_in": breadcrumb.planted_in,
                "source": source[:500],
            })
        except Exception:  # pragma: no cover
            pass


breadcrumb_tracker = BreadcrumbTracker()
