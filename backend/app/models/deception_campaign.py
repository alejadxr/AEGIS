"""DeceptionCampaign model — Postgres-backed persistence for Honey-AI campaigns.

``app/services/honey_ai/orchestrator.py`` keeps an in-memory dict of
:class:`app.services.honey_ai.campaign.Campaign` dataclasses as the fast-read
source of truth, but that dict is lost on every process restart (PM2 restart,
deploy, crash) while the underlying ``honey_breadcrumbs`` rows survive —
leaving orphaned breadcrumbs with no visible parent campaign.

This model persists a row per campaign so the orchestrator can rehydrate its
in-memory dict at boot (see ``DeceptionOrchestrator.rehydrate`` and the
``lifespan`` wiring in ``app/main.py``).

Only the fields that are useful to query/filter directly get their own
column (``client_id``, ``name``, ``status``). Everything else the in-memory
``Campaign`` dataclass tracks (theme, decoy_count, service_mix, rotation_hours,
honeypot_ids, breadcrumb_ids, error, deployed_at/last_rotated_at/stopped_at)
is serialized into the ``config`` JSON blob and reconstructed on rehydration.
"""
from sqlalchemy import ForeignKey, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDMixin


class DeceptionCampaign(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "deception_campaigns"

    client_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("clients.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # Mirrors app.services.honey_ai.campaign.CampaignStatus values
    # (pending/deploying/running/rotating/stopped/failed).
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    # Everything else the in-memory Campaign dataclass carries: theme,
    # decoy_count, service_mix, rotation_hours, honeypot_ids, breadcrumb_ids,
    # error, deployed_at, last_rotated_at, stopped_at.
    config: Mapped[dict] = mapped_column(JSON, default=dict)
