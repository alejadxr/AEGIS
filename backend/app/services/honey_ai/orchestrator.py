"""Deception orchestrator — deploy, stop and rotate campaigns.

A *campaign* is a bundle of decoy honeypots (web, db, files, admin) sharing
a single theme.  On deploy the orchestrator:

1. Picks a service mix (how many of each kind) from the Campaign config.
2. For each decoy, asks :mod:`phantom.orchestrator` to spin up the matching
   smart honeypot with a per-decoy config pointing at the campaign + theme.
3. Generates an initial batch of breadcrumbs and persists them so the
   tracker can later match them in real logs.
4. Keeps the ``Campaign`` object in memory; persistence of the individual
   decoys happens via the existing Honeypot rows.

Rotation mutates the campaign (regen breadcrumbs, bump versions) to avoid
attacker fingerprinting.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events import event_bus
from app.services.honey_ai.breadcrumb_tracker import breadcrumb_tracker
from app.services.honey_ai.campaign import (
    Campaign,
    CampaignStatus,
    ServiceMix,
)
from app.services.honey_ai.content_generator import content_generator
from app.services.honey_ai.themes import get_theme

logger = logging.getLogger("aegis.honey_ai.orchestrator")


# ---------------------------------------------------------------------------
# Map a decoy "kind" to a phantom honeypot type + base port range
# ---------------------------------------------------------------------------
#
# We intentionally re-use the existing smart_http / smart_api / smart_db
# honeypot types so deployment hits the same code path the user already
# trusts, but each decoy gets a unique port and a campaign-stamped config.

DECOY_MAPPING: dict[str, dict] = {
    "web": {
        "honeypot_type": "smart_http",
        "port_base": 18080,
        "config_factory": lambda theme: {
            "app_type": "nextjs",
            "ai_responses": True,
            "breadcrumb_env": True,
            "theme": theme,
        },
    },
    "db": {
        "honeypot_type": "smart_db",
        "port_base": 13306,
        "config_factory": lambda theme: {
            "fake_engine": "mysql",
            "fake_databases": ["production", "users", "billing"],
            "injection_detection": True,
            "theme": theme,
        },
    },
    "files": {
        "honeypot_type": "smart_http",
        "port_base": 18180,
        "config_factory": lambda theme: {
            "app_type": "nextjs",
            "ai_responses": True,
            "breadcrumb_env": True,
            "fake_paths": ["/files", "/downloads", "/backup", "/export"],
            "theme": theme,
        },
    },
    "admin": {
        "honeypot_type": "smart_api",
        "port_base": 19090,
        "config_factory": lambda theme: {
            "fake_users": 50,
            "injection_detection": True,
            "api_key_tracking": True,
            "admin_panel": True,
            "theme": theme,
        },
    },
}


class DeceptionOrchestrator:
    """Deploy, rotate and tear down multi-decoy deception campaigns."""

    def __init__(self) -> None:
        # In-memory registry.  The *source of truth* for persisted decoys
        # is the ``honeypots`` table — this dict is the live view.
        self._campaigns: dict[str, Campaign] = {}
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def list_campaigns(self, client_id: Optional[str] = None) -> list[Campaign]:
        values = list(self._campaigns.values())
        if client_id:
            values = [c for c in values if c.client_id == client_id]
        return sorted(values, key=lambda c: c.created_at, reverse=True)

    def get(self, campaign_id: str) -> Optional[Campaign]:
        return self._campaigns.get(campaign_id)

    # ------------------------------------------------------------------
    # Deploy
    # ------------------------------------------------------------------

    async def deploy_campaign(
        self,
        campaign: Campaign,
        db: AsyncSession,
        client=None,
    ) -> Campaign:
        """Spin up the full set of decoys for a campaign.

        Raises :class:`ValueError` if the client isn't entitled to the
        ``honey_ai_deception`` feature — callers are expected to check
        with :func:`require_feature` before reaching here, but we defend
        in depth too.
        """
        from app.modules.phantom.orchestrator import honeypot_orchestrator
        from app.services.subscription import check_feature

        async with self._lock:
            if client is not None and not check_feature(client, "honey_ai_deception"):
                raise ValueError(
                    "honey_ai_deception feature not enabled for this client"
                )

            theme_cfg = get_theme(campaign.theme)
            campaign.service_mix.validate()
            slots = campaign.service_mix.distribute(campaign.decoy_count)

            campaign.status = CampaignStatus.DEPLOYING
            self._campaigns[campaign.id] = campaign

            logger.info(
                f"[honey_ai] Deploying campaign '{campaign.name}' "
                f"(theme={campaign.theme}, decoys={campaign.decoy_count}, slots={slots})"
            )

            deployed_ids: list[str] = []
            breadcrumbs: list[dict] = []

            # Breadcrumb accumulator callback passed down to the content
            # generator — every fake field the generator mints registers
            # a breadcrumb here.
            def _mint(bait_kind: str, preview: str) -> str:
                bc_uuid = breadcrumb_tracker.mint()
                breadcrumbs.append({
                    "breadcrumb_uuid": bc_uuid,
                    "bait_kind": bait_kind,
                    "planted_in": f"campaign:{campaign.name}",
                    "context": {
                        "preview": preview[:120],
                        "theme": campaign.theme,
                    },
                })
                return bc_uuid

            slot_index = 0
            for kind, count in slots.items():
                meta = DECOY_MAPPING.get(kind)
                if not meta or count <= 0:
                    continue

                for i in range(count):
                    slot_index += 1
                    port = meta["port_base"] + slot_index
                    name = f"{campaign.name}-{kind}-{i + 1:03d}"
                    config = meta["config_factory"](campaign.theme)
                    config["campaign_id"] = campaign.id
                    config["port"] = port
                    try:
                        honeypot = await honeypot_orchestrator.deploy(
                            honeypot_type=meta["honeypot_type"],
                            name=name,
                            client_id=campaign.client_id,
                            db=db,
                            custom_config=config,
                            client=client,
                        )
                        deployed_ids.append(honeypot.id)
                    except Exception as e:
                        logger.warning(
                            f"[honey_ai] Failed to deploy decoy {name}: {e}"
                        )
                        continue

            # Generate an initial batch of fake users per campaign to warm up
            # the breadcrumb table.  Even if nobody hits the decoy yet we
            # want breadcrumbs in the DB so log scanning works immediately.
            try:
                content_generator.fake_users(
                    theme_cfg,
                    count=min(50, campaign.decoy_count),
                    breadcrumb_provider=_mint,
                )
            except Exception as e:  # pragma: no cover - defensive
                logger.error(f"[honey_ai] content warmup failed: {e}")

            # Persist breadcrumbs in one batch
            if breadcrumbs:
                try:
                    breadcrumb_ids = await breadcrumb_tracker.save_breadcrumbs(
                        db, campaign.client_id, campaign.id, breadcrumbs,
                    )
                    campaign.breadcrumb_ids.extend(breadcrumb_ids)
                except Exception as e:  # pragma: no cover
                    logger.error(f"[honey_ai] breadcrumb save failed: {e}")

            campaign.honeypot_ids = deployed_ids
            campaign.status = (
                CampaignStatus.RUNNING if deployed_ids else CampaignStatus.FAILED
            )
            campaign.deployed_at = datetime.utcnow()
            if not deployed_ids:
                campaign.error = "No decoys were deployed successfully"

            await event_bus.publish("honey_ai.campaign_deployed", {
                "campaign_id": campaign.id,
                "name": campaign.name,
                "theme": campaign.theme,
                "decoy_count": len(deployed_ids),
                "breadcrumbs": len(breadcrumbs),
            })

            logger.info(
                f"[honey_ai] Campaign '{campaign.name}' now RUNNING with "
                f"{len(deployed_ids)} decoys and {len(breadcrumbs)} breadcrumbs"
            )
            return campaign

    # ------------------------------------------------------------------
    # Stop
    # ------------------------------------------------------------------

    async def stop_campaign(
        self,
        campaign_id: str,
        db: AsyncSession,
    ) -> Optional[Campaign]:
        """Tear down all decoys for the campaign."""
        from sqlalchemy import select
        from app.models.honeypot import Honeypot
        from app.modules.phantom.orchestrator import honeypot_orchestrator

        async with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return None

            logger.info(f"[honey_ai] Stopping campaign '{campaign.name}'")

            for honeypot_id in campaign.honeypot_ids:
                try:
                    result = await db.execute(
                        select(Honeypot).where(Honeypot.id == honeypot_id)
                    )
                    hp = result.scalar_one_or_none()
                    if hp:
                        await honeypot_orchestrator.remove(hp, db)
                except Exception as e:
                    logger.warning(
                        f"[honey_ai] Failed to remove decoy {honeypot_id}: {e}"
                    )

            campaign.status = CampaignStatus.STOPPED
            campaign.stopped_at = datetime.utcnow()
            campaign.honeypot_ids = []

            await event_bus.publish("honey_ai.campaign_stopped", {
                "campaign_id": campaign.id,
                "name": campaign.name,
            })
            return campaign

    # ------------------------------------------------------------------
    # Rotate
    # ------------------------------------------------------------------

    async def rotate_campaign(
        self,
        campaign_id: str,
        db: AsyncSession,
        client=None,
    ) -> Optional[Campaign]:
        """Regenerate breadcrumbs and bump decoy configs to defeat fingerprinting."""
        async with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return None

            logger.info(f"[honey_ai] Rotating campaign '{campaign.name}'")
            campaign.status = CampaignStatus.ROTATING

        # Stop + redeploy with the same config — simplest, guarantees new
        # ports / fresh breadcrumbs / new fake data distribution.
        await self.stop_campaign(campaign_id, db)
        # Reset deployment state for the redeploy
        campaign.honeypot_ids = []
        campaign.breadcrumb_ids = []
        campaign.status = CampaignStatus.PENDING
        campaign.last_rotated_at = datetime.utcnow()
        await self.deploy_campaign(campaign, db, client=client)
        return campaign

    # ------------------------------------------------------------------
    # Test helper — directly register an externally-built campaign
    # ------------------------------------------------------------------

    def _register(self, campaign: Campaign) -> None:
        """Used by tests to stash a campaign without running deploy."""
        self._campaigns[campaign.id] = campaign


deception_orchestrator = DeceptionOrchestrator()
