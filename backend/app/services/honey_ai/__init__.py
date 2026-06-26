"""Honey-AI Deception at Scale.

Auto-generate massive fake infrastructure (50+ decoy services per campaign)
with realistic AI-generated content.  Every fake asset embeds a breadcrumb
UUID that is tracked in the database.  When a breadcrumb UUID appears in the
logs of a *real* service, the :class:`BreadcrumbTracker` raises a CRITICAL
incident linking the bait campaign to the attacker.

Main exports:

* :class:`DeceptionOrchestrator` — deploy / stop / rotate campaigns
* :class:`Campaign`, :class:`ServiceMix`, :class:`ThemeConfig` — config dataclasses
* :class:`BreadcrumbTracker` — mint + match breadcrumb UUIDs
* :class:`ContentGenerator` — realistic fake JSON/CSV/HTML via AI or Faker
* :data:`THEMES` — preset theme configs
"""

from app.services.honey_ai.campaign import (
    Campaign,
    CampaignStatus,
    ServiceMix,
    ThemeConfig,
)
from app.services.honey_ai.themes import THEMES, get_theme
from app.services.honey_ai.content_generator import ContentGenerator, content_generator
from app.services.honey_ai.breadcrumb_tracker import (
    BreadcrumbTracker,
    breadcrumb_tracker,
)
from app.services.honey_ai.orchestrator import (
    DeceptionOrchestrator,
    deception_orchestrator,
)

__all__ = [
    "Campaign",
    "CampaignStatus",
    "ServiceMix",
    "ThemeConfig",
    "THEMES",
    "get_theme",
    "ContentGenerator",
    "content_generator",
    "BreadcrumbTracker",
    "breadcrumb_tracker",
    "DeceptionOrchestrator",
    "deception_orchestrator",
]
