"""
Freemium tier definitions and feature/quota gate helpers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.client import Client


# ---------------------------------------------------------------------------
# Tier definitions
# ---------------------------------------------------------------------------

TIERS: dict[str, dict] = {
    "free": {
        "label": "Free",
        "max_nodes": 3,
        "max_assets": 25,
        "max_users": 3,
        "features": [
            "counter_attack",
            "intel_sharing",
            "detection_pipeline",
            "sigma_rules",
            "playbooks",
            "honeypots",
            "behavioral_ml",
            "node_agent",
            "rbac",
            "dashboard",
        ],
    },
    "pro": {
        "label": "Pro",
        "max_nodes": 25,
        "max_assets": 500,
        "max_users": 15,
        "features": [
            # Inherits all free features
            "counter_attack",
            "intel_sharing",
            "detection_pipeline",
            "sigma_rules",
            "playbooks",
            "honeypots",
            "behavioral_ml",
            "node_agent",
            "rbac",
            "dashboard",
            # Pro additions
            "quantum_entropy",
            "grover_calculator",
            "sbom_scanner",
            "advanced_reporting",
            "priority_feeds",
            "smart_honeypots",
        ],
    },
    "enterprise": {
        "label": "Enterprise",
        "max_nodes": -1,   # unlimited
        "max_assets": -1,  # unlimited
        "max_users": -1,   # unlimited
        "features": [
            # All free + pro features
            "counter_attack",
            "intel_sharing",
            "detection_pipeline",
            "sigma_rules",
            "playbooks",
            "honeypots",
            "behavioral_ml",
            "node_agent",
            "rbac",
            "dashboard",
            "quantum_entropy",
            "grover_calculator",
            "sbom_scanner",
            "advanced_reporting",
            "priority_feeds",
            "smart_honeypots",
            # Enterprise additions
            "adversarial_ml",
            "compliance_dashboard",
            "sso_saml",
            "custom_sigma_rules",
            "quantum_timeline",
        ],
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_tier_config(tier_name: str) -> dict:
    """Return tier config dict, defaulting to free if unknown."""
    return TIERS.get(tier_name, TIERS["free"])


def check_feature(client: Client, feature: str) -> bool:
    """Return True if the client's tier includes *feature*."""
    tier_cfg = get_tier_config(client.tier)
    return feature in tier_cfg["features"]


FEATURE_LABELS: dict[str, str] = {
    "quantum_entropy": "Quantum Entropy Analysis",
    "grover_calculator": "Quantum Crypto Assessment",
    "adversarial_ml": "Adversarial ML Detection",
    "advanced_reporting": "Advanced PDF Reports",
    "compliance_dashboard": "Compliance Dashboard",
    "smart_honeypots": "Smart Honeypots",
    "sbom_scanner": "SBOM Scanner",
    "quantum_timeline": "Quantum Vulnerability Timeline",
    "priority_feeds": "Priority Threat Feeds",
}


def require_feature(client: Client, feature: str, tier: str = "pro") -> None:
    """Raise HTTPException with structured upgrade payload if feature missing.

    Usage::

        require_feature(auth.client, "quantum_entropy", "pro")
    """
    if check_feature(client, feature):
        return
    from fastapi import HTTPException

    label = FEATURE_LABELS.get(feature, feature.replace("_", " ").title())
    tier_label = TIERS.get(tier, {}).get("label", tier.title())
    raise HTTPException(
        status_code=403,
        detail={
            "upgrade_required": True,
            "feature": feature,
            "feature_label": label,
            "tier_needed": tier,
            "tier_label": tier_label,
            "message": f"{label} requires the {tier_label} plan. Upgrade to unlock this feature.",
        },
    )


def check_quota(client: Client, resource: str, current_count: int) -> bool:
    """
    Return True if adding one more *resource* would still be within quota.
    *resource* is one of 'nodes', 'assets', 'users'.
    Uses the limit stored on the Client row (which may have been overridden
    individually), falling back to the tier default.
    """
    resource_map = {
        "nodes": "max_nodes",
        "assets": "max_assets",
        "users": "max_users",
    }
    attr = resource_map.get(resource)
    if attr is None:
        return True  # unknown resource type -> allow

    limit = getattr(client, attr, None)
    if limit is None:
        limit = get_tier_config(client.tier).get(attr, -1)

    if limit == -1:  # unlimited
        return True

    return current_count < limit
