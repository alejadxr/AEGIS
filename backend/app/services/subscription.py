"""
Tier definitions and feature/quota gate helpers.

AEGIS offers two tiers:
- free:       Full open-source platform for individuals and homelabs
- enterprise: Commercial tier for companies with unlimited scale + premium features
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.client import Client


# ---------------------------------------------------------------------------
# Tier definitions
# ---------------------------------------------------------------------------

# Features available to all tiers (free + enterprise)
FREE_FEATURES = [
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
]

# Additional features locked behind enterprise
ENTERPRISE_FEATURES = [
    "smart_honeypots",
    "quantum_entropy",
    "grover_calculator",
    "quantum_timeline",
    "sbom_scanner",
    "advanced_reporting",
    "priority_feeds",
    "adversarial_ml",
    "compliance_dashboard",
    "sso_saml",
    "custom_sigma_rules",
    "sla_support",
    "honey_ai_deception",
]


TIERS: dict[str, dict] = {
    "free": {
        "label": "Free",
        "max_nodes": 20,
        "max_assets": 100,
        "max_users": 3,
        "features": list(FREE_FEATURES),
    },
    "enterprise": {
        "label": "Enterprise",
        "max_nodes": -1,   # unlimited
        "max_assets": -1,  # unlimited
        "max_users": -1,   # unlimited
        "features": list(FREE_FEATURES) + list(ENTERPRISE_FEATURES),
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_tier_config(tier_name: str) -> dict:
    """Return tier config dict, defaulting to free if unknown."""
    # Legacy "pro" tier gets mapped to enterprise for backward compatibility
    if tier_name == "pro":
        return TIERS["enterprise"]
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
    "sso_saml": "SSO (SAML / OIDC)",
    "custom_sigma_rules": "Custom Sigma Rules",
    "sla_support": "SLA + Dedicated Support",
    "honey_ai_deception": "Honey-AI Deception at Scale",
}


def require_feature(client: Client, feature: str, tier: str = "enterprise") -> None:
    """Raise HTTPException with structured upgrade payload if feature missing.

    Usage::

        require_feature(auth.client, "quantum_entropy")
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
            "message": f"{label} requires the {tier_label} plan. Contact us to unlock this feature.",
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
