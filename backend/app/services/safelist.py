"""Safelist management: the env layer + the runtime layer, as one operator view.

``app.core.safelist_store`` owns the mutable runtime entries (and is what the
detectors consult). This module is the operator-facing logic around it:

* listing both layers together, each entry tagged ``env`` or ``runtime``;
* adding and removing, refusing to "remove" something that lives in ``.env``;
* explaining WHY an address is protected, which the block endpoint uses to
  refuse an operator typo that would take down his own office.

Nothing here is reachable from the AI assistant. That is deliberate and tested
(tests/unit/test_assistant_actions.py): a safelist entry disables the
platform's defences for that address, and the assistant reads text written by
attackers.
"""
import ipaddress
import logging
from datetime import datetime
from typing import Optional

from app.core import attack_detector as _ad
from app.core import safelist_store as store
from app.core.safelist_store import SafelistError
from app.services import block_policy

logger = logging.getLogger("aegis.safelist")

CATEGORIES = store.CATEGORIES

ENV_VARS = {
    store.SAFE: "AEGIS_SAFE_IPS",
    store.INTERNAL: "AEGIS_INTERNAL_IPS",
    store.SHARED_EGRESS: "AEGIS_SHARED_EGRESS_IPS",
}

CATEGORY_MEANING = {
    store.SAFE: "never blocked and never an incident (third party known to be benign)",
    store.INTERNAL: "never blocked and never an incident (one of your own addresses)",
    store.SHARED_EGRESS: "still detected and raised, but never auto-blocked (many real users behind one address)",
}


class EnvPinned(Exception):
    """The entry is defined by an environment variable; the API cannot remove it."""

    def __init__(self, category: str, value: str):
        self.category = category
        self.value = value
        self.var = ENV_VARS[category]
        super().__init__(
            f"{value} is pinned by {self.var} in the server environment. The API cannot edit "
            f".env: remove it from {self.var} there and restart the API."
        )


class NotListed(Exception):
    pass


def _env_raw(category: str) -> tuple[set, list]:
    """(literals, networks) the env var produced at import."""
    if category == store.SAFE:
        return _ad._safe_ips_literals, _ad._safe_ips_nets
    if category == store.INTERNAL:
        return _ad._internal_ips_literals, _ad._internal_ips_nets
    return _ad._shared_egress_literals, _ad._shared_egress_env_nets


def env_entries(category: str) -> list[dict]:
    literals, nets = _env_raw(category)
    out = [{"value": v, "kind": "ip", "source": "env", "var": ENV_VARS[category]} for v in sorted(literals)]
    out += [{"value": str(n), "kind": "cidr", "source": "env", "var": ENV_VARS[category]}
            for n in sorted(nets, key=str)]
    return out


def _env_canonicals(category: str) -> set[str]:
    out = set()
    for e in env_entries(category):
        try:
            out.add(store.normalize(e["value"])[0])
        except SafelistError:
            # e.g. "localhost", or an env CIDR wider than the runtime cap: still
            # pinned, just not comparable. Keep the raw text so removal reports it.
            out.add(e["value"])
    return out


def list_category(category: str) -> list[dict]:
    return env_entries(category) + store.list_entries(category)


def list_all() -> dict:
    return {c: list_category(c) for c in CATEGORIES}


def _blocked_inside(canonical: str, is_network: bool) -> list[str]:
    """Currently-blocked addresses this entry would cover."""
    from app.core.ip_blocker import ip_blocker_service
    blocked = ip_blocker_service.list_blocked()
    if not is_network:
        return [canonical] if canonical in blocked else []
    net = ipaddress.ip_network(canonical)
    hits = []
    for b in blocked:
        try:
            if ipaddress.ip_address(b) in net:
                hits.append(b)
        except ValueError:
            continue
    return hits


async def unblock_everywhere(ip: str, db=None, by: str = "") -> dict:
    """Lift `ip` on all three layers (Pi agent, 403 blocklist, system firewall).

    With `db`, also mark the Actions that still claim to cover the IP as
    rolled back (caller commits). Otherwise ai_engine would fold the next block
    request into an Action that no longer enforces anything.
    """
    from app.config import settings
    from app.core.firewall_client import firewall_client
    from app.core.ip_blocker import ip_blocker_service
    out: dict = {"ip": ip, "pi": None, "local": None, "system_fw": None}
    if settings.AEGIS_FIREWALL_URL:
        out["pi"] = await firewall_client.unblock_ip(ip)
    out["local"] = ip_blocker_service.unblock_ip(ip)
    try:
        import app.services.firewall_local as firewall_local
        out["system_fw"] = bool(firewall_local.get_firewall().unblock(ip))
    except Exception as exc:
        out["system_fw"] = False
        logger.warning(f"system firewall unblock of {ip} failed: {exc}")
    if db is not None:
        try:
            for action in await block_policy.live_block_actions(db, ip):
                action.status = "rolled_back"
                action.parameters = {**(action.parameters or {}), "rolled_back_by": by or "operator",
                                     "rolled_back_at": datetime.utcnow().isoformat()}
        except Exception as exc:
            logger.warning(f"could not mark block actions for {ip} rolled back: {exc}")
    return out


async def add(category: str, value: str, *, added_by: str, note: str = "",
              unblock_if_blocked: bool = False, db=None) -> dict:
    """Add a runtime entry. Raises SafelistError for a value the store refuses."""
    if category not in CATEGORIES:
        raise SafelistError(f"unknown category {category!r}; use one of {', '.join(CATEGORIES)}")
    canonical, is_net = store.normalize(value)
    created = store.add(category, canonical, is_net, added_by, note)
    in_env = canonical in _env_canonicals(category)
    covered_blocks = _blocked_inside(canonical, is_net)
    unblocked: list[dict] = []
    if unblock_if_blocked and category != store.SHARED_EGRESS:
        # Shared-egress entries are still detected and may stay blocked on
        # purpose; only the two "never block" categories imply a release.
        for ip in covered_blocks:
            unblocked.append(await unblock_everywhere(ip, db, added_by))
    logger.warning(f"SAFELIST: {category} += {canonical} by {added_by} (created={created}, env={in_env})")
    return {
        "category": category, "value": canonical, "kind": "cidr" if is_net else "ip",
        "created": created, "also_in_env": in_env,
        "currently_blocked": covered_blocks,
        "unblocked": unblocked,
        "message": (
            "Added; effective immediately and kept across restarts." if created
            else "Already in the runtime safelist; nothing changed."
        ) + (
            f" {len(covered_blocks) - len(unblocked)} covered address(es) are still blocked: pass "
            f"unblock_if_blocked=true or DELETE /firewall/blocked/{{ip}}."
            if covered_blocks and len(unblocked) < len(covered_blocks) and category != store.SHARED_EGRESS
            else ""
        ),
    }


def remove(category: str, value: str) -> dict:
    """Remove a runtime entry. Raises EnvPinned / NotListed / SafelistError."""
    if category not in CATEGORIES:
        raise SafelistError(f"unknown category {category!r}; use one of {', '.join(CATEGORIES)}")
    try:
        canonical, _ = store.normalize(value)
    except SafelistError:
        # An env-only oddity ("localhost") cannot be normalized but may be pinned.
        if value.strip() in _env_canonicals(category):
            raise EnvPinned(category, value.strip())
        raise
    in_env = canonical in _env_canonicals(category)
    removed = store.remove(category, canonical)
    if not removed:
        if in_env:
            raise EnvPinned(category, canonical)
        raise NotListed(canonical)
    logger.warning(f"SAFELIST: {category} -= {canonical}")
    still = effective_protection(canonical)
    return {
        "category": category, "value": canonical, "removed": True,
        "still_in_env": in_env,
        "still_protected_by": still,
        "message": (
            "Removed from the runtime safelist."
            + (f" It is still pinned by {ENV_VARS[category]} in the environment." if in_env else "")
            + (f" Note: the address is still treated as protected ({still})." if still else "")
        ),
    }


def effective_protection(value: str) -> Optional[str]:
    """Why `value` (an IP or CIDR's first host) is still protected, or None."""
    try:
        probe = value.split("/")[0]
        ipaddress.ip_address(probe)
    except ValueError:
        return None
    reason = protection_reason(probe)
    return reason[0] if reason else None


def protection_reason(ip: str) -> Optional[tuple[str, str]]:
    """(code, human message) when `ip` must not be blocked by an operator, else None.

    Order matters for the message, not the verdict: an address the operator
    listed as his own is reported as "internal" even if it also sits in a
    private range.
    """
    if store.matches(store.INTERNAL, ip) or _env_covers(store.INTERNAL, ip):
        return ("internal", f"{ip} is on your internal safelist ({ENV_VARS[store.INTERNAL]} / runtime): "
                            f"it is one of your own addresses.")
    if store.matches(store.SAFE, ip) or _env_covers(store.SAFE, ip):
        return ("safelisted", f"{ip} is safelisted ({ENV_VARS[store.SAFE]} / runtime).")
    if _ad._is_safe_ip(ip):
        return ("protected_range", f"{ip} is in a built-in protected range (loopback, private, Tailscale, "
                                   f"this host, or a verified crawler/CDN network).")
    if _ad.is_shared_egress(ip):
        return ("shared_egress", f"{ip} is shared consumer egress (WARP / Private Relay / "
                                 f"{ENV_VARS[store.SHARED_EGRESS]}): many real users share it, so blocking it "
                                 f"would lock out innocent people. Use the response approval flow if you "
                                 f"are sure.")
    return None


def _env_covers(category: str, ip: str) -> bool:
    literals, nets = _env_raw(category)
    if ip in literals:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)
