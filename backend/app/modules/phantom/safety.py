"""
phantom/safety.py — IP-level guard for phantom profile creation.

Prevents attacker profiles from being created for safe, documentation,
or non-routable IP addresses that will never be real attackers.
"""
import ipaddress
import logging

from app.core.attack_detector import _is_safe_ip

logger = logging.getLogger("aegis.phantom.profiler")

# RFC 5737 documentation ranges — NEVER appear in real traffic.
_DOC_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
]

# Additional non-routable / defensive ranges
_EXTRA_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local
]

_ALL_SKIP_NETWORKS = _DOC_NETWORKS + _EXTRA_NETWORKS


def should_skip_profile(ip: str) -> bool:
    """Return True if creating an attacker profile for *ip* should be skipped.

    Skips:
    - IPs that pass _is_safe_ip (RFC1918, CGNAT/Tailscale, AEGIS_SAFE_IPS env)
    - RFC 5737 documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24)
    - Loopback (127.0.0.0/8) and link-local (169.254.0.0/16)
    """
    if _is_safe_ip(ip):
        logger.info(f"phantom: skipped profile for safe/doc IP {ip}")
        return True
    try:
        addr = ipaddress.ip_address(ip)
        if any(addr in net for net in _ALL_SKIP_NETWORKS):
            logger.info(f"phantom: skipped profile for safe/doc IP {ip}")
            return True
    except (ValueError, TypeError):
        pass
    return False
