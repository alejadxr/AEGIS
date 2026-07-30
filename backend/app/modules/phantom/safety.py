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


def is_synthetic_ip(ip: str) -> bool:
    """True only for addresses that CANNOT be a real attacker.

    Documentation ranges (RFC 5737), loopback and link-local. These carry no
    forensic value, so a honeypot hit from one is safe to discard outright.

    Deliberately does NOT consult _is_safe_ip. A honeypot is a service nobody
    has a legitimate reason to touch: Googlebot does not SSH into port 2222.
    A connection from a "safe" crawler/CDN range is therefore MORE interesting,
    not less — it means a compromised crawler host, a spoofed source, or an
    attacker sitting in a cloud range. See should_skip_profile.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return any(addr in net for net in _ALL_SKIP_NETWORKS)


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
