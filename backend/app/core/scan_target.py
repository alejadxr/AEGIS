"""Validation of scan targets before they reach a scanner's argv.

No shell is involved, but a scanner still parses its own arguments: a target
of ``-oN=/path`` or ``--script=/path`` is an option to nmap, not a host. A
target must therefore be an IP address, a CIDR network or a DNS hostname, and
nothing else.
"""

from __future__ import annotations

import ipaddress
import re

_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*\.?$")
MAX_TARGET_LENGTH = 253


def validate_scan_target(value) -> str:
    """Return the canonical target, or raise ``ValueError``."""
    if not isinstance(value, str):
        raise ValueError("scan target must be a string")
    target = value.strip()
    if not target or len(target) > MAX_TARGET_LENGTH:
        raise ValueError("scan target is empty or too long")
    if target.startswith("-"):
        raise ValueError("scan target must be an IP address, CIDR range or hostname")
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    if "/" in target:
        try:
            return str(ipaddress.ip_network(target, strict=False))
        except ValueError:
            raise ValueError("scan target is not a valid CIDR range") from None
    if _HOSTNAME_RE.match(target) and not target.replace(".", "").isdigit():
        return target.rstrip(".").lower()
    raise ValueError("scan target must be an IP address, CIDR range or hostname")


def is_valid_scan_target(value) -> bool:
    try:
        validate_scan_target(value)
        return True
    except ValueError:
        return False
