"""Severity-aware TTL for provisional auto-blocks.

A flat 6h TTL released IPs that had just fired critical exploit rules (e.g. a
host with six CVE-2025-34026 incidents). Expiry now depends on what the source
did and on whether it has been blocked before:

* critical severity or exploit-class (sigma_cve_*, path traversal, command
  injection, web shell, RCE) -> AEGIS_BLOCK_TTL_CRITICAL_HOURS (default 720h = 30d)
* everything else -> AEGIS_PROVISIONAL_BLOCK_TTL_HOURS (default 6h)
* repeat offenders (blocked again within REPEAT_WINDOW_DAYS) double the TTL for
  each earlier block, capped at AEGIS_BLOCK_TTL_MAX_HOURS (default 8760h = 1y).
"""
import os
import re
from datetime import datetime, timedelta
from typing import Iterable, Optional

BASE_TTL_HOURS = int(os.environ.get("AEGIS_PROVISIONAL_BLOCK_TTL_HOURS", "6"))
CRITICAL_TTL_HOURS = int(os.environ.get("AEGIS_BLOCK_TTL_CRITICAL_HOURS", str(30 * 24)))
MAX_TTL_HOURS = int(os.environ.get("AEGIS_BLOCK_TTL_MAX_HOURS", str(365 * 24)))
REPEAT_WINDOW_DAYS = 30

_EXPLOIT_RULE_MARKERS = (
    "sigma_cve_", "path_traversal", "directory_traversal",
    "command_injection", "cmd_injection", "os_command", "webshell", "web_shell",
)
# Short tokens must match whole words ("brute_force" contains "rce").
_EXPLOIT_RULE_TOKEN = re.compile(r"(?:^|[^a-z0-9])(?:rce|lfi)(?:$|[^a-z0-9])")
_EXPLOIT_THREAT_TYPES = frozenset({
    "rce", "web_shell", "webshell", "command_injection", "path_traversal",
})


def collect_rule_ids(alert_data: dict) -> list[str]:
    """Gather every rule identifier an alert carries, lowercased."""
    ids: list[str] = []
    for key in ("rule_id", "pattern", "rule"):
        v = alert_data.get(key)
        if isinstance(v, str) and v:
            ids.append(v.lower())
    for key in ("sigma_matches", "rules", "rule_ids"):
        v = alert_data.get(key)
        if isinstance(v, (list, tuple)):
            for item in v:
                if isinstance(item, dict):
                    item = item.get("id") or item.get("rule_id")
                if isinstance(item, str) and item:
                    ids.append(item.lower())
    return ids


def is_critical_or_exploit(
    severity: Optional[str], rule_ids: Iterable[str], threat_type: Optional[str] = None,
) -> bool:
    if (severity or "").lower() == "critical":
        return True
    if (threat_type or "").lower() in _EXPLOIT_THREAT_TYPES:
        return True
    for rid in rule_ids:
        rid = rid.lower()
        if _EXPLOIT_RULE_TOKEN.search(rid) or any(m in rid for m in _EXPLOIT_RULE_MARKERS):
            return True
    return False


def compute_ttl_hours(
    severity: Optional[str],
    rule_ids: Iterable[str],
    threat_type: Optional[str] = None,
    prior_blocks: int = 0,
) -> int:
    base = CRITICAL_TTL_HOURS if is_critical_or_exploit(severity, rule_ids, threat_type) else BASE_TTL_HOURS
    # Cap the exponent so a huge history can't build an enormous int first.
    ttl = base * (2 ** min(max(prior_blocks, 0), 20))
    return min(ttl, max(MAX_TTL_HOURS, base))


async def count_recent_blocks(db, ip: str, now: Optional[datetime] = None) -> int:
    """Earlier block_ip actions on this IP within the repeat window."""
    from sqlalchemy import func, select
    from app.models.action import Action

    since = (now or datetime.utcnow()) - timedelta(days=REPEAT_WINDOW_DAYS)
    result = await db.execute(
        select(func.count(Action.id)).where(
            Action.action_type == "block_ip",
            Action.target == ip,
            Action.created_at >= since,
        )
    )
    return int(result.scalar() or 0)
