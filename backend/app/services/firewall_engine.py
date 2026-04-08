"""
Configurable Firewall Rule Engine.

Loads tenant-scoped rules from the DB, compiles their YAML DSL into
Python filter functions, and evaluates them against runtime events.

Compiled rules are cached per (client_id, rule_id, yaml_hash) so updates
hot-reload in <1s without restarting the process. Designed to run INSIDE
the attack_detector hot path — target <100 microseconds for 50 rules.

YAML Rule DSL
-------------
```yaml
name: Block SSH brute force
enabled: true
priority: 100
match:
  - port: 22
  - protocol: tcp
  - rate_limit: { count: 5, window_seconds: 60 }
action: block_ip
duration_seconds: 3600
```

Match conditions (all must match — AND semantics):
  - source_ip: "10.0.0.0/8"   (CIDR or single IP)
  - source_ip_in: ["1.2.3.4", "5.6.7.8/24"]   (list)
  - port: 22                   (int or list)
  - protocol: "tcp"            (tcp|udp|http|any)
  - path_contains: "/admin"
  - method: "POST"
  - user_agent: "nmap"         (substring, case-insensitive)
  - user_agent_regex: "sqlmap|nikto"
  - country: "CN"              (placeholder — GeoIP not yet wired)
  - rate_limit: { count: N, window_seconds: W }   (stateful per source_ip)

Actions:
  - block_ip        (block the source IP, optionally for `duration_seconds`)
  - allow           (explicit allow, short-circuits evaluation)
  - alert           (fire-and-forget log + incident entry)
  - quarantine_host (mark host for isolation)
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session
from app.models.firewall_rule import FirewallRule

logger = logging.getLogger("cayde6.firewall_engine")


# ---------------------------------------------------------------------------
# Rule compilation
# ---------------------------------------------------------------------------

@dataclass
class CompiledRule:
    """A rule that has been parsed from YAML and turned into a match function."""

    rule_id: str
    client_id: str
    name: str
    priority: int
    enabled: bool
    yaml_hash: str
    matcher: Callable[[dict], bool]
    action: str
    action_params: dict
    raw_def: dict = field(default_factory=dict)


@dataclass
class RuleMatch:
    """Result of an engine evaluation."""

    rule_id: str
    rule_name: str
    action: str
    action_params: dict
    priority: int


# Per-source-ip rate limit window state: (client_id, rule_id, source_ip) -> deque[float]
_rate_windows: dict[tuple[str, str, str], deque] = defaultdict(deque)


def _hash_yaml(yaml_text: str) -> str:
    return hashlib.sha1(yaml_text.encode("utf-8")).hexdigest()


def _cidr_matcher(cidr: str) -> Callable[[str], bool]:
    """Build a matcher for a single CIDR or IP string."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        # Fall back to exact string compare if not valid CIDR
        return lambda ip: ip == cidr

    def _check(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in network
        except ValueError:
            return False

    return _check


def _compile_match_conditions(match_list: list[dict] | dict) -> Callable[[dict], bool]:
    """
    Turn a list of match clauses into a single Python closure that evaluates
    an event dict and returns True if all clauses match.

    `match_list` can be either a list of single-key dicts (preferred for YAML
    readability) or a single flat dict.
    """
    # Normalize to a flat dict of {condition: value}
    flat: dict[str, Any] = {}
    if isinstance(match_list, dict):
        flat.update(match_list)
    else:
        for item in match_list or []:
            if isinstance(item, dict):
                flat.update(item)

    # Pre-compile each condition once
    checks: list[Callable[[dict], bool]] = []

    if "source_ip" in flat:
        cidr_check = _cidr_matcher(str(flat["source_ip"]))
        checks.append(lambda e, c=cidr_check: c(str(e.get("source_ip", ""))))

    if "source_ip_in" in flat:
        cidrs = [str(x) for x in flat["source_ip_in"] or []]
        matchers = [_cidr_matcher(c) for c in cidrs]
        checks.append(
            lambda e, ms=matchers: any(m(str(e.get("source_ip", ""))) for m in ms)
        )

    if "port" in flat:
        port_val = flat["port"]
        if isinstance(port_val, list):
            port_set = {int(p) for p in port_val}
            checks.append(lambda e, ps=port_set: int(e.get("port", -1)) in ps)
        else:
            try:
                port_int = int(port_val)
                checks.append(lambda e, p=port_int: int(e.get("port", -1)) == p)
            except (TypeError, ValueError):
                pass

    if "protocol" in flat:
        proto = str(flat["protocol"]).lower()
        if proto != "any":
            checks.append(lambda e, p=proto: str(e.get("protocol", "")).lower() == p)

    if "path_contains" in flat:
        needle = str(flat["path_contains"])
        checks.append(lambda e, n=needle: n in str(e.get("path", "")))

    if "method" in flat:
        method = str(flat["method"]).upper()
        checks.append(lambda e, m=method: str(e.get("method", "")).upper() == m)

    if "user_agent" in flat:
        needle = str(flat["user_agent"]).lower()
        checks.append(lambda e, n=needle: n in str(e.get("user_agent", "")).lower())

    if "user_agent_regex" in flat:
        try:
            pattern = re.compile(str(flat["user_agent_regex"]), re.IGNORECASE)
            checks.append(
                lambda e, p=pattern: bool(p.search(str(e.get("user_agent", ""))))
            )
        except re.error as exc:
            logger.warning(f"Invalid user_agent_regex: {exc}")

    if "country" in flat:
        # Placeholder — GeoIP lookup not yet wired. Expects e['country'] if upstream provides it.
        country = str(flat["country"]).upper()
        checks.append(lambda e, c=country: str(e.get("country", "")).upper() == c)

    if "event_type" in flat:
        et = str(flat["event_type"])
        checks.append(lambda e, t=et: str(e.get("event_type", "")) == t)

    # rate_limit is stateful — handled with a factory that captures rule metadata
    rate_limit_cfg: Optional[dict] = flat.get("rate_limit") if isinstance(flat.get("rate_limit"), dict) else None

    def combined(event: dict) -> bool:
        for fn in checks:
            if not fn(event):
                return False
        return True

    combined._rate_limit_cfg = rate_limit_cfg  # type: ignore[attr-defined]
    return combined


def _rate_limit_hit(
    client_id: str, rule_id: str, source_ip: str, count: int, window_seconds: float
) -> bool:
    """Stateful rate limiter. Returns True if source_ip exceeded `count` in `window_seconds`."""
    if not source_ip:
        return False
    key = (client_id, rule_id, source_ip)
    now = time.time()
    cutoff = now - window_seconds
    q = _rate_windows[key]
    while q and q[0] < cutoff:
        q.popleft()
    q.append(now)
    return len(q) >= count


def compile_rule(rule: FirewallRule) -> Optional[CompiledRule]:
    """Compile a DB row into an executable CompiledRule. Returns None on parse errors."""
    try:
        parsed = yaml.safe_load(rule.yaml_def) or {}
    except yaml.YAMLError as exc:
        logger.warning(f"Failed to parse YAML for rule {rule.id}: {exc}")
        return None

    if not isinstance(parsed, dict):
        logger.warning(f"Rule {rule.id} YAML must be a mapping, got {type(parsed).__name__}")
        return None

    match = parsed.get("match", [])
    matcher = _compile_match_conditions(match)

    action = str(parsed.get("action", "alert")).lower()
    action_params = {
        k: v for k, v in parsed.items() if k not in ("name", "enabled", "priority", "match", "action")
    }

    return CompiledRule(
        rule_id=rule.id,
        client_id=rule.client_id,
        name=rule.name,
        priority=rule.priority,
        enabled=rule.enabled,
        yaml_hash=_hash_yaml(rule.yaml_def),
        matcher=matcher,
        action=action,
        action_params=action_params,
        raw_def=parsed,
    )


# ---------------------------------------------------------------------------
# Engine — memoized, thread-safe enough for asyncio single-loop usage
# ---------------------------------------------------------------------------

class FirewallEngine:
    """Per-process rule cache + evaluator."""

    def __init__(self) -> None:
        # client_id -> list of CompiledRule (sorted by priority desc)
        self._cache: dict[str, list[CompiledRule]] = {}
        # (client_id, rule_id) -> yaml_hash, for change detection
        self._hashes: dict[tuple[str, str], str] = {}
        self._loaded_at: dict[str, float] = {}
        self._reload_ttl = 2.0  # seconds — hot-reload interval
        # Stats
        self._eval_count = 0
        self._match_count = 0

    async def _fetch_rules(self, client_id: str, db: AsyncSession) -> list[FirewallRule]:
        result = await db.execute(
            select(FirewallRule).where(FirewallRule.client_id == client_id)
        )
        return list(result.scalars().all())

    async def load_rules(self, client_id: str, force: bool = False) -> list[CompiledRule]:
        """Load and compile rules for a tenant, memoized with short TTL."""
        now = time.time()
        last = self._loaded_at.get(client_id, 0)
        if not force and (now - last) < self._reload_ttl and client_id in self._cache:
            return self._cache[client_id]

        async with async_session() as db:
            rows = await self._fetch_rules(client_id, db)

        compiled: list[CompiledRule] = []
        for row in rows:
            if not row.enabled:
                continue
            key = (client_id, row.id)
            cached_hash = self._hashes.get(key)
            new_hash = _hash_yaml(row.yaml_def)
            if cached_hash == new_hash:
                # Reuse previously-compiled rule from cache if present
                existing = next(
                    (r for r in self._cache.get(client_id, []) if r.rule_id == row.id),
                    None,
                )
                if existing is not None:
                    existing.enabled = row.enabled
                    existing.priority = row.priority
                    compiled.append(existing)
                    continue
            cr = compile_rule(row)
            if cr is not None:
                compiled.append(cr)
                self._hashes[key] = new_hash

        compiled.sort(key=lambda r: r.priority, reverse=True)
        self._cache[client_id] = compiled
        self._loaded_at[client_id] = now
        return compiled

    def invalidate(self, client_id: Optional[str] = None) -> None:
        """Drop cached rules. If client_id is None, clears everything."""
        if client_id is None:
            self._cache.clear()
            self._hashes.clear()
            self._loaded_at.clear()
        else:
            self._cache.pop(client_id, None)
            self._loaded_at.pop(client_id, None)
            self._hashes = {k: v for k, v in self._hashes.items() if k[0] != client_id}

    async def evaluate(self, event: dict, client_id: str) -> list[RuleMatch]:
        """
        Evaluate an event against all enabled rules for a tenant.

        Returns matched rules sorted by priority (higher first). An `allow`
        action short-circuits the list (nothing after it is returned).
        """
        rules = await self.load_rules(client_id)
        return self._evaluate_compiled(event, rules, client_id)

    def evaluate_sync(self, event: dict, client_id: str) -> list[RuleMatch]:
        """Sync variant — uses whatever is in cache, does NOT touch the DB.

        Safe to call from the attack_detector hot path. If the cache is cold,
        returns []; an async caller (or background warmer) should prime it first.
        """
        rules = self._cache.get(client_id) or []
        return self._evaluate_compiled(event, rules, client_id)

    def evaluate_all_sync(self, event: dict) -> list[RuleMatch]:
        """Sync evaluation across ALL cached tenants.

        The attack_detector middleware doesn't know which tenant a request
        belongs to, so it evaluates against every tenant's rules. Returns
        the highest-priority match across all tenants.
        """
        if not self._cache:
            return []
        all_matches: list[RuleMatch] = []
        for client_id, rules in self._cache.items():
            matches = self._evaluate_compiled(event, rules, client_id)
            all_matches.extend(matches)
        all_matches.sort(key=lambda m: m.priority, reverse=True)
        return all_matches

    def _evaluate_compiled(
        self, event: dict, rules: list[CompiledRule], client_id: str
    ) -> list[RuleMatch]:
        self._eval_count += 1
        matches: list[RuleMatch] = []
        for rule in rules:
            if not rule.enabled:
                continue
            if not rule.matcher(event):
                continue

            # Stateful rate_limit check happens only after structural match
            rl_cfg = getattr(rule.matcher, "_rate_limit_cfg", None)
            if rl_cfg:
                try:
                    count = int(rl_cfg.get("count", 1))
                    window = float(rl_cfg.get("window_seconds", 60))
                except (TypeError, ValueError):
                    continue
                if not _rate_limit_hit(
                    client_id, rule.rule_id, str(event.get("source_ip", "")), count, window
                ):
                    continue

            self._match_count += 1
            matches.append(
                RuleMatch(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    action=rule.action,
                    action_params=dict(rule.action_params),
                    priority=rule.priority,
                )
            )
            if rule.action == "allow":
                # Explicit allow short-circuits everything below
                break
        return matches

    async def test_rule(self, yaml_def: str, event: dict, client_id: str = "__test__") -> dict:
        """Compile a rule from raw YAML and test it against a synthetic event.

        Does NOT touch the DB. Used by the /firewall/rules/{id}/test endpoint.
        """
        try:
            parsed = yaml.safe_load(yaml_def) or {}
        except yaml.YAMLError as exc:
            return {"ok": False, "error": f"YAML parse error: {exc}", "matched": False}

        if not isinstance(parsed, dict):
            return {"ok": False, "error": "Rule must be a YAML mapping", "matched": False}

        matcher = _compile_match_conditions(parsed.get("match", []))

        structural = matcher(event)
        matched = structural
        rate_info: dict[str, Any] | None = None

        rl_cfg = getattr(matcher, "_rate_limit_cfg", None)
        if structural and rl_cfg:
            try:
                count = int(rl_cfg.get("count", 1))
                window = float(rl_cfg.get("window_seconds", 60))
                rate_info = {"count": count, "window_seconds": window}
                matched = _rate_limit_hit(
                    client_id, "__test__", str(event.get("source_ip", "")), count, window
                )
            except (TypeError, ValueError):
                matched = False

        return {
            "ok": True,
            "matched": matched,
            "structural_match": structural,
            "rate_limit": rate_info,
            "action": str(parsed.get("action", "alert")).lower() if matched else None,
            "rule_name": parsed.get("name", "unnamed"),
        }

    def stats(self) -> dict:
        return {
            "eval_count": self._eval_count,
            "match_count": self._match_count,
            "tenants_cached": len(self._cache),
            "total_rules_cached": sum(len(rs) for rs in self._cache.values()),
        }


# ---------------------------------------------------------------------------
# Default templates shipped with the product
# ---------------------------------------------------------------------------

DEFAULT_TEMPLATES: list[dict] = [
    {
        "id": "block_ssh_brute_force",
        "name": "Block SSH brute force",
        "description": "Auto-block IPs that attempt more than 5 SSH connections in 60 seconds.",
        "yaml_def": """name: Block SSH brute force
enabled: true
priority: 100
match:
  - port: 22
  - protocol: tcp
  - rate_limit: { count: 5, window_seconds: 60 }
action: block_ip
duration_seconds: 3600
""",
    },
    {
        "id": "block_port_scan",
        "name": "Block port scan",
        "description": "Rate-limit raw TCP connections — trips when a single IP hits many ports in one minute.",
        "yaml_def": """name: Block port scan
enabled: true
priority: 95
match:
  - protocol: tcp
  - rate_limit: { count: 10, window_seconds: 60 }
action: block_ip
duration_seconds: 1800
""",
    },
    {
        "id": "allow_office_ips",
        "name": "Allow only specific IPs",
        "description": "Whitelist mode — explicitly allow traffic from trusted office / VPN ranges.",
        "yaml_def": """name: Allow office network
enabled: true
priority: 200
match:
  - source_ip_in:
      - 10.0.0.0/8
      - 192.168.0.0/16
action: allow
""",
    },
    {
        "id": "block_scanner_user_agents",
        "name": "Block scanner User-Agents",
        "description": "Match nmap, sqlmap, nikto, masscan and similar security scanners in the UA header.",
        "yaml_def": """name: Block scanner User-Agents
enabled: true
priority: 90
match:
  - user_agent_regex: "(nmap|sqlmap|nikto|masscan|gobuster|dirbuster|wfuzz|nuclei)"
action: block_ip
duration_seconds: 86400
""",
    },
    {
        "id": "auto_quarantine_malware",
        "name": "Auto-quarantine on malware hit",
        "description": "When the antivirus engine flags a host, trigger network isolation via quarantine_host.",
        "yaml_def": """name: Auto-quarantine on malware hit
enabled: true
priority: 150
match:
  - event_type: antivirus_detection
action: quarantine_host
""",
    },
    {
        "id": "geo_block_country",
        "name": "Geo-block country (placeholder)",
        "description": "Block traffic from a specific country code — requires GeoIP lookup upstream.",
        "yaml_def": """name: Geo-block CN
enabled: false
priority: 80
match:
  - country: CN
action: block_ip
duration_seconds: 86400
""",
    },
]


# Module-level singleton — imported by attack_detector, api/firewall, main.py
firewall_engine = FirewallEngine()
