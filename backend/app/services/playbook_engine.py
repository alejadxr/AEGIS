"""
Deterministic playbook engine for AEGIS.

Playbooks provide instant, rule-based response to known attack patterns
WITHOUT requiring AI inference. Target: <50ms per playbook evaluation.

Flow:
  1. Event arrives with sigma_matches and IOC check results
  2. PlaybookEngine.evaluate() checks all playbooks
  3. Matching playbooks execute their action sequences
  4. Results published to event bus
"""

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger("aegis.playbook_engine")

# ---------------------------------------------------------------------------
# Playbook definitions
# ---------------------------------------------------------------------------

PLAYBOOKS: list[dict] = [
    # 1 - Auto-block SSH brute force
    {
        "id": "auto_block_brute_force",
        "name": "Auto-block brute force",
        "description": "Immediately block IPs performing SSH/RDP brute force attacks",
        "trigger": {"sigma_rule": "brute_force_ssh", "min_severity": "high"},
        "conditions": [
            {"type": "ip_reputation", "operator": "in_blocklist"},
        ],
        "actions": [
            {"type": "block_ip", "via": "firewall"},
            {"type": "block_ip", "via": "local"},
            {"type": "notify", "channel": "webhook", "template": "brute_force_blocked"},
            {"type": "create_incident", "severity": "high"},
            {"type": "increase_scan_freq", "duration_minutes": 120},
        ],
    },
    # 2 - Auto-block SQL injection chain
    {
        "id": "auto_block_sql_injection",
        "name": "Auto-block SQL injection chain",
        "description": "Block IPs performing repeated SQL injection attempts",
        "trigger": {"sigma_rule": "sql_injection_chain"},
        "conditions": [],
        "actions": [
            {"type": "block_ip", "via": "firewall"},
            {"type": "block_ip", "via": "local"},
            {"type": "notify", "channel": "webhook"},
            {"type": "create_incident", "severity": "critical"},
            {"type": "forensic_snapshot"},
        ],
    },
    # 3 - Auto-block credential stuffing
    {
        "id": "auto_block_credential_stuffing",
        "name": "Auto-block credential stuffing",
        "description": "Block IPs performing credential stuffing attacks",
        "trigger": {"sigma_rule": "credential_stuffing", "min_severity": "high"},
        "conditions": [],
        "actions": [
            {"type": "block_ip", "via": "firewall"},
            {"type": "block_ip", "via": "local"},
            {"type": "notify", "channel": "webhook", "template": "credential_stuffing_blocked"},
            {"type": "create_incident", "severity": "high"},
        ],
    },
    # 4 - Auto-block RDP brute force
    {
        "id": "auto_block_rdp_brute_force",
        "name": "Auto-block RDP brute force",
        "description": "Block IPs performing RDP brute force attacks",
        "trigger": {"sigma_rule": "rdp_brute_force", "min_severity": "high"},
        "conditions": [],
        "actions": [
            {"type": "block_ip", "via": "firewall"},
            {"type": "block_ip", "via": "local"},
            {"type": "notify", "channel": "webhook"},
            {"type": "create_incident", "severity": "high"},
        ],
    },
    # 5 - Auto-respond to C2 beacon
    {
        "id": "auto_respond_c2_beacon",
        "name": "Auto-respond to C2 beacon",
        "description": "Block and isolate hosts showing C2 beacon patterns",
        "trigger": {"sigma_rule": "c2_beacon", "min_severity": "critical"},
        "conditions": [],
        "actions": [
            {"type": "block_ip", "via": "firewall"},
            {"type": "block_ip", "via": "local"},
            {"type": "notify", "channel": "webhook", "template": "c2_beacon_detected"},
            {"type": "create_incident", "severity": "critical"},
            {"type": "forensic_snapshot"},
            {"type": "increase_scan_freq", "duration_minutes": 240},
        ],
    },
    # 6 - Auto-block web shell activity
    {
        "id": "auto_block_web_shell",
        "name": "Auto-block web shell activity",
        "description": "Block IPs showing web shell usage patterns",
        "trigger": {"sigma_rule": "web_shell_activity", "min_severity": "critical"},
        "conditions": [],
        "actions": [
            {"type": "block_ip", "via": "firewall"},
            {"type": "block_ip", "via": "local"},
            {"type": "notify", "channel": "webhook"},
            {"type": "create_incident", "severity": "critical"},
            {"type": "forensic_snapshot"},
        ],
    },
    # 7 - Auto-block port scan + known bad IP
    {
        "id": "auto_block_port_scan_bad_ip",
        "name": "Auto-block port scan from malicious IP",
        "description": "Block known-bad IPs performing port scans",
        "trigger": {"sigma_rule": "port_scan", "min_severity": "medium"},
        "conditions": [
            {"type": "ip_reputation", "operator": "in_blocklist"},
        ],
        "actions": [
            {"type": "block_ip", "via": "firewall"},
            {"type": "block_ip", "via": "local"},
            {"type": "notify", "channel": "webhook"},
            {"type": "create_incident", "severity": "high"},
        ],
    },
    # 8 - Auto-respond to data exfiltration
    {
        "id": "auto_respond_data_exfil",
        "name": "Auto-respond to data exfiltration",
        "description": "Block and alert on suspected data exfiltration",
        "trigger": {"sigma_rule": "data_exfiltration", "min_severity": "critical"},
        "conditions": [],
        "actions": [
            {"type": "block_ip", "via": "firewall"},
            {"type": "block_ip", "via": "local"},
            {"type": "notify", "channel": "webhook", "template": "data_exfil_detected"},
            {"type": "create_incident", "severity": "critical"},
            {"type": "forensic_snapshot"},
            {"type": "increase_scan_freq", "duration_minutes": 360},
        ],
    },
    # 9 - Auto-block DNS tunneling
    {
        "id": "auto_block_dns_tunneling",
        "name": "Auto-block DNS tunneling",
        "description": "Block IPs performing DNS tunneling",
        "trigger": {"sigma_rule": "dns_tunneling", "min_severity": "high"},
        "conditions": [],
        "actions": [
            {"type": "block_ip", "via": "firewall"},
            {"type": "block_ip", "via": "local"},
            {"type": "notify", "channel": "webhook"},
            {"type": "create_incident", "severity": "high"},
        ],
    },
    # 10 - Auto-respond to privilege escalation
    {
        "id": "auto_respond_priv_esc",
        "name": "Auto-respond to privilege escalation",
        "description": "Immediately respond to privilege escalation attempts",
        "trigger": {"sigma_rule": "privilege_escalation", "min_severity": "critical"},
        "conditions": [],
        "actions": [
            {"type": "block_ip", "via": "firewall"},
            {"type": "block_ip", "via": "local"},
            {"type": "notify", "channel": "webhook", "template": "priv_esc_detected"},
            {"type": "create_incident", "severity": "critical"},
            {"type": "forensic_snapshot"},
        ],
    },
]

# Severity ordering for comparison
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# ---------------------------------------------------------------------------
# Auto-block confirmation gate  (BUG: false-positive auto-block on lone
# medium auth-failure incidents, e.g. 38.52.220.20 blocked on 2 medium
# `auth_failure` events 5 days apart against GET /api/v1/auth/me)
# ---------------------------------------------------------------------------
#
# block_ip must only AUTO-execute when the threat is a CONFIRMED real attack.
# A lone / low-count MEDIUM auth-failure or brute-force incident must NOT
# auto-block — it still creates an incident for visibility, but the block is
# withheld pending operator approval (via the normal guardrail flow).
#
# A block is considered CONFIRMED when ANY of the following holds:
#   1. A known-bad IOC hit  — the source IP is on a malicious threat feed.
#   2. A non-auth exploit / high-signal sigma rule matched (SQLi, RCE, XSS,
#      web shell, privilege escalation, C2, data exfil, DNS tunnel, port
#      scan, honeypot). These are inherently confirmed on a single match —
#      no legitimate traffic produces them.
#   3. A REPEATED, high-confidence brute force: the matched auth/brute-force
#      rule fired at HIGH+ severity AND its correlation count_threshold meets
#      the real-attack floor (>= MIN_BRUTE_FORCE_COUNT). A lone MEDIUM auth
#      failure (session-check 401, credential typo) never meets this bar.

# Sigma rule IDs whose SINGLE match is, by itself, a confirmed attack.
# These are non-auth exploit / high-signal detections — no benign traffic
# produces them, so one match is sufficient to auto-block.
CONFIRMED_EXPLOIT_RULES = frozenset({
    "sql_injection_chain",
    "xss_attack_chain",
    "web_shell_activity",
    "privilege_escalation",
    "c2_beacon",
    "data_exfiltration",
    "dns_tunneling",
    "rce",
    "rce_attempt",
    "port_scan",
    "ssh_honeypot_attempt",       # honeypot: any hit is malicious by definition
    "ssh_honeypot_failure",
})

# Sigma rule IDs / event types that are auth/brute-force in nature. A match
# here is only "confirmed" when it is HIGH+ severity AND meets the repeated
# count floor below. A lone MEDIUM auth failure must NOT auto-block.
AUTH_BRUTE_FORCE_RULES = frozenset({
    "http_auth_brute_force",
    "generic_credential_attack",
    "brute_force_ssh",
    "brute_force",
    "credential_stuffing",
    "rdp_brute_force",
    "auth_failure",
})

# Minimum repeated-attempt count for a brute-force detection to be treated as
# a confirmed attack eligible for auto-block. A rule whose correlation
# count_threshold is below this floor (or unknown) does not qualify on its own.
MIN_BRUTE_FORCE_COUNT = 5

# Minimum severity for a brute-force detection to be eligible for auto-block.
MIN_BRUTE_FORCE_SEVERITY = "high"


def _rule_id(match: dict) -> str:
    return match.get("id", match.get("rule_id", "")) or ""


def _rule_severity(match: dict) -> str:
    return match.get("severity", "low") or "low"


def _rule_count_threshold(match: dict) -> int:
    """Correlation count_threshold declared by a sigma rule dict.

    For rules that fired via the correlation engine the rule dict carries a
    `condition.count_threshold`. When the threshold is met the rule fires, so
    a threshold >= MIN_BRUTE_FORCE_COUNT means the attack was repeated at
    least that many times within the rule window.
    """
    cond = match.get("condition")
    if isinstance(cond, dict):
        try:
            return int(cond.get("count_threshold", 0) or 0)
        except (TypeError, ValueError):
            return 0
    # Some callers flatten the threshold onto the match itself.
    try:
        return int(match.get("count_threshold", 0) or 0)
    except (TypeError, ValueError):
        return 0


def is_confirmed_attack(
    sigma_matches: Optional[list[dict]],
    ioc_check: Optional[dict] = None,
) -> tuple[bool, str]:
    """Decide whether an auto-block is justified.

    Returns (confirmed, reason). `confirmed=True` means the threat is a real,
    repeated attack (or exploit / known-bad IOC) and block_ip may auto-execute.
    `confirmed=False` means the signal is too weak (e.g. a lone medium
    auth-failure) and the block must be withheld for operator approval.
    """
    sigma_matches = sigma_matches or []

    # 1. Known-bad IOC hit — always auto-block regardless of sigma detail.
    if ioc_check and ioc_check.get("verdict") == "malicious":
        return True, "known_bad_ioc"

    # 2. Non-auth exploit / high-signal sigma rule matched.
    for m in sigma_matches:
        rid = _rule_id(m)
        if rid in CONFIRMED_EXPLOIT_RULES:
            return True, f"confirmed_exploit:{rid}"

    # 3. Repeated, high-confidence brute force.
    min_sev_rank = SEVERITY_ORDER.get(MIN_BRUTE_FORCE_SEVERITY, 3)
    for m in sigma_matches:
        rid = _rule_id(m)
        if rid not in AUTH_BRUTE_FORCE_RULES:
            continue
        sev_rank = SEVERITY_ORDER.get(_rule_severity(m), 0)
        count = _rule_count_threshold(m)
        if sev_rank >= min_sev_rank and count >= MIN_BRUTE_FORCE_COUNT:
            return True, f"confirmed_brute_force:{rid}(sev>={MIN_BRUTE_FORCE_SEVERITY},count>={count})"

    # 4. Any remaining HIGH+/CRITICAL sigma match that is not an auth rule is
    #    treated as confirmed (e.g. bespoke critical rules). Medium/low
    #    non-exploit auth signals fall through to "not confirmed".
    for m in sigma_matches:
        rid = _rule_id(m)
        if rid in AUTH_BRUTE_FORCE_RULES:
            continue
        if SEVERITY_ORDER.get(_rule_severity(m), 0) >= SEVERITY_ORDER["high"]:
            return True, f"confirmed_high_severity:{rid}"

    return False, "unconfirmed_low_signal"


# ---------------------------------------------------------------------------
# PlaybookEngine
# ---------------------------------------------------------------------------

class PlaybookEngine:
    """
    Deterministic playbook executor. No AI involved.

    Methods:
      - evaluate(event, sigma_matches, ioc_check) -> list of playbook results
      - execute_playbook(playbook, event) -> execution result
    """

    def __init__(self):
        self._playbooks: list[dict] = list(PLAYBOOKS)
        self._event_bus = None
        self._stats = {
            "evaluations": 0,
            "playbooks_triggered": 0,
            "actions_executed": 0,
            "avg_eval_time_ms": 0.0,
            "total_eval_time_ms": 0.0,
        }

    def register_event_bus(self, bus):
        self._event_bus = bus

    def evaluate(
        self,
        event: dict,
        sigma_matches: list[dict],
        ioc_check: Optional[dict] = None,
    ) -> list[dict]:
        """
        Evaluate all playbooks against the event + sigma matches + IOC check.
        Returns list of matching playbooks. Target: <50ms.
        """
        start = time.monotonic_ns()
        self._stats["evaluations"] += 1

        matched_rule_ids = {m.get("id", m.get("rule_id", "")) for m in sigma_matches}
        results = []

        for playbook in self._playbooks:
            trigger = playbook.get("trigger", {})

            # Check if the triggering sigma rule matches
            trigger_rule = trigger.get("sigma_rule", "")
            if trigger_rule and trigger_rule not in matched_rule_ids:
                continue

            # Check minimum severity
            min_sev = trigger.get("min_severity")
            if min_sev:
                # Check against the highest severity among matched rules
                max_rule_sev = 0
                for m in sigma_matches:
                    if m.get("id", m.get("rule_id", "")) == trigger_rule:
                        max_rule_sev = max(
                            max_rule_sev,
                            SEVERITY_ORDER.get(m.get("severity", "low"), 0),
                        )
                if max_rule_sev < SEVERITY_ORDER.get(min_sev, 0):
                    continue

            # Check conditions
            conditions_met = True
            for condition in playbook.get("conditions", []):
                if condition["type"] == "ip_reputation":
                    if condition.get("operator") == "in_blocklist":
                        if not ioc_check or ioc_check.get("verdict") not in ("malicious", "suspicious"):
                            conditions_met = False
                            break
                    elif condition.get("operator") == "not_in_blocklist":
                        if ioc_check and ioc_check.get("verdict") in ("malicious", "suspicious"):
                            conditions_met = False
                            break

            if conditions_met:
                # Attach the auto-block confirmation verdict so execute_playbook
                # can withhold block_ip on weak signals (lone medium auth
                # failures) without dropping the incident/notify actions.
                confirmed, reason = is_confirmed_attack(sigma_matches, ioc_check)
                pb = dict(playbook)
                pb["_block_confirmed"] = confirmed
                pb["_block_confirmation_reason"] = reason
                results.append(pb)
                self._stats["playbooks_triggered"] += 1

        elapsed_ms = (time.monotonic_ns() - start) / 1_000_000
        self._stats["total_eval_time_ms"] += elapsed_ms
        if self._stats["evaluations"] > 0:
            self._stats["avg_eval_time_ms"] = (
                self._stats["total_eval_time_ms"] / self._stats["evaluations"]
            )

        return results

    async def execute_playbook(self, playbook: dict, event: dict) -> dict:
        """
        Execute all actions in a playbook. Returns execution result.
        Target: <50ms for non-network actions.
        """
        execution_id = str(uuid.uuid4())
        source_ip = event.get("source_ip", "")
        results = []
        start = time.monotonic_ns()

        # Auto-block confirmation gate. evaluate() stamps _block_confirmed on
        # the playbook. If it is missing (playbook executed directly without
        # going through evaluate()), default to WITHHOLD so we fail safe —
        # block_ip never auto-fires on an unverified path.
        block_confirmed = playbook.get("_block_confirmed", False)
        block_reason = playbook.get("_block_confirmation_reason", "no_confirmation_context")

        for action in playbook.get("actions", []):
            action_type = action["type"]
            result = {"action": action_type, "status": "pending"}

            try:
                if action_type == "block_ip" and source_ip:
                    if not block_confirmed:
                        # Not a confirmed real attack (e.g. lone medium
                        # auth-failure). Withhold the auto-block; the incident
                        # + notify actions still run for visibility, and an
                        # operator can approve the block via the guardrail flow.
                        logger.warning(
                            "GUARDRAIL (playbook): withholding auto-block_ip on "
                            f"{source_ip} — attack NOT confirmed "
                            f"(reason={block_reason}, playbook={playbook.get('id')}). "
                            "Requires operator approval."
                        )
                        result = {
                            "action": "block_ip",
                            "via": action.get("via", "local"),
                            "status": "withheld_requires_approval",
                            "ip": source_ip,
                            "reason": block_reason,
                        }
                        self._stats["actions_executed"] += 1
                        results.append(result)
                        continue
                    via = action.get("via", "local")
                    if via == "firewall":
                        result = await self._block_via_firewall(source_ip)
                    else:
                        result = self._block_via_local(source_ip)

                elif action_type == "notify":
                    result = await self._notify(action, event, playbook)

                elif action_type == "create_incident":
                    result = {
                        "action": "create_incident",
                        "status": "delegated",
                        "severity": action.get("severity", "high"),
                        "note": "Incident creation delegated to fast_triage flow",
                    }

                elif action_type == "forensic_snapshot":
                    result = {
                        "action": "forensic_snapshot",
                        "status": "queued",
                        "timestamp": datetime.utcnow().isoformat(),
                        "source_ip": source_ip,
                    }

                elif action_type == "increase_scan_freq":
                    result = {
                        "action": "increase_scan_freq",
                        "status": "applied",
                        "duration_minutes": action.get("duration_minutes", 60),
                    }

                else:
                    result = {"action": action_type, "status": "unknown_action"}

                self._stats["actions_executed"] += 1

            except Exception as e:
                result = {"action": action_type, "status": "error", "error": str(e)}
                logger.error(f"Playbook action '{action_type}' failed: {e}")

            results.append(result)

        elapsed_ms = (time.monotonic_ns() - start) / 1_000_000

        block_withheld = any(
            r.get("action") == "block_ip"
            and r.get("status") == "withheld_requires_approval"
            for r in results
        )

        execution_result = {
            "execution_id": execution_id,
            "playbook_id": playbook["id"],
            "playbook_name": playbook["name"],
            "source_ip": source_ip,
            "actions": results,
            "block_confirmed": block_confirmed,
            "block_confirmation_reason": block_reason,
            "block_withheld": block_withheld,
            "elapsed_ms": round(elapsed_ms, 2),
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Publish to event bus
        if self._event_bus:
            await self._event_bus.publish("playbook_executed", execution_result)

        logger.info(
            f"Playbook '{playbook['id']}' executed in {elapsed_ms:.1f}ms | "
            f"actions={len(results)} | source_ip={source_ip}"
        )

        return execution_result

    async def _block_via_firewall(self, ip: str) -> dict:
        """Block IP via Firewall (Pi firewall). Fire-and-forget."""
        # BUG-4 fix: enforce the same safe-IP CIDR check that
        # guardrails.evaluate_action() applies. Playbooks bypass the normal
        # guardrails flow (no client/db context), so we apply the safe-IP
        # short-circuit directly here.
        try:
            from app.core.attack_detector import _is_safe_ip as _safe_ip_check
            if _safe_ip_check(ip):
                logger.warning(
                    f"GUARDRAIL (playbook): Refusing block_ip via firewall on "
                    f"safe IP {ip} (AEGIS_SAFE_IPS)"
                )
                return {
                    "action": "block_ip",
                    "via": "firewall",
                    "status": "skipped_safe_ip",
                    "ip": ip,
                }
        except Exception:
            pass
        try:
            from app.core.firewall_client import firewall_client
            result = await firewall_client.block_ip(ip)
            return {
                "action": "block_ip",
                "via": "firewall",
                "status": "success" if result.get("success") else "failed",
                "ip": ip,
            }
        except Exception as e:
            logger.error(f"Firewall block failed for {ip}: {e}")
            return {"action": "block_ip", "via": "firewall", "status": "error", "error": str(e)}

    def _block_via_local(self, ip: str) -> dict:
        """Block IP via local IP blocker."""
        # BUG-4 fix: enforce safe-IP CIDR guardrail before local block too.
        try:
            from app.core.attack_detector import _is_safe_ip as _safe_ip_check
            if _safe_ip_check(ip):
                logger.warning(
                    f"GUARDRAIL (playbook): Refusing local block_ip on "
                    f"safe IP {ip} (AEGIS_SAFE_IPS)"
                )
                return {
                    "action": "block_ip",
                    "via": "local",
                    "status": "skipped_safe_ip",
                    "ip": ip,
                }
        except Exception:
            pass
        try:
            from app.core.ip_blocker import ip_blocker_service
            result = ip_blocker_service.block_ip(ip)
            return {
                "action": "block_ip",
                "via": "local",
                "status": "success",
                "ip": ip,
                "already_blocked": result.get("already_blocked", False),
            }
        except Exception as e:
            logger.error(f"Local block failed for {ip}: {e}")
            return {"action": "block_ip", "via": "local", "status": "error", "error": str(e)}

    async def _notify(self, action: dict, event: dict, playbook: dict) -> dict:
        """Send notification via configured channel."""
        try:
            from app.services.notifier import notifier
            from app.config import settings

            webhook_url = settings.WEBHOOK_URL
            if not webhook_url:
                return {"action": "notify", "status": "skipped", "reason": "no webhook configured"}

            payload = {
                "platform": "AEGIS",
                "event_type": "playbook_auto_response",
                "playbook": playbook["name"],
                "source_ip": event.get("source_ip"),
                "severity": event.get("severity", "high"),
                "template": action.get("template", "generic_playbook"),
                "timestamp": datetime.utcnow().isoformat(),
            }
            success = await notifier.send_webhook(webhook_url, payload)
            return {
                "action": "notify",
                "channel": action.get("channel", "webhook"),
                "status": "sent" if success else "failed",
            }
        except Exception as e:
            return {"action": "notify", "status": "error", "error": str(e)}

    def list_playbooks(self) -> list[dict]:
        return list(self._playbooks)

    def stats(self) -> dict:
        return {
            **self._stats,
            "playbook_count": len(self._playbooks),
        }


# Singleton
playbook_engine = PlaybookEngine()
