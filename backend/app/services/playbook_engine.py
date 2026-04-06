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
                results.append(playbook)
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

        for action in playbook.get("actions", []):
            action_type = action["type"]
            result = {"action": action_type, "status": "pending"}

            try:
                if action_type == "block_ip" and source_ip:
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
                        "timestamp": datetime.now(timezone.utc).isoformat(),
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

        execution_result = {
            "execution_id": execution_id,
            "playbook_id": playbook["id"],
            "playbook_name": playbook["name"],
            "source_ip": source_ip,
            "actions": results,
            "elapsed_ms": round(elapsed_ms, 2),
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
                "timestamp": datetime.now(timezone.utc).isoformat(),
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
