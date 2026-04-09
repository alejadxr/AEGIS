"""
Post-block IP investigation service.

After AEGIS auto-blocks an IP, this service runs an AI-powered investigation
to verify the block is legitimate. If the AI determines with high confidence
that it's a false positive, the IP is auto-unblocked.

Flow: block first (safety) -> investigate (2-5s AI call) -> unblock if false positive
"""

import ipaddress
import json
import logging
import time
from datetime import datetime
from typing import Optional

from sqlalchemy import select

logger = logging.getLogger("cayde6.ip_investigator")


class IPInvestigator:
    """Investigates auto-blocked IPs for false positives."""

    # Private/internal ranges that suggest false positive
    _PRIVATE_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("100.64.0.0/10"),   # CGNAT / Tailscale
        ipaddress.ip_network("127.0.0.0/8"),
    ]

    # Reasons that indicate a real attack (never unblock these)
    _HARD_BLOCK_REASONS = frozenset({
        "breadcrumb_credential_used",
        "command_injection",
        "sql_injection",
        "ssrf",
        "path_traversal",
    })

    # Confidence threshold for auto-unblock
    UNBLOCK_CONFIDENCE_THRESHOLD = 0.8

    async def investigate_blocked_ip(
        self,
        ip: str,
        reason: str,
        client_id: Optional[str] = None,
    ) -> dict:
        """Run post-block investigation on an IP.

        This runs AFTER the block (fire-and-forget), so the system is
        safe first, and we investigate second.

        Returns investigation result dict.
        """
        t0 = time.time()
        logger.info(f"[IPInvestigator] Starting investigation for blocked IP {ip} (reason: {reason})")

        try:
            evidence = self._gather_evidence(ip, reason)

            # Short-circuit: if reason is a hard attack type, skip AI call
            reason_base = reason.split("(")[0].strip() if "(" in reason else reason
            if any(hard in reason_base for hard in self._HARD_BLOCK_REASONS):
                result = {
                    "ip": ip,
                    "verdict": "malicious",
                    "confidence": 0.95,
                    "reasoning": f"Block reason '{reason}' matches known attack pattern. No further investigation needed.",
                    "action_taken": "block_confirmed",
                    "duration_s": round(time.time() - t0, 2),
                }
                await self._log_investigation(ip, reason, evidence, result, client_id)
                logger.info(f"[IPInvestigator] {ip} confirmed malicious (hard block reason: {reason})")
                return result

            # Ask AI to analyze the evidence
            ai_verdict = await self._query_ai(ip, reason, evidence)

            # Determine action based on AI verdict
            action_taken = "block_confirmed"
            if (
                ai_verdict.get("verdict") == "legitimate"
                and ai_verdict.get("confidence", 0) > self.UNBLOCK_CONFIDENCE_THRESHOLD
            ):
                # False positive detected — auto-unblock
                await self._unblock_ip(ip)
                action_taken = "auto_unblocked"
                logger.warning(
                    f"[IPInvestigator] FALSE POSITIVE: auto-unblocked {ip} "
                    f"(confidence: {ai_verdict.get('confidence', 0):.2f}, "
                    f"reason: {ai_verdict.get('reasoning', 'N/A')})"
                )
            else:
                logger.info(
                    f"[IPInvestigator] Block confirmed for {ip} "
                    f"(verdict: {ai_verdict.get('verdict')}, "
                    f"confidence: {ai_verdict.get('confidence', 0):.2f})"
                )

            result = {
                "ip": ip,
                "verdict": ai_verdict.get("verdict", "suspicious"),
                "confidence": ai_verdict.get("confidence", 0.5),
                "reasoning": ai_verdict.get("reasoning", "No reasoning provided"),
                "action_taken": action_taken,
                "evidence": evidence,
                "duration_s": round(time.time() - t0, 2),
            }

            await self._log_investigation(ip, reason, evidence, result, client_id)
            return result

        except Exception as e:
            logger.error(f"[IPInvestigator] Investigation failed for {ip}: {e}")
            # On error, keep the block (fail-safe)
            return {
                "ip": ip,
                "verdict": "error",
                "confidence": 0,
                "reasoning": f"Investigation failed: {e}",
                "action_taken": "block_kept_on_error",
                "duration_s": round(time.time() - t0, 2),
            }

    def _gather_evidence(self, ip: str, reason: str) -> dict:
        """Gather evidence about the blocked IP for AI analysis."""
        evidence = {
            "ip": ip,
            "block_reason": reason,
            "is_private_range": self._is_private_ip(ip),
            "is_tailscale": self._is_tailscale_ip(ip),
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Check attack log for request history
        try:
            from app.core.attack_detector import _attack_log
            ip_attacks = _attack_log.get(ip, [])
            evidence["attack_count"] = len(ip_attacks)
            if ip_attacks:
                evidence["attack_types"] = list(set(
                    entry[1] for entry in ip_attacks
                ))
        except Exception:
            evidence["attack_count"] = 0

        return evidence

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in a private/internal range."""
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._PRIVATE_NETWORKS)
        except (ValueError, TypeError):
            return False

    def _is_tailscale_ip(self, ip: str) -> bool:
        """Check if IP is in the Tailscale CGNAT range (100.64.0.0/10)."""
        try:
            addr = ipaddress.ip_address(ip)
            return addr in ipaddress.ip_network("100.64.0.0/10")
        except (ValueError, TypeError):
            return False

    async def _query_ai(self, ip: str, reason: str, evidence: dict) -> dict:
        """Query AI to analyze the blocked IP evidence."""
        try:
            from app.core.openrouter import openrouter_client

            prompt = (
                "You are a cybersecurity analyst reviewing an auto-blocked IP address. "
                "Analyze the evidence and determine if this is a legitimate block or a false positive.\n\n"
                f"Evidence:\n{json.dumps(evidence, indent=2, default=str)}\n\n"
                "Key considerations:\n"
                "- Private/Tailscale IPs (10.x, 172.16-31.x, 192.168.x, 100.64-127.x) are internal/VPN users\n"
                "- Scanner detection alone may be a security researcher or monitoring tool\n"
                "- High request rate without attack payloads may be a dashboard or API consumer\n"
                "- Breadcrumb credential usage is ALWAYS malicious (honeypot trap)\n"
                "- SQL injection, XSS, command injection payloads are ALWAYS malicious\n\n"
                "Respond with ONLY valid JSON:\n"
                '{"verdict": "legitimate"|"malicious"|"suspicious", '
                '"confidence": 0.0-1.0, '
                '"reasoning": "brief explanation"}'
            )

            response = await openrouter_client.query(
                messages=[{"role": "user", "content": prompt}],
                task_type="investigation",
            )

            content = response.get("content", "{}")
            return self._parse_ai_response(content)

        except Exception as e:
            logger.error(f"[IPInvestigator] AI query failed: {e}")
            # Default to suspicious on AI failure (keep block)
            return {
                "verdict": "suspicious",
                "confidence": 0.5,
                "reasoning": f"AI analysis unavailable: {e}",
            }

    def _parse_ai_response(self, content: str) -> dict:
        """Parse AI response, extracting JSON verdict."""
        defaults = {
            "verdict": "suspicious",
            "confidence": 0.5,
            "reasoning": "Could not parse AI response",
        }
        try:
            # Try to find JSON in the response
            start = content.find("{")
            end = content.rfind("}") + 1
            if start >= 0 and end > start:
                parsed = json.loads(content[start:end])
                # Validate verdict
                if parsed.get("verdict") not in ("legitimate", "malicious", "suspicious"):
                    parsed["verdict"] = "suspicious"
                # Clamp confidence
                conf = float(parsed.get("confidence", 0.5))
                parsed["confidence"] = max(0.0, min(1.0, conf))
                return {**defaults, **parsed}
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
        return defaults

    async def _unblock_ip(self, ip: str):
        """Unblock an IP that was identified as a false positive."""
        # Remove from attack_detector in-memory set + file
        try:
            from app.core.attack_detector import unblock_ip as detector_unblock
            detector_unblock(ip)
        except Exception as e:
            logger.error(f"[IPInvestigator] Failed to unblock {ip} from detector: {e}")

        # Also unblock from ip_blocker_service
        try:
            from app.core.ip_blocker import ip_blocker_service
            ip_blocker_service.unblock_ip(ip)
        except Exception as e:
            logger.error(f"[IPInvestigator] Failed to unblock {ip} from ip_blocker: {e}")

        # Notify external firewall to unblock
        try:
            import os
            import aiohttp
            firewall_url = os.getenv("AEGIS_FIREWALL_URL", "")
            if firewall_url:
                async with aiohttp.ClientSession() as session:
                    await session.post(
                        f"{firewall_url}/unblock",
                        json={"ip": ip, "reason": "aegis_false_positive_auto_unblock"},
                        timeout=aiohttp.ClientTimeout(total=3),
                    )
                    logger.info(f"[IPInvestigator] Firewall notified to unblock {ip}")
        except Exception as e:
            logger.debug(f"[IPInvestigator] Firewall unblock failed (non-fatal): {e}")

    async def _log_investigation(
        self,
        ip: str,
        reason: str,
        evidence: dict,
        result: dict,
        client_id: Optional[str] = None,
    ):
        """Log the investigation result to the audit_log and update the incident."""
        try:
            from app.database import async_session
            from app.core.audit import log_audit
            from app.models.incident import Incident
            from app.models.client import Client

            async with async_session() as db:
                # Get client_id if not provided
                if not client_id:
                    stmt = select(Client).limit(1)
                    row = await db.execute(stmt)
                    client = row.scalar_one_or_none()
                    client_id = client.id if client else "system"

                # Write audit log
                await log_audit(
                    db=db,
                    action="ip_investigation",
                    details=(
                        f"IP {ip} investigated after auto-block. "
                        f"Verdict: {result.get('verdict')} "
                        f"(confidence: {result.get('confidence', 0):.2f}). "
                        f"Action: {result.get('action_taken')}. "
                        f"Reason: {result.get('reasoning', 'N/A')}"
                    ),
                    client_id=client_id,
                )

                # Update the incident if it exists
                stmt = (
                    select(Incident)
                    .where(Incident.source_ip == ip, Incident.source == "attack_detector")
                    .order_by(Incident.detected_at.desc())
                    .limit(1)
                )
                row = await db.execute(stmt)
                incident = row.scalar_one_or_none()

                if incident:
                    analysis = incident.ai_analysis or {}
                    analysis["investigation"] = {
                        "verdict": result.get("verdict"),
                        "confidence": result.get("confidence"),
                        "reasoning": result.get("reasoning"),
                        "action_taken": result.get("action_taken"),
                        "evidence": evidence,
                        "investigated_at": datetime.utcnow().isoformat(),
                    }
                    incident.ai_analysis = analysis

                    if result.get("action_taken") == "auto_unblocked":
                        incident.status = "resolved"
                        incident.resolved_at = datetime.utcnow()
                        incident.description = (
                            (incident.description or "")
                            + f"\n\n[AUTO-RESOLVED] False positive detected. "
                            f"AI verdict: {result.get('verdict')} "
                            f"(confidence: {result.get('confidence', 0):.2f}). "
                            f"IP auto-unblocked."
                        )

                await db.commit()
                logger.info(f"[IPInvestigator] Investigation logged for {ip}")

        except Exception as e:
            logger.error(f"[IPInvestigator] Failed to log investigation: {e}")


# Module-level singleton
ip_investigator = IPInvestigator()
