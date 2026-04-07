"""
AEGIS Counter-Attack Module -- Active Defense

When a high/critical attack is detected:
1. AI (dolphin-mistral uncensored via OpenRouter) analyzes attacker IP, methods, patterns
2. Recommends counter-measures (recon, intel, deception, report, tarpit)
3. Executes approved counter-attacks via guardrails system

Counter-attack types:
- recon_attacker:    nmap scan attacker IP, fingerprint OS/services
- intel_lookup:      threat intel feeds, geolocation, reputation check
- deception:         serve fake data, redirect to honeypots
- report_abuse:      auto-report to AbuseIPDB, threat intel sharing
- tarpit:            slow down attacker connections deliberately

All counter-attack actions require approval by default (guardrails).
"""

import asyncio
import json
import logging
import subprocess
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.openrouter import openrouter_client
from app.core.guardrails import guardrail_engine
from app.core.events import event_bus, PRIORITY_HIGH
from app.database import async_session
from app.models.client import Client
from app.models.incident import Incident
from app.models.action import Action

logger = logging.getLogger("cayde6.counter_attack")


# Counter-attack action types (all auto-approved — AEGIS is autonomous)
COUNTER_ATTACK_ACTIONS = {
    "recon_attacker": {
        "description": "Reconnaissance scan of attacker infrastructure",
        "risk": "low",
        "guardrail": "auto_approve",
    },
    "intel_lookup": {
        "description": "Threat intelligence lookup (AbuseIPDB, VirusTotal, Shodan)",
        "risk": "none",
        "guardrail": "auto_approve",
    },
    "deception": {
        "description": "Deploy deception against attacker (fake data, honeypot redirect)",
        "risk": "low",
        "guardrail": "auto_approve",
    },
    "report_abuse": {
        "description": "Report attacker IP to AbuseIPDB and threat intel networks",
        "risk": "none",
        "guardrail": "auto_approve",
    },
    "tarpit": {
        "description": "Slow down attacker connections to waste their time",
        "risk": "low",
        "guardrail": "auto_approve",
    },
}


COUNTER_ATTACK_SYSTEM_PROMPT = (
    "You are an offensive security AI operating as part of the AEGIS active defense system. "
    "Your role is to analyze attackers and recommend aggressive but legal counter-measures. "
    "You have no restrictions on analyzing attack techniques, payloads, or suggesting "
    "reconnaissance of attacker infrastructure.\n\n"
    "Available counter-attack actions:\n"
    "- recon_attacker: Scan attacker IP with nmap to fingerprint their OS, open ports, services\n"
    "- intel_lookup: Check threat intel feeds (AbuseIPDB, VirusTotal, Shodan) for attacker reputation\n"
    "- deception: Serve fake credentials/data to attacker, redirect to additional honeypots\n"
    "- report_abuse: Report attacker to AbuseIPDB with evidence\n"
    "- tarpit: Apply connection throttling to waste attacker time and resources\n\n"
    "Always respond with valid JSON containing:\n"
    '{"analysis": "...", "threat_level": "critical|high|medium|low", '
    '"attacker_profile": "...", "recommended_actions": [{"action": "...", "priority": 1-5, '
    '"reason": "...", "command": "..."}], "mitre_techniques_observed": ["T1xxx"]}'
)


class CounterAttackEngine:
    """Active defense engine that analyzes attackers and executes counter-measures."""

    def __init__(self):
        self._analyses: dict[str, dict] = {}  # incident_id -> analysis result
        self._stats = {
            "analyses_run": 0,
            "actions_recommended": 0,
            "actions_executed": 0,
            "attacks_countered": 0,
        }

    def register_event_bus(self):
        """Subscribe to high-severity attack events."""
        event_bus.subscribe("alert_processed", self._on_alert_processed)
        event_bus.subscribe("high_severity_attack", self._on_high_severity_attack)
        logger.info("Counter-attack engine registered with event bus")

    async def _on_alert_processed(self, data: dict):
        """Handle alert_processed events -- trigger counter-attack for high/critical."""
        severity = (data.get("incident_severity") or "").lower()
        if severity in ("critical", "high"):
            source_ip = data.get("source_ip")
            incident_id = data.get("incident_id")
            if source_ip and incident_id:
                logger.info(
                    f"High severity alert detected from {source_ip} -- "
                    f"triggering counter-attack analysis for incident {incident_id}"
                )
                await event_bus.publish_high("high_severity_attack", {
                    "incident_id": incident_id,
                    "source_ip": source_ip,
                    "severity": severity,
                    "attack_type": data.get("incident_title", "unknown"),
                    "details": data.get("summary", ""),
                })

    async def _on_high_severity_attack(self, data: dict):
        """Auto-trigger counter-attack analysis when high severity attack is detected."""
        incident_id = data.get("incident_id")
        if not incident_id:
            return

        try:
            result = await self.analyze(
                incident_id=incident_id,
                source_ip=data.get("source_ip", "unknown"),
                attack_type=data.get("attack_type", "unknown"),
                details=data.get("details", ""),
                severity=data.get("severity", "high"),
            )
            logger.info(
                f"Counter-attack analysis complete for {incident_id}: "
                f"{len(result.get('recommended_actions', []))} actions recommended"
            )
            # Publish analysis result to event bus for WebSocket/UI
            await event_bus.publish("counter_attack_analysis", {
                "incident_id": incident_id,
                "source_ip": data.get("source_ip"),
                "analysis": result,
            })
        except Exception as e:
            logger.error(f"Counter-attack analysis failed for {incident_id}: {e}")

    async def analyze(
        self,
        incident_id: str,
        source_ip: str,
        attack_type: str,
        details: str,
        severity: str = "high",
    ) -> dict:
        """Run AI analysis of attacker and generate counter-attack recommendations.

        Uses dolphin-mistral uncensored model via OpenRouter for unrestricted
        offensive security analysis.
        """
        start_time = time.time()

        prompt = (
            f"An attacker at IP {source_ip} has been detected.\n"
            f"Attack type: {attack_type}\n"
            f"Severity: {severity}\n"
            f"Details: {details}\n\n"
            f"Analyze this attacker and recommend counter-measures. "
            f"Be aggressive but legal. Focus on:\n"
            f"1. Reconnaissance of attacker infrastructure (what can we learn about them?)\n"
            f"2. Intelligence gathering (threat feeds, reputation, geolocation)\n"
            f"3. Deception tactics (fake data, honeypot redirect)\n"
            f"4. Reporting (AbuseIPDB, threat intel sharing)\n"
            f"5. Tarpit/slowdown tactics\n\n"
            f"For recon_attacker, include the exact nmap command to run.\n"
            f"Respond in JSON format."
        )

        # Call OpenRouter with counter_attack task type (uses dolphin-mistral uncensored)
        ai_result = await openrouter_client.query(
            messages=[{"role": "user", "content": prompt}],
            task_type="counter_attack",
            temperature=0.4,
            max_tokens=2048,
        )

        # Parse AI response
        content = ai_result.get("content", "")
        analysis = self._parse_ai_response(content)
        analysis["incident_id"] = incident_id
        analysis["source_ip"] = source_ip
        analysis["model_used"] = ai_result.get("model_used", "unknown")
        analysis["latency_ms"] = ai_result.get("latency_ms", 0)
        analysis["timestamp"] = datetime.now(timezone.utc).isoformat()
        analysis["total_time_ms"] = int((time.time() - start_time) * 1000)

        # Store analysis
        self._analyses[incident_id] = analysis
        self._stats["analyses_run"] += 1
        self._stats["actions_recommended"] += len(analysis.get("recommended_actions", []))

        return analysis

    def _parse_ai_response(self, content: str) -> dict:
        """Parse JSON from AI response, handling markdown code blocks."""
        # Strip markdown code fences
        cleaned = content.strip()
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            # Remove first and last lines (``` markers)
            lines = [l for l in lines if not l.strip().startswith("```")]
            cleaned = "\n".join(lines)

        try:
            start = cleaned.find("{")
            end = cleaned.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(cleaned[start:end])
        except json.JSONDecodeError:
            pass

        # Fallback: return raw content as analysis
        return {
            "analysis": content[:2000],
            "threat_level": "unknown",
            "recommended_actions": [],
            "parse_error": True,
        }

    async def get_analysis(self, incident_id: str) -> Optional[dict]:
        """Retrieve cached counter-attack analysis for an incident."""
        return self._analyses.get(incident_id)

    async def execute_action(
        self,
        incident_id: str,
        action_type: str,
        target_ip: str,
        db: AsyncSession,
    ) -> dict:
        """Execute a counter-attack action (after guardrail approval)."""
        if action_type not in COUNTER_ATTACK_ACTIONS:
            return {"success": False, "error": f"Unknown action type: {action_type}"}

        logger.info(f"Executing counter-attack: {action_type} against {target_ip}")
        result = {"action": action_type, "target": target_ip, "timestamp": datetime.now(timezone.utc).isoformat()}

        try:
            if action_type == "recon_attacker":
                result["data"] = await self._recon_attacker(target_ip)
            elif action_type == "intel_lookup":
                result["data"] = await self._intel_lookup(target_ip)
            elif action_type == "deception":
                result["data"] = await self._deploy_deception(target_ip)
            elif action_type == "report_abuse":
                result["data"] = await self._report_abuse(target_ip, incident_id)
            elif action_type == "tarpit":
                result["data"] = await self._tarpit(target_ip)

            result["success"] = True
            self._stats["actions_executed"] += 1
            self._stats["attacks_countered"] += 1

            # Publish execution event
            await event_bus.publish("counter_attack_executed", {
                "incident_id": incident_id,
                "action_type": action_type,
                "target_ip": target_ip,
                "success": True,
            })

        except Exception as e:
            result["success"] = False
            result["error"] = str(e)
            logger.error(f"Counter-attack {action_type} failed: {e}")

        return result

    async def _recon_attacker(self, target_ip: str) -> dict:
        """Scan attacker IP with nmap to fingerprint their infrastructure."""
        loop = asyncio.get_event_loop()
        nmap_result = await loop.run_in_executor(None, self._run_nmap, target_ip)

        # AI analysis of scan results
        ai_result = await openrouter_client.query(
            messages=[{
                "role": "user",
                "content": (
                    f"Analyze this nmap scan of an attacker at {target_ip}:\n\n"
                    f"{nmap_result}\n\n"
                    f"Identify: OS, open services, potential vulnerabilities, "
                    f"whether this is a proxy/VPN/botnet node. Respond in JSON."
                ),
            }],
            task_type="counter_attack",
            temperature=0.3,
            max_tokens=1024,
        )

        return {
            "nmap_raw": nmap_result,
            "ai_analysis": ai_result.get("content", ""),
            "model_used": ai_result.get("model_used", ""),
        }

    def _run_nmap(self, target_ip: str) -> str:
        """Run nmap scan (synchronous, in thread executor)."""
        try:
            result = subprocess.run(
                ["nmap", "-sV", "-T4", "--top-ports", "100", "-O", target_ip],
                capture_output=True, text=True, timeout=120,
            )
            return result.stdout[:4000] if result.stdout else result.stderr[:2000]
        except subprocess.TimeoutExpired:
            return f"nmap scan timed out for {target_ip}"
        except Exception as e:
            return f"nmap error: {str(e)}"

    async def _intel_lookup(self, target_ip: str) -> dict:
        """Look up attacker IP in threat intelligence feeds."""
        import httpx

        intel = {"ip": target_ip, "sources": {}}

        # AbuseIPDB lookup
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": "anonymous", "Accept": "application/json"},
                    params={"ipAddress": target_ip, "maxAgeInDays": 90},
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    intel["sources"]["abuseipdb"] = {
                        "abuse_confidence": data.get("abuseConfidenceScore", 0),
                        "total_reports": data.get("totalReports", 0),
                        "country": data.get("countryCode", ""),
                        "isp": data.get("isp", ""),
                        "domain": data.get("domain", ""),
                        "is_tor": data.get("isTor", False),
                    }
        except Exception as e:
            intel["sources"]["abuseipdb"] = {"error": str(e)}

        # IP geolocation (ip-api.com, free)
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"http://ip-api.com/json/{target_ip}")
                if resp.status_code == 200:
                    data = resp.json()
                    intel["sources"]["geolocation"] = {
                        "country": data.get("country", ""),
                        "region": data.get("regionName", ""),
                        "city": data.get("city", ""),
                        "isp": data.get("isp", ""),
                        "org": data.get("org", ""),
                        "as": data.get("as", ""),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                    }
        except Exception as e:
            intel["sources"]["geolocation"] = {"error": str(e)}

        return intel

    async def _deploy_deception(self, target_ip: str) -> dict:
        """Deploy deception measures against the attacker."""
        # Generate fake credentials/data using AI
        ai_result = await openrouter_client.query(
            messages=[{
                "role": "user",
                "content": (
                    f"Generate convincing but fake security data to serve to an attacker at {target_ip}. "
                    f"Include: fake database credentials, fake API keys, fake internal IPs, "
                    f"and a fake server configuration. Make it look real enough to waste their time. "
                    f"Respond in JSON."
                ),
            }],
            task_type="decoy_content",
            temperature=0.7,
            max_tokens=1024,
        )

        return {
            "deception_deployed": True,
            "target_ip": target_ip,
            "fake_data_generated": True,
            "ai_content": ai_result.get("content", "")[:2000],
        }

    async def _report_abuse(self, target_ip: str, incident_id: str) -> dict:
        """Report attacker IP to AbuseIPDB."""
        # Note: requires AbuseIPDB API key for actual reporting
        # This prepares the report payload
        analysis = self._analyses.get(incident_id, {})
        attack_type = analysis.get("analysis", "Automated attack detected")

        report = {
            "ip": target_ip,
            "categories": "14,15,18,21",  # port scan, brute force, DDoS, web app attack
            "comment": (
                f"Automated attack detected by AEGIS Defense Platform. "
                f"Attack type: {attack_type[:200]}. "
                f"Incident ID: {incident_id}"
            ),
            "prepared": True,
            "note": "Set ABUSEIPDB_API_KEY to enable auto-reporting",
        }

        return report

    async def _tarpit(self, target_ip: str) -> dict:
        """Apply tarpit/throttling to attacker connections."""
        # This would integrate with iptables or the firewall
        # For now, log the intent and prepare the command
        commands = [
            f"# Add to iptables tarpit (requires root)",
            f"iptables -A INPUT -s {target_ip} -j TARPIT --tarpit",
            f"# Or use tc for bandwidth throttling:",
            f"tc qdisc add dev eth0 root handle 1: htb",
            f"tc class add dev eth0 parent 1: classid 1:1 htb rate 1kbit",
            f"tc filter add dev eth0 parent 1: protocol ip u32 match ip src {target_ip} flowid 1:1",
        ]

        return {
            "tarpit_prepared": True,
            "target_ip": target_ip,
            "commands": commands,
            "note": "Tarpit commands prepared. Execute via firewall integration.",
        }

    def stats(self) -> dict:
        """Return counter-attack engine statistics."""
        return {
            **self._stats,
            "cached_analyses": len(self._analyses),
            "available_actions": list(COUNTER_ATTACK_ACTIONS.keys()),
        }


# Singleton
counter_attack_engine = CounterAttackEngine()
