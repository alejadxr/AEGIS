import json
import logging

from app.core.openrouter import openrouter_client
from app.services.ai_engine import MITRE_MAPPINGS

logger = logging.getLogger("aegis.analyzer")


class ThreatAnalyzer:
    """AI-powered threat analysis with MITRE ATT&CK mapping."""

    async def analyze(self, alert_data: dict) -> dict:
        """Perform deep analysis on an alert or incident."""
        messages = [
            {
                "role": "user",
                "content": (
                    f"Perform a thorough security analysis of this alert:\n"
                    f"{json.dumps(alert_data, default=str)}\n\n"
                    f"Include MITRE ATT&CK mapping, attack vector analysis, "
                    f"and recommended response actions."
                ),
            }
        ]
        response = await openrouter_client.query(messages, "investigation")
        content = response.get("content", "{}")

        try:
            cleaned = content.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                lines = [l for l in lines if not l.strip().startswith("```")]
                cleaned = "\n".join(lines)
            analysis = json.loads(cleaned)
        except (json.JSONDecodeError, ValueError):
            analysis = {
                "findings": content,
                "kill_chain_stage": "unknown",
                "iocs": [],
                "recommendations": [],
            }

        # Enrich with MITRE mapping
        threat_type = alert_data.get("threat_type") or self._detect_threat_type(alert_data)
        mitre = MITRE_MAPPINGS.get(threat_type, {})
        analysis["mitre_technique"] = mitre.get("technique", analysis.get("mitre_technique", ""))
        analysis["mitre_tactic"] = mitre.get("tactic", analysis.get("mitre_tactic", ""))
        analysis["model_used"] = response.get("model_used", "")

        return analysis

    async def correlate_events(self, events: list[dict]) -> dict:
        """Correlate multiple events to identify attack patterns."""
        messages = [
            {
                "role": "user",
                "content": (
                    f"Correlate these security events and identify attack patterns:\n"
                    f"{json.dumps(events, default=str)}\n\n"
                    f"Look for: multi-stage attacks, lateral movement, "
                    f"coordinated activity, or false positive patterns."
                ),
            }
        ]
        response = await openrouter_client.query(messages, "investigation")
        content = response.get("content", "{}")

        try:
            cleaned = content.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                lines = [l for l in lines if not l.strip().startswith("```")]
                cleaned = "\n".join(lines)
            return json.loads(cleaned)
        except (json.JSONDecodeError, ValueError):
            return {"correlation": content, "patterns": []}

    def _detect_threat_type(self, data: dict) -> str:
        """Heuristic threat type detection from alert data."""
        text = json.dumps(data).lower()
        keywords = {
            "brute_force": ["brute", "login fail", "authentication fail", "invalid password"],
            "port_scan": ["port scan", "syn scan", "nmap", "masscan"],
            "sql_injection": ["sql", "sqli", "union select", "' or '1'='1"],
            "xss": ["xss", "script>", "alert(", "onerror"],
            "rce": ["command injection", "rce", "remote code", "exec("],
            "phishing": ["phish", "credential harvest", "fake login"],
            "malware": ["malware", "trojan", "ransomware", "backdoor"],
            "c2_communication": ["c2", "beacon", "command and control", "callback"],
            "credential_dumping": ["credential dump", "mimikatz", "lsass", "hashdump"],
            "web_shell": ["webshell", "web shell", "cmd.php", "shell.php"],
        }
        for threat_type, kws in keywords.items():
            if any(kw in text for kw in kws):
                return threat_type
        return "unknown"


threat_analyzer = ThreatAnalyzer()
