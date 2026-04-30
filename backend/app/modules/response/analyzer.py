import json
import logging
import os
from pathlib import Path

from app.core.openrouter import openrouter_client
from app.core.ai_mode import degrade_or_call
from app.services.ai_engine import MITRE_MAPPINGS

logger = logging.getLogger("aegis.analyzer")

# Load MITRE mapping from JSON file; fall back to the in-memory dict from ai_engine
_DATA_FILE = Path(__file__).parent.parent.parent / "data" / "mitre_mapping.json"
try:
    with open(_DATA_FILE) as _f:
        _MITRE_JSON: dict = json.load(_f)
except Exception:
    _MITRE_JSON = {}


def _mitre_for(threat_type: str) -> dict:
    """Return MITRE info for a threat type, checking JSON file then in-memory map."""
    return _MITRE_JSON.get(threat_type) or MITRE_MAPPINGS.get(threat_type, {})


class ThreatAnalyzer:
    """Threat analysis with MITRE ATT&CK mapping; AI-assisted when available."""

    async def analyze(self, alert_data: dict) -> dict:
        """Perform deep analysis on an alert or incident."""
        threat_type = alert_data.get("threat_type") or self._detect_threat_type(alert_data)

        async def _ai_analyze(_data: dict) -> dict:
            messages = [
                {
                    "role": "user",
                    "content": (
                        f"Perform a thorough security analysis of this alert:\n"
                        f"{json.dumps(_data, default=str)}\n\n"
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

            analysis["model_used"] = response.get("model_used", "")
            return analysis

        def _rule_based_analyze(_data: dict) -> dict:
            tt = _data.get("threat_type") or self._detect_threat_type(_data)
            mitre = _mitre_for(tt)
            return {
                "findings": f"Deterministic analysis: {tt} detected.",
                "kill_chain_stage": mitre.get("tactic", "unknown"),
                "iocs": [_data.get("source_ip")] if _data.get("source_ip") else [],
                "recommendations": self._static_recommendations(tt),
                "mitre_technique": mitre.get("technique", ""),
                "mitre_tactic": mitre.get("tactic", ""),
                "model_used": "deterministic",
            }

        analysis = await degrade_or_call(_ai_analyze, _rule_based_analyze, alert_data)

        # Ensure MITRE fields are always present
        mitre = _mitre_for(threat_type)
        analysis.setdefault("mitre_technique", mitre.get("technique", ""))
        analysis.setdefault("mitre_tactic", mitre.get("tactic", ""))

        return analysis

    async def correlate_events(self, events: list[dict]) -> dict:
        """Correlate multiple events to identify attack patterns."""

        async def _ai_correlate(_events: list) -> dict:
            messages = [
                {
                    "role": "user",
                    "content": (
                        f"Correlate these security events and identify attack patterns:\n"
                        f"{json.dumps(_events, default=str)}\n\n"
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

        def _rule_based_correlate(_events: list) -> dict:
            threat_types = [e.get("threat_type", "unknown") for e in _events]
            source_ips = list({e.get("source_ip") for e in _events if e.get("source_ip")})
            patterns = []
            if len(source_ips) == 1 and len(_events) > 3:
                patterns.append("Single-source multi-event — possible persistent attacker")
            if len(set(threat_types)) > 2:
                patterns.append("Mixed threat types — possible multi-stage attack")
            return {
                "correlation": f"Deterministic correlation of {len(_events)} events.",
                "patterns": patterns,
                "source_ips": source_ips,
                "threat_types": list(set(threat_types)),
            }

        return await degrade_or_call(_ai_correlate, _rule_based_correlate, events)

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

    def _static_recommendations(self, threat_type: str) -> list[str]:
        _recs = {
            "brute_force": ["Block source IP", "Enable account lockout policy", "Enable MFA"],
            "sql_injection": ["Block source IP", "Patch input validation", "Review WAF rules"],
            "xss": ["Block source IP", "Add Content-Security-Policy header", "Sanitize inputs"],
            "port_scan": ["Tarpit source IP", "Review firewall rules", "Enable stealth mode"],
            "command_injection": ["Block source IP immediately", "Isolate affected host", "Review exposed commands"],
            "lateral_movement": ["Isolate affected host", "Rotate credentials", "Review network segmentation"],
            "c2_beacon": ["Block C2 IP", "Isolate infected host", "Hunt for persistence"],
            "ransomware": ["Isolate host immediately", "Restore from backup", "Engage incident response"],
        }
        return _recs.get(threat_type, ["Investigate further", "Monitor for continued activity"])


threat_analyzer = ThreatAnalyzer()
