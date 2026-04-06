import json
import logging
from typing import Optional

from app.core.openrouter import openrouter_client

logger = logging.getLogger("aegis.playbooks")

# Built-in playbook templates
PLAYBOOK_TEMPLATES = {
    "brute_force": {
        "name": "Brute Force Response",
        "description": "Respond to brute force / credential stuffing attacks",
        "steps": [
            {"action": "block_ip", "description": "Block the attacking IP address"},
            {"action": "disable_account", "description": "Temporarily lock targeted account"},
            {"action": "revoke_creds", "description": "Force password reset for affected account"},
            {"action": "firewall_rule", "description": "Add rate limiting for auth endpoints"},
        ],
    },
    "malware": {
        "name": "Malware Response",
        "description": "Contain and eradicate malware infection",
        "steps": [
            {"action": "isolate_host", "description": "Network isolate the infected host"},
            {"action": "kill_process", "description": "Terminate malicious processes"},
            {"action": "quarantine_file", "description": "Move malware to quarantine"},
            {"action": "block_ip", "description": "Block C2 communication IPs"},
        ],
    },
    "data_exfiltration": {
        "name": "Data Exfiltration Response",
        "description": "Stop and investigate data exfiltration",
        "steps": [
            {"action": "block_ip", "description": "Block destination IP"},
            {"action": "isolate_host", "description": "Isolate source host"},
            {"action": "network_segment", "description": "Segment affected network"},
            {"action": "revoke_creds", "description": "Revoke compromised credentials"},
        ],
    },
    "lateral_movement": {
        "name": "Lateral Movement Response",
        "description": "Contain lateral movement within the network",
        "steps": [
            {"action": "isolate_host", "description": "Isolate compromised hosts"},
            {"action": "network_segment", "description": "Segment network boundaries"},
            {"action": "revoke_creds", "description": "Reset credentials on affected systems"},
            {"action": "disable_account", "description": "Disable compromised service accounts"},
        ],
    },
    "ransomware": {
        "name": "Ransomware Response",
        "description": "Critical ransomware containment",
        "steps": [
            {"action": "isolate_host", "description": "Immediately isolate infected hosts"},
            {"action": "network_segment", "description": "Segment entire affected network"},
            {"action": "shutdown_service", "description": "Shut down file sharing services"},
            {"action": "block_ip", "description": "Block all C2 and exfiltration IPs"},
        ],
    },
    "web_shell": {
        "name": "Web Shell Response",
        "description": "Detect and remove web shells",
        "steps": [
            {"action": "quarantine_file", "description": "Remove web shell file"},
            {"action": "isolate_host", "description": "Isolate the web server"},
            {"action": "revoke_creds", "description": "Rotate all service credentials"},
            {"action": "firewall_rule", "description": "Restrict web server egress"},
        ],
    },
}


class PlaybookEngine:
    """Dynamic playbook selection and execution using AI."""

    def get_playbook(self, threat_type: str) -> Optional[dict]:
        """Get a built-in playbook by threat type."""
        return PLAYBOOK_TEMPLATES.get(threat_type)

    def list_playbooks(self) -> list[dict]:
        """List all available playbook templates."""
        return [
            {"id": k, "name": v["name"], "description": v["description"], "steps": len(v["steps"])}
            for k, v in PLAYBOOK_TEMPLATES.items()
        ]

    async def select_playbook(self, alert_data: dict) -> dict:
        """Use AI to select the best playbook for an alert."""
        available = self.list_playbooks()
        messages = [
            {
                "role": "user",
                "content": (
                    f"Given this security alert, select the most appropriate response playbook.\n"
                    f"Alert: {json.dumps(alert_data, default=str)}\n"
                    f"Available playbooks: {json.dumps(available, default=str)}\n\n"
                    f"Respond in JSON with keys: selected_playbook_id, confidence, reasoning"
                ),
            }
        ]
        response = await openrouter_client.query(messages, "quick_decision")
        content = response.get("content", "{}")

        try:
            cleaned = content.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                lines = [l for l in lines if not l.strip().startswith("```")]
                cleaned = "\n".join(lines)
            result = json.loads(cleaned)
            selected_id = result.get("selected_playbook_id", "brute_force")
            playbook = self.get_playbook(selected_id)
            return {
                "playbook": playbook or PLAYBOOK_TEMPLATES["brute_force"],
                "confidence": result.get("confidence", 0.5),
                "reasoning": result.get("reasoning", ""),
            }
        except (json.JSONDecodeError, ValueError):
            return {
                "playbook": PLAYBOOK_TEMPLATES["brute_force"],
                "confidence": 0.3,
                "reasoning": "Default playbook selected due to analysis unavailability",
            }


playbook_engine = PlaybookEngine()
