import logging
from typing import Optional

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
        "name": "Ransomware Containment and Recovery",
        "description": "Critical ransomware containment — isolate, kill chain, protect snapshots, block C2, notify, postmortem",
        "steps": [
            {"action": "isolate_host", "description": "Immediately isolate infected hosts from all network segments except AEGIS management VLAN"},
            {"action": "kill_chain_processes", "description": "Terminate malicious processes matching ransomware LOLBin patterns"},
            {"action": "deny_shadow_delete", "description": "Block vssadmin.exe, wbadmin.exe, bcdedit.exe from further shadow-copy modifications"},
            {"action": "trigger_snapshot", "description": "Create emergency volume snapshot before further encryption completes"},
            {"action": "block_c2_ips", "description": "Push C2 IPs into iptables/pfctl block list and blocked_ips.txt persistence file"},
            {"action": "notify_admin", "description": "Send CRITICAL alert to all configured admin channels with incident context"},
            {"action": "write_postmortem", "description": "Generate structured postmortem stub requiring human review before incident closure"},
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


THREAT_TO_PLAYBOOK: dict[str, str] = {
    "brute_force": "brute_force",
    "credential_stuffing": "brute_force",
    "password_spray": "brute_force",
    "malware": "malware",
    "ransomware": "ransomware",
    "data_exfiltration": "data_exfiltration",
    "exfiltration": "data_exfiltration",
    "lateral_movement": "lateral_movement",
    "web_shell": "web_shell",
    "rce": "web_shell",
    "command_injection": "web_shell",
    "sql_injection": "brute_force",
    "xss": "brute_force",
    "port_scan": "brute_force",
    "scanner": "brute_force",
    "c2_beacon": "malware",
    "c2_communication": "malware",
    "phishing": "data_exfiltration",
    "credential_dumping": "lateral_movement",
    # Ransomware chain rule triggers
    "ransomware_chain": "ransomware",
    "ransomware_canary_modified": "ransomware",
    "ransomware_extension_mass_change": "ransomware",
    "ransomware_vss_delete": "ransomware",
}


class PlaybookEngine:
    """Playbook selection and management."""

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
        """Select the best playbook for an alert using a static threat-type map."""
        threat_type = (
            alert_data.get("threat_type")
            or alert_data.get("classification")
            or "unknown"
        )
        playbook_id = THREAT_TO_PLAYBOOK.get(threat_type, "brute_force")
        playbook = self.get_playbook(playbook_id) or PLAYBOOK_TEMPLATES["brute_force"]
        return {
            "playbook": playbook,
            "confidence": 0.85,
            "reasoning": f"Static mapping: {threat_type} → {playbook_id}",
        }


playbook_engine = PlaybookEngine()
