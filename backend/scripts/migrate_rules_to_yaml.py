"""
One-shot migration script: dumps BUILT_IN_RULES + CHAIN_RULES to YAML files.
Run from backend/ directory:  python scripts/migrate_rules_to_yaml.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Minimal MITRE technique → tactic mapping for the ~30 techniques used
# ---------------------------------------------------------------------------
_TECH_TO_TACTIC: dict[str, str] = {
    # CredentialAccess
    "T1110": "CredentialAccess",
    "T1110.001": "CredentialAccess",
    "T1110.003": "CredentialAccess",
    "T1110.004": "CredentialAccess",
    "T1558": "CredentialAccess",
    "T1558.001": "CredentialAccess",
    "T1558.003": "CredentialAccess",
    "T1550.002": "CredentialAccess",
    "T1556.006": "CredentialAccess",
    "T1078": "DefenseEvasion",
    "T1078.001": "DefenseEvasion",
    "T1078.003": "DefenseEvasion",
    # LateralMovement
    "T1021": "LateralMovement",
    "T1021.001": "LateralMovement",
    "T1021.002": "LateralMovement",
    "T1021.003": "LateralMovement",
    "T1021.006": "LateralMovement",
    "T1047": "LateralMovement",
    "T1569.002": "LateralMovement",
    "T1557.001": "LateralMovement",
    "T1557.002": "LateralMovement",
    "T1572": "LateralMovement",
    # Exfiltration
    "T1041": "Exfiltration",
    "T1048": "Exfiltration",
    "T1048.002": "Exfiltration",
    "T1048.003": "Exfiltration",
    "T1052.001": "Exfiltration",
    "T1567.002": "Exfiltration",
    "T1560.001": "Exfiltration",
    "T1115": "Exfiltration",
    "T1571": "Exfiltration",
    # CommandAndControl
    "T1071": "CommandAndControl",
    "T1071.001": "CommandAndControl",
    "T1071.004": "CommandAndControl",
    "T1090.003": "CommandAndControl",
    "T1090.004": "CommandAndControl",
    "T1218": "CommandAndControl",
    # InitialAccess
    "T1190": "InitialAccess",
    "T1189": "InitialAccess",
    "T1595.002": "Reconnaissance",
    "T1590.002": "Reconnaissance",
    # Execution
    "T1059": "Execution",
    "T1059.001": "Execution",
    "T1059.007": "Execution",
    # Persistence
    "T1053.003": "Persistence",
    "T1053.005": "Persistence",
    "T1543.001": "Persistence",
    "T1543.002": "Persistence",
    "T1547.001": "Persistence",
    "T1098.004": "Persistence",
    "T1505.003": "Persistence",
    "T1037.002": "Persistence",
    "T1037.004": "Persistence",
    # PrivilegeEscalation
    "T1068": "PrivilegeEscalation",
    "T1548": "PrivilegeEscalation",
    "T1548.001": "PrivilegeEscalation",
    "T1548.003": "PrivilegeEscalation",
    "T1134": "PrivilegeEscalation",
    "T1134.001": "PrivilegeEscalation",
    "T1574.001": "PrivilegeEscalation",
    "T1574.009": "PrivilegeEscalation",
    # DefenseEvasion
    "T1070": "DefenseEvasion",
    "T1070.001": "DefenseEvasion",
    "T1070.006": "DefenseEvasion",
    "T1055": "DefenseEvasion",
    "T1055.012": "DefenseEvasion",
    "T1027.001": "DefenseEvasion",
    "T1027.003": "DefenseEvasion",
    "T1014": "DefenseEvasion",
    "T1562.001": "DefenseEvasion",
    "T1562.004": "DefenseEvasion",
    # Discovery
    "T1046": "Discovery",
    "T1083": "Discovery",
    "T1135": "Discovery",
    "T1087.002": "Discovery",
    "T1087.004": "Discovery",
    # Collection
    "T1530": "Collection",
    "T1552.005": "CredentialAccess",
    "T1552.007": "CredentialAccess",
    # Impact
    "T1496": "Impact",
    # CloudContainer
    "T1609": "Execution",
    "T1610": "Defense Evasion",
    "T1611": "PrivilegeEscalation",
    # Other
    "T1046": "Discovery",
    "T1083": "Discovery",
    "T1135": "Discovery",
}


def _tactic(technique: str) -> str:
    return _TECH_TO_TACTIC.get(technique, "Unknown")


def _data_sources_for(event_type: str) -> list[str]:
    mapping = {
        "auth_failure": ["auth_log"],
        "auth_success": ["auth_log"],
        "kerberos_auth": ["auth_log"],
        "ntlm_auth": ["auth_log"],
        "mfa_failure": ["auth_log"],
        "web_request": ["pm2", "web_log"],
        "http_request": ["pm2", "web_log"],
        "sql_injection": ["pm2", "web_log"],
        "xss": ["pm2", "web_log"],
        "connection": ["network"],
        "network": ["network"],
        "dns_query": ["dns"],
        "process_creation": ["edr"],
        "service_install": ["edr"],
        "file_modification": ["edr"],
        "file_creation": ["edr"],
        "registry_modification": ["edr"],
        "dll_load": ["edr"],
        "pipe_creation": ["edr"],
        "token_manipulation": ["edr"],
        "process_injection": ["edr"],
        "kernel_module_load": ["edr"],
        "smb_access": ["network"],
        "arp_anomaly": ["network"],
        "email_sent": ["email"],
        "device_connect": ["endpoint"],
        "clipboard_access": ["edr"],
        "ldap_query": ["network", "auth_log"],
        "priv_escalation": ["pm2", "edr"],
        "container_start": ["container"],
        "container_pull": ["container"],
        "cloud_api": ["cloud"],
        "honeypot_interaction": ["honeypot"],
    }
    return mapping.get(event_type, ["pm2"])


def _category_for(rule: dict) -> str:
    cat = rule.get("category") or rule.get("source", "")
    if cat in (
        "authentication", "web_attacks", "lateral_movement", "persistence",
        "privilege_escalation", "data_exfiltration", "command_and_control",
        "defense_evasion", "discovery", "container_cloud",
    ):
        return cat
    # Infer from id prefix
    rule_id = rule["id"]
    if rule_id.startswith("sigma_auth"):
        return "authentication"
    if rule_id.startswith("sigma_web"):
        return "web_attacks"
    if rule_id.startswith("sigma_lateral"):
        return "lateral_movement"
    if rule_id.startswith("sigma_persist"):
        return "persistence"
    if rule_id.startswith("sigma_privesc"):
        return "privilege_escalation"
    if rule_id.startswith("sigma_exfil"):
        return "data_exfiltration"
    if rule_id.startswith("sigma_c2"):
        return "command_and_control"
    if rule_id.startswith("sigma_evasion"):
        return "defense_evasion"
    if rule_id.startswith("sigma_recon"):
        return "discovery"
    if rule_id.startswith("sigma_cloud"):
        return "container_cloud"
    # core rules
    if rule_id in ("brute_force_ssh", "rdp_brute_force", "credential_stuffing"):
        return "authentication"
    if rule_id in ("lateral_movement",):
        return "lateral_movement"
    if rule_id in ("data_exfiltration",):
        return "data_exfiltration"
    if rule_id in ("port_scan",):
        return "discovery"
    if rule_id in ("sql_injection_chain",):
        return "web_attacks"
    if rule_id in ("c2_beacon",):
        return "command_and_control"
    if rule_id in ("web_shell_activity",):
        return "persistence"
    if rule_id in ("privilege_escalation",):
        return "privilege_escalation"
    if rule_id in ("dns_tunneling",):
        return "command_and_control"
    if rule_id in ("xss_attack_chain",):
        return "web_attacks"
    return "misc"


def _rule_to_yaml_dict(rule: dict) -> dict:
    techniques = rule.get("mitre", [])
    tactics = list({_tactic(t) for t in techniques})
    cond = rule["condition"]
    event_type = cond.get("event_type", "unknown")

    yaml_rule: dict = {
        "id": rule["id"],
        "name": rule.get("title", rule["id"]),
        "kind": "sigma",
        "severity": rule["severity"],
        "enabled": rule.get("enabled", True),
        "tactics": tactics,
        "techniques": techniques,
        "data_sources": _data_sources_for(event_type),
        "condition": {
            "event_type": event_type,
        },
        "entityMappings": [{"type": "IP", "field": "source_ip"}],
    }

    if rule.get("description"):
        yaml_rule["description"] = rule["description"]

    # Condition fields
    if "count_threshold" in cond:
        yaml_rule["condition"]["count_threshold"] = cond["count_threshold"]
    if "time_window_seconds" in cond:
        yaml_rule["condition"]["time_window_seconds"] = cond["time_window_seconds"]
    if "group_by" in cond:
        yaml_rule["condition"]["group_by"] = cond["group_by"]
    if "unique_field" in cond:
        yaml_rule["condition"]["unique_field"] = cond["unique_field"]
    if "filter" in cond:
        yaml_rule["condition"]["filter"] = cond["filter"]

    return yaml_rule


def _chain_to_yaml_dict(chain: dict) -> dict:
    techniques = chain.get("mitre", [])
    tactics = list({_tactic(t) for t in techniques})
    steps = chain.get("chain", [])

    return {
        "id": chain["id"],
        "name": chain.get("title", chain["id"]),
        "kind": "chain",
        "severity": chain.get("severity", "critical"),
        "enabled": chain.get("enabled", True),
        "tactics": tactics,
        "techniques": techniques,
        "data_sources": ["correlation"],
        "description": chain.get("description", ""),
        "condition": {"event_type": "__chain__"},
        "sequence": [s.get("sigma_rule") or s.get("event_type", "") for s in steps],
        "max_window_seconds": chain.get("max_window_seconds", 7200),
        "group_by": chain.get("group_by", "source_ip"),
        "chain": [
            {k: v for k, v in step.items()}
            for step in steps
        ],
        "entityMappings": [{"type": "IP", "field": "source_ip"}],
    }


# ---------------------------------------------------------------------------
# All rules (exact data from correlation_engine.py)
# ---------------------------------------------------------------------------

BUILT_IN_RULES = [
    {"id": "brute_force_ssh", "title": "SSH Brute Force Detected",
     "description": "Multiple failed SSH login attempts from the same source IP.",
     "severity": "high", "enabled": True, "source": "builtin", "mitre": ["T1110.001"],
     "condition": {"event_type": "auth_failure", "count_threshold": 5, "time_window_seconds": 300, "group_by": "source_ip"}},
    {"id": "lateral_movement", "title": "Lateral Movement Detected",
     "description": "Internal host accessing multiple internal services rapidly.",
     "severity": "critical", "enabled": True, "source": "builtin", "mitre": ["T1021"],
     "condition": {"event_type": "connection", "count_threshold": 10, "time_window_seconds": 60, "group_by": "source_ip", "filter": {"target_type": "internal"}}},
    {"id": "data_exfiltration", "title": "Possible Data Exfiltration",
     "description": "Large outbound data transfer to external IP.",
     "severity": "critical", "enabled": True, "source": "builtin", "mitre": ["T1041"],
     "condition": {"event_type": "network", "filter": {"direction": "outbound", "bytes_gt": 104857600}}},
    {"id": "credential_stuffing", "title": "Credential Stuffing Attack",
     "description": "Multiple failed logins with different usernames from same IP.",
     "severity": "high", "enabled": True, "source": "builtin", "mitre": ["T1110.004"],
     "condition": {"event_type": "auth_failure", "count_threshold": 10, "time_window_seconds": 120, "group_by": "source_ip", "unique_field": "username"}},
    {"id": "port_scan", "title": "Port Scan Detected",
     "description": "Single IP probing multiple ports.",
     "severity": "medium", "enabled": True, "source": "builtin", "mitre": ["T1046"],
     "condition": {"event_type": "connection", "count_threshold": 20, "time_window_seconds": 60, "group_by": "source_ip", "unique_field": "target_port"}},
    {"id": "sql_injection_chain", "title": "SQL Injection Attack Chain",
     "description": "Multiple SQLi patterns from the same source.",
     "severity": "critical", "enabled": True, "source": "builtin", "mitre": ["T1190"],
     "condition": {"event_type": "sql_injection", "count_threshold": 3, "time_window_seconds": 300, "group_by": "source_ip"}},
    {"id": "rdp_brute_force", "title": "RDP Brute Force Detected",
     "description": "Multiple failed RDP authentication attempts from same IP.",
     "severity": "high", "enabled": True, "source": "builtin", "mitre": ["T1110.003"],
     "condition": {"event_type": "auth_failure", "count_threshold": 8, "time_window_seconds": 180, "group_by": "source_ip", "filter": {"service": "rdp"}}},
    {"id": "dns_tunneling", "title": "Possible DNS Tunneling",
     "description": "Unusually high volume of DNS queries from a single host.",
     "severity": "high", "enabled": True, "source": "builtin", "mitre": ["T1071.004"],
     "condition": {"event_type": "dns_query", "count_threshold": 100, "time_window_seconds": 60, "group_by": "source_ip"}},
    {"id": "c2_beacon", "title": "C2 Beacon Pattern Detected",
     "description": "Periodic outbound connections suggesting command-and-control beaconing.",
     "severity": "critical", "enabled": True, "source": "builtin", "mitre": ["T1071"],
     "condition": {"event_type": "connection", "count_threshold": 5, "time_window_seconds": 300, "group_by": "source_ip", "filter": {"direction": "outbound", "target_type": "external"}, "unique_field": "destination_ip"}},
    {"id": "web_shell_activity", "title": "Web Shell Activity Detected",
     "description": "Suspicious HTTP requests consistent with web shell usage.",
     "severity": "critical", "enabled": True, "source": "builtin", "mitre": ["T1505.003"],
     "condition": {"event_type": "http_request", "count_threshold": 3, "time_window_seconds": 120, "group_by": "source_ip", "filter": {"method": "POST", "path_contains": [".php", ".asp", ".jsp"]}}},
    {"id": "privilege_escalation", "title": "Privilege Escalation Attempt",
     "description": "Multiple privilege escalation attempts detected.",
     "severity": "critical", "enabled": True, "source": "builtin", "mitre": ["T1068"],
     "condition": {"event_type": "priv_escalation", "count_threshold": 2, "time_window_seconds": 300, "group_by": "source_ip"}},
    {"id": "xss_attack_chain", "title": "XSS Attack Chain",
     "description": "Multiple cross-site scripting attempts from same source.",
     "severity": "high", "enabled": True, "source": "builtin", "mitre": ["T1059.007"],
     "condition": {"event_type": "xss", "count_threshold": 5, "time_window_seconds": 300, "group_by": "source_ip"}},
    # Auth category
    {"id": "sigma_auth_account_lockout", "title": "Account Lockout Detected", "description": "Multiple failed authentications leading to account lockout.", "severity": "medium", "enabled": True, "source": "sigma", "category": "authentication", "mitre": ["T1110"], "condition": {"event_type": "auth_failure", "count_threshold": 10, "time_window_seconds": 300, "group_by": "username"}},
    {"id": "sigma_auth_password_spray", "title": "Password Spray Attack", "description": "Same password tried against many accounts from single source.", "severity": "high", "enabled": True, "source": "sigma", "category": "authentication", "mitre": ["T1110.003"], "condition": {"event_type": "auth_failure", "count_threshold": 15, "time_window_seconds": 600, "group_by": "source_ip", "unique_field": "username"}},
    {"id": "sigma_auth_kerberos_abuse", "title": "Kerberos Ticket Abuse", "description": "Suspicious Kerberos authentication patterns indicating ticket abuse.", "severity": "critical", "enabled": True, "source": "sigma", "category": "authentication", "mitre": ["T1558.003"], "condition": {"event_type": "kerberos_auth", "count_threshold": 3, "time_window_seconds": 120, "group_by": "source_ip", "filter": {"encryption_type": "RC4"}}},
    {"id": "sigma_auth_ntlm_relay", "title": "NTLM Relay Attack Detected", "description": "NTLM authentication from unexpected source suggesting relay.", "severity": "critical", "enabled": True, "source": "sigma", "category": "authentication", "mitre": ["T1557.001"], "condition": {"event_type": "ntlm_auth", "count_threshold": 3, "time_window_seconds": 60, "group_by": "source_ip", "filter": {"target_type": "internal"}}},
    {"id": "sigma_auth_pass_the_hash", "title": "Pass-the-Hash Attack", "description": "Authentication using NTLM hash without interactive login.", "severity": "critical", "enabled": True, "source": "sigma", "category": "authentication", "mitre": ["T1550.002"], "condition": {"event_type": "ntlm_auth", "count_threshold": 2, "time_window_seconds": 60, "group_by": "source_ip", "filter": {"logon_type": "network"}}},
    {"id": "sigma_auth_default_credentials", "title": "Default Credentials Usage", "description": "Login attempt using known default credentials.", "severity": "high", "enabled": True, "source": "sigma", "category": "authentication", "mitre": ["T1078.001"], "condition": {"event_type": "auth_success", "filter": {"username": ["admin", "root", "test", "guest", "default", "pi", "ubuntu"]}}},
    {"id": "sigma_auth_ssh_key_brute", "title": "SSH Key Brute Force", "description": "Multiple SSH key authentication failures from same IP.", "severity": "high", "enabled": True, "source": "sigma", "category": "authentication", "mitre": ["T1110.004"], "condition": {"event_type": "auth_failure", "count_threshold": 20, "time_window_seconds": 120, "group_by": "source_ip", "filter": {"service": "ssh", "auth_method": "publickey"}}},
    {"id": "sigma_auth_ftp_brute", "title": "FTP Brute Force Detected", "description": "Multiple failed FTP login attempts from same source.", "severity": "high", "enabled": True, "source": "sigma", "category": "authentication", "mitre": ["T1110.001"], "condition": {"event_type": "auth_failure", "count_threshold": 10, "time_window_seconds": 300, "group_by": "source_ip", "filter": {"service": "ftp"}}},
    {"id": "sigma_auth_golden_ticket", "title": "Golden Ticket Usage Suspected", "description": "Kerberos TGT with abnormally long lifetime detected.", "severity": "critical", "enabled": True, "source": "sigma", "category": "authentication", "mitre": ["T1558.001"], "condition": {"event_type": "kerberos_auth", "filter": {"ticket_lifetime_gt": 36000}}},
    {"id": "sigma_auth_mfa_bypass", "title": "MFA Bypass Attempt", "description": "Successful auth without MFA after multiple MFA failures.", "severity": "critical", "enabled": True, "source": "sigma", "category": "authentication", "mitre": ["T1556.006"], "condition": {"event_type": "mfa_failure", "count_threshold": 5, "time_window_seconds": 300, "group_by": "username"}},
    {"id": "sigma_auth_after_hours", "title": "After-Hours Authentication", "description": "Successful authentication outside normal business hours.", "severity": "medium", "enabled": True, "source": "sigma", "category": "authentication", "mitre": ["T1078"], "condition": {"event_type": "auth_success", "filter": {"time_of_day": "off_hours"}}},
    {"id": "sigma_auth_impossible_travel", "title": "Impossible Travel - Concurrent Sessions", "description": "Same user authenticated from geographically distant locations simultaneously.", "severity": "high", "enabled": True, "source": "sigma", "category": "authentication", "mitre": ["T1078"], "condition": {"event_type": "auth_success", "count_threshold": 2, "time_window_seconds": 300, "group_by": "username", "unique_field": "geo_country"}},
    {"id": "sigma_auth_smtp_brute", "title": "SMTP Authentication Brute Force", "description": "Multiple failed SMTP authentication attempts.", "severity": "high", "enabled": True, "source": "sigma", "category": "authentication", "mitre": ["T1110.001"], "condition": {"event_type": "auth_failure", "count_threshold": 10, "time_window_seconds": 600, "group_by": "source_ip", "filter": {"service": "smtp"}}},
    {"id": "sigma_auth_vpn_brute", "title": "VPN Brute Force Detected", "description": "Multiple failed VPN authentication attempts from same source.", "severity": "high", "enabled": True, "source": "sigma", "category": "authentication", "mitre": ["T1110"], "condition": {"event_type": "auth_failure", "count_threshold": 8, "time_window_seconds": 300, "group_by": "source_ip", "filter": {"service": "vpn"}}},
    {"id": "sigma_auth_service_account_interactive", "title": "Service Account Interactive Login", "description": "Service account used for interactive login unexpectedly.", "severity": "high", "enabled": True, "source": "sigma", "category": "authentication", "mitre": ["T1078.003"], "condition": {"event_type": "auth_success", "filter": {"account_type": "service", "logon_type": "interactive"}}},
    # Web attacks
    {"id": "sigma_web_sqli_union", "title": "SQL Injection - UNION SELECT", "description": "Detects UNION SELECT SQL injection attempts in web requests.", "severity": "high", "enabled": True, "source": "sigma", "category": "web_attacks", "mitre": ["T1190"], "condition": {"event_type": "web_request", "filter": {"path_contains": ["UNION", "SELECT", "union", "select"]}, "count_threshold": 1, "time_window_seconds": 60, "group_by": "source_ip"}},
    {"id": "sigma_web_sqli_blind", "title": "Blind SQL Injection Attempt", "description": "Detects blind SQL injection attempts using boolean/time techniques.", "severity": "high", "enabled": True, "source": "sigma", "category": "web_attacks", "mitre": ["T1190"], "condition": {"event_type": "web_request", "filter": {"path_contains": ["SLEEP(", "BENCHMARK(", "WAITFOR", "1=1", "1'='1", "OR 1=1"]}, "count_threshold": 1, "time_window_seconds": 60, "group_by": "source_ip"}},
    {"id": "sigma_web_sqli_time", "title": "Time-Based SQL Injection", "description": "Detects time-based blind SQL injection via slow response patterns.", "severity": "high", "enabled": True, "source": "sigma", "category": "web_attacks", "mitre": ["T1190"], "condition": {"event_type": "web_request", "filter": {"path_contains": ["SLEEP", "pg_sleep", "DBMS_PIPE", "WAITFOR DELAY"]}, "count_threshold": 2, "time_window_seconds": 120, "group_by": "source_ip"}},
    {"id": "sigma_web_xss_reflected", "title": "Reflected XSS Attempt", "description": "Detects reflected cross-site scripting payloads in URL parameters.", "severity": "high", "enabled": True, "source": "sigma", "category": "web_attacks", "mitre": ["T1059.007"], "condition": {"event_type": "web_request", "filter": {"path_contains": ["<script", "javascript:", "onerror=", "onload=", "alert("]}, "count_threshold": 1, "time_window_seconds": 60, "group_by": "source_ip"}},
    {"id": "sigma_web_xss_stored", "title": "Stored XSS Attempt", "description": "Detects stored XSS via POST requests with script payloads.", "severity": "critical", "enabled": True, "source": "sigma", "category": "web_attacks", "mitre": ["T1059.007"], "condition": {"event_type": "web_request", "filter": {"method": "POST", "path_contains": ["<script", "<img", "<svg", "onmouseover="]}, "count_threshold": 1, "time_window_seconds": 60, "group_by": "source_ip"}},
    {"id": "sigma_web_csrf", "title": "CSRF Attack Detected", "description": "Cross-site request forgery detected via missing/invalid CSRF token.", "severity": "medium", "enabled": True, "source": "sigma", "category": "web_attacks", "mitre": ["T1189"], "condition": {"event_type": "web_request", "filter": {"csrf_valid": False, "method": "POST"}, "count_threshold": 5, "time_window_seconds": 120, "group_by": "source_ip"}},
    {"id": "sigma_web_path_traversal", "title": "Path Traversal Attack", "description": "Directory traversal attempt to access files outside web root.", "severity": "high", "enabled": True, "source": "sigma", "category": "web_attacks", "mitre": ["T1083"], "condition": {"event_type": "web_request", "filter": {"path_contains": ["../", "..\\", "%2e%2e", "/etc/passwd", "/etc/shadow"]}, "count_threshold": 1, "time_window_seconds": 60, "group_by": "source_ip"}},
    {"id": "sigma_web_command_injection", "title": "OS Command Injection", "description": "Detects OS command injection patterns in web requests.", "severity": "critical", "enabled": True, "source": "sigma", "category": "web_attacks", "mitre": ["T1059"], "condition": {"event_type": "web_request", "filter": {"path_contains": ["; ls", "| cat", "&& whoami", "`id`", "$(id)", "; curl"]}, "count_threshold": 1, "time_window_seconds": 60, "group_by": "source_ip"}},
    {"id": "sigma_web_ssrf", "title": "Server-Side Request Forgery (SSRF)", "description": "Detects SSRF attempts targeting internal resources or cloud metadata.", "severity": "critical", "enabled": True, "source": "sigma", "category": "web_attacks", "mitre": ["T1190"], "condition": {"event_type": "web_request", "filter": {"path_contains": ["169.254.169.254", "localhost", "127.0.0.1", "0.0.0.0", "metadata.google"]}, "count_threshold": 1, "time_window_seconds": 60, "group_by": "source_ip"}},
    {"id": "sigma_web_file_upload", "title": "Malicious File Upload Attempt", "description": "Upload of potentially malicious file types detected.", "severity": "high", "enabled": True, "source": "sigma", "category": "web_attacks", "mitre": ["T1505.003"], "condition": {"event_type": "web_request", "filter": {"method": "POST", "path_contains": [".php", ".jsp", ".aspx", ".sh", ".exe", ".phtml"]}, "count_threshold": 1, "time_window_seconds": 300, "group_by": "source_ip"}},
    {"id": "sigma_web_xxe", "title": "XML External Entity (XXE) Injection", "description": "Detects XXE injection via XML payloads with external entity definitions.", "severity": "critical", "enabled": True, "source": "sigma", "category": "web_attacks", "mitre": ["T1190"], "condition": {"event_type": "web_request", "filter": {"path_contains": ["<!ENTITY", "SYSTEM", "file://", "expect://"]}, "count_threshold": 1, "time_window_seconds": 60, "group_by": "source_ip"}},
    {"id": "sigma_web_open_redirect", "title": "Open Redirect Attempt", "description": "Detects open redirect abuse via URL parameters.", "severity": "medium", "enabled": True, "source": "sigma", "category": "web_attacks", "mitre": ["T1189"], "condition": {"event_type": "web_request", "filter": {"path_contains": ["redirect=http", "url=http", "next=http", "return_to=http"]}, "count_threshold": 3, "time_window_seconds": 120, "group_by": "source_ip"}},
    {"id": "sigma_web_deserialization", "title": "Insecure Deserialization Attack", "description": "Detects serialized object injection attempts.", "severity": "critical", "enabled": True, "source": "sigma", "category": "web_attacks", "mitre": ["T1190"], "condition": {"event_type": "web_request", "filter": {"path_contains": ["rO0AB", "O:4:", "a:2:{", "aced0005"]}, "count_threshold": 1, "time_window_seconds": 60, "group_by": "source_ip"}},
    {"id": "sigma_web_request_smuggling", "title": "HTTP Request Smuggling", "description": "Detects HTTP request smuggling via malformed headers.", "severity": "high", "enabled": True, "source": "sigma", "category": "web_attacks", "mitre": ["T1190"], "condition": {"event_type": "web_request", "filter": {"path_contains": ["Transfer-Encoding: chunked", "Content-Length:"]}, "count_threshold": 3, "time_window_seconds": 60, "group_by": "source_ip"}},
    {"id": "sigma_web_api_abuse", "title": "API Endpoint Enumeration", "description": "Rapid requests to multiple API endpoints suggesting enumeration.", "severity": "medium", "enabled": True, "source": "sigma", "category": "web_attacks", "mitre": ["T1190"], "condition": {"event_type": "web_request", "filter": {"path_contains": ["/api/"]}, "count_threshold": 50, "time_window_seconds": 60, "group_by": "source_ip", "unique_field": "path"}},
    # Lateral movement
    {"id": "sigma_lateral_smb_enum", "title": "SMB Share Enumeration", "description": "Multiple SMB share access attempts suggesting network enumeration.", "severity": "high", "enabled": True, "source": "sigma", "category": "lateral_movement", "mitre": ["T1021.002"], "condition": {"event_type": "smb_access", "count_threshold": 5, "time_window_seconds": 120, "group_by": "source_ip", "unique_field": "share_name"}},
    {"id": "sigma_lateral_wmi_exec", "title": "WMI Remote Execution", "description": "Remote process creation via WMI detected.", "severity": "high", "enabled": True, "source": "sigma", "category": "lateral_movement", "mitre": ["T1047"], "condition": {"event_type": "process_creation", "filter": {"parent_process": "wmiprvse.exe"}}},
    {"id": "sigma_lateral_psexec", "title": "PsExec Remote Execution", "description": "PsExec service installation or usage detected on remote host.", "severity": "high", "enabled": True, "source": "sigma", "category": "lateral_movement", "mitre": ["T1569.002"], "condition": {"event_type": "service_install", "filter": {"service_name": ["PSEXESVC", "psexec"]}}},
    {"id": "sigma_lateral_rdp_pivot", "title": "RDP Lateral Pivot", "description": "RDP connection from internal host to multiple internal targets.", "severity": "high", "enabled": True, "source": "sigma", "category": "lateral_movement", "mitre": ["T1021.001"], "condition": {"event_type": "connection", "count_threshold": 3, "time_window_seconds": 300, "group_by": "source_ip", "unique_field": "destination_ip", "filter": {"destination_port": 3389, "target_type": "internal"}}},
    {"id": "sigma_lateral_ssh_tunnel", "title": "SSH Tunneling Detected", "description": "SSH connection with port forwarding flags detected.", "severity": "high", "enabled": True, "source": "sigma", "category": "lateral_movement", "mitre": ["T1572"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["ssh", "-L", "-R", "-D"]}}},
    {"id": "sigma_lateral_port_forward", "title": "Port Forwarding Detected", "description": "Local or remote port forwarding established.", "severity": "medium", "enabled": True, "source": "sigma", "category": "lateral_movement", "mitre": ["T1572"], "condition": {"event_type": "network", "filter": {"port_forward": True}}},
    {"id": "sigma_lateral_dcom", "title": "DCOM Remote Execution", "description": "Process creation via DCOM lateral movement technique.", "severity": "high", "enabled": True, "source": "sigma", "category": "lateral_movement", "mitre": ["T1021.003"], "condition": {"event_type": "process_creation", "filter": {"parent_process": "mmc.exe", "path_contains": ["excel.exe", "powershell.exe"]}}},
    {"id": "sigma_lateral_winrm", "title": "WinRM Lateral Movement", "description": "Remote command execution via WinRM/PowerShell Remoting.", "severity": "high", "enabled": True, "source": "sigma", "category": "lateral_movement", "mitre": ["T1021.006"], "condition": {"event_type": "process_creation", "filter": {"parent_process": "wsmprovhost.exe"}}},
    {"id": "sigma_lateral_internal_scan", "title": "Internal Network Port Scan", "description": "Internal host scanning other internal hosts on multiple ports.", "severity": "high", "enabled": True, "source": "sigma", "category": "lateral_movement", "mitre": ["T1046"], "condition": {"event_type": "connection", "count_threshold": 15, "time_window_seconds": 60, "group_by": "source_ip", "unique_field": "destination_ip", "filter": {"target_type": "internal"}}},
    {"id": "sigma_lateral_arp_spoof", "title": "ARP Spoofing Detected", "description": "Gratuitous ARP packets suggesting ARP cache poisoning.", "severity": "critical", "enabled": True, "source": "sigma", "category": "lateral_movement", "mitre": ["T1557.002"], "condition": {"event_type": "arp_anomaly", "count_threshold": 5, "time_window_seconds": 30, "group_by": "source_mac"}},
    # Persistence
    {"id": "sigma_persist_cron", "title": "Suspicious Cron Job Created", "description": "New cron job created with potentially malicious command.", "severity": "high", "enabled": True, "source": "sigma", "category": "persistence", "mitre": ["T1053.003"], "condition": {"event_type": "file_modification", "filter": {"path_contains": ["/etc/crontab", "/var/spool/cron", "/etc/cron.d"]}}},
    {"id": "sigma_persist_systemd", "title": "Suspicious Systemd Service Created", "description": "New systemd service unit file created or modified.", "severity": "high", "enabled": True, "source": "sigma", "category": "persistence", "mitre": ["T1543.002"], "condition": {"event_type": "file_modification", "filter": {"path_contains": ["/etc/systemd/system/", "/lib/systemd/system/"]}}},
    {"id": "sigma_persist_registry_run", "title": "Registry Run Key Persistence", "description": "Modification of Windows registry Run key for persistence.", "severity": "high", "enabled": True, "source": "sigma", "category": "persistence", "mitre": ["T1547.001"], "condition": {"event_type": "registry_modification", "filter": {"path_contains": ["\\Run", "\\RunOnce"]}}},
    {"id": "sigma_persist_scheduled_task", "title": "Scheduled Task Created", "description": "New scheduled task created via schtasks or Task Scheduler.", "severity": "high", "enabled": True, "source": "sigma", "category": "persistence", "mitre": ["T1053.005"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["schtasks", "/create"]}}},
    {"id": "sigma_persist_ssh_keys", "title": "SSH Authorized Keys Modified", "description": "Modification of SSH authorized_keys file for persistent access.", "severity": "critical", "enabled": True, "source": "sigma", "category": "persistence", "mitre": ["T1098.004"], "condition": {"event_type": "file_modification", "filter": {"path_contains": ["authorized_keys"]}}},
    {"id": "sigma_persist_webshell", "title": "Web Shell File Deployed", "description": "Suspicious script file created in web-accessible directory.", "severity": "critical", "enabled": True, "source": "sigma", "category": "persistence", "mitre": ["T1505.003"], "condition": {"event_type": "file_creation", "filter": {"path_contains": ["/var/www/", "/public_html/", "wwwroot", ".php", ".jsp", ".aspx"]}}},
    {"id": "sigma_persist_startup_folder", "title": "Startup Folder Persistence", "description": "File placed in Windows Startup folder for automatic execution.", "severity": "high", "enabled": True, "source": "sigma", "category": "persistence", "mitre": ["T1547.001"], "condition": {"event_type": "file_creation", "filter": {"path_contains": ["\\Start Menu\\Programs\\Startup", "\\Startup\\"]}}},
    {"id": "sigma_persist_login_hook", "title": "macOS Login Hook Persistence", "description": "Login or logout hook configured for persistence on macOS.", "severity": "high", "enabled": True, "source": "sigma", "category": "persistence", "mitre": ["T1037.002"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["defaults write", "LoginHook", "LogoutHook"]}}},
    {"id": "sigma_persist_launch_agent", "title": "macOS Launch Agent/Daemon Created", "description": "New LaunchAgent or LaunchDaemon plist created on macOS.", "severity": "high", "enabled": True, "source": "sigma", "category": "persistence", "mitre": ["T1543.001"], "condition": {"event_type": "file_creation", "filter": {"path_contains": ["/LaunchAgents/", "/LaunchDaemons/"]}}},
    {"id": "sigma_persist_init_script", "title": "Init Script Modified", "description": "System init script modified for persistence.", "severity": "high", "enabled": True, "source": "sigma", "category": "persistence", "mitre": ["T1037.004"], "condition": {"event_type": "file_modification", "filter": {"path_contains": ["/etc/init.d/", "/etc/rc.local", "/etc/rc.d/"]}}},
    # Privilege escalation
    {"id": "sigma_privesc_suid", "title": "SUID Binary Exploitation", "description": "Execution of uncommon SUID binary suggesting privilege escalation.", "severity": "critical", "enabled": True, "source": "sigma", "category": "privilege_escalation", "mitre": ["T1548.001"], "condition": {"event_type": "process_creation", "filter": {"suid": True, "path_contains": ["find", "vim", "nmap", "python", "perl"]}}},
    {"id": "sigma_privesc_sudo_abuse", "title": "Sudo Misconfiguration Exploitation", "description": "Exploitation of permissive sudo rules to gain root access.", "severity": "critical", "enabled": True, "source": "sigma", "category": "privilege_escalation", "mitre": ["T1548.003"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["sudo", "-u root", "NOPASSWD"]}, "count_threshold": 3, "time_window_seconds": 60, "group_by": "username"}},
    {"id": "sigma_privesc_kernel_exploit", "title": "Kernel Exploit Attempt", "description": "Suspicious binary execution patterns consistent with kernel exploitation.", "severity": "critical", "enabled": True, "source": "sigma", "category": "privilege_escalation", "mitre": ["T1068"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["/tmp/", "exploit", "pwn", "dirty"]}}},
    {"id": "sigma_privesc_service_account", "title": "Service Account Privilege Abuse", "description": "Service account performing actions beyond normal scope.", "severity": "high", "enabled": True, "source": "sigma", "category": "privilege_escalation", "mitre": ["T1078.003"], "condition": {"event_type": "process_creation", "filter": {"account_type": "service", "path_contains": ["cmd.exe", "powershell", "/bin/bash"]}}},
    {"id": "sigma_privesc_token_manipulation", "title": "Access Token Manipulation", "description": "Token impersonation or theft for privilege escalation.", "severity": "critical", "enabled": True, "source": "sigma", "category": "privilege_escalation", "mitre": ["T1134"], "condition": {"event_type": "token_manipulation", "count_threshold": 1, "time_window_seconds": 60, "group_by": "source_ip"}},
    {"id": "sigma_privesc_dll_hijack", "title": "DLL Hijacking Attempt", "description": "DLL loaded from unexpected path suggesting DLL hijacking.", "severity": "high", "enabled": True, "source": "sigma", "category": "privilege_escalation", "mitre": ["T1574.001"], "condition": {"event_type": "dll_load", "filter": {"path_contains": ["\\Temp\\", "\\Downloads\\", "\\AppData\\"]}}},
    {"id": "sigma_privesc_named_pipe", "title": "Named Pipe Impersonation", "description": "Named pipe created for token impersonation.", "severity": "high", "enabled": True, "source": "sigma", "category": "privilege_escalation", "mitre": ["T1134.001"], "condition": {"event_type": "pipe_creation", "filter": {"path_contains": ["\\\\.\\pipe\\", "ImpersonateNamedPipeClient"]}}},
    {"id": "sigma_privesc_unquoted_path", "title": "Unquoted Service Path Exploitation", "description": "Executable placed in path to exploit unquoted service path vulnerability.", "severity": "high", "enabled": True, "source": "sigma", "category": "privilege_escalation", "mitre": ["T1574.009"], "condition": {"event_type": "file_creation", "filter": {"path_contains": ["Program.exe", "Common.exe"]}}},
    {"id": "sigma_privesc_setuid_change", "title": "SUID/SGID Bit Modified", "description": "File permissions changed to add SUID or SGID bit.", "severity": "critical", "enabled": True, "source": "sigma", "category": "privilege_escalation", "mitre": ["T1548.001"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["chmod", "+s", "4755", "2755"]}}},
    {"id": "sigma_privesc_capabilities", "title": "Linux Capability Abuse", "description": "Binary with dangerous capabilities executed for privilege escalation.", "severity": "high", "enabled": True, "source": "sigma", "category": "privilege_escalation", "mitre": ["T1548"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["cap_setuid", "cap_sys_admin", "setcap"]}}},
    # Data exfiltration
    {"id": "sigma_exfil_large_transfer", "title": "Large Outbound Data Transfer", "description": "Unusually large data transfer to external destination.", "severity": "high", "enabled": True, "source": "sigma", "category": "data_exfiltration", "mitre": ["T1048"], "condition": {"event_type": "network", "filter": {"direction": "outbound", "bytes_gt": 52428800, "target_type": "external"}}},
    {"id": "sigma_exfil_dns", "title": "DNS Data Exfiltration", "description": "Large or encoded DNS queries suggesting data exfiltration via DNS.", "severity": "high", "enabled": True, "source": "sigma", "category": "data_exfiltration", "mitre": ["T1048.003"], "condition": {"event_type": "dns_query", "count_threshold": 50, "time_window_seconds": 60, "group_by": "source_ip", "filter": {"query_length_gt": 50}}},
    {"id": "sigma_exfil_uncommon_port", "title": "HTTPS on Uncommon Port", "description": "TLS traffic on non-standard port suggesting covert channel.", "severity": "medium", "enabled": True, "source": "sigma", "category": "data_exfiltration", "mitre": ["T1571"], "condition": {"event_type": "connection", "filter": {"protocol": "tls", "target_type": "external"}, "count_threshold": 5, "time_window_seconds": 300, "group_by": "source_ip"}},
    {"id": "sigma_exfil_cloud_upload", "title": "Cloud Storage Upload Detected", "description": "Data upload to cloud storage services detected.", "severity": "medium", "enabled": True, "source": "sigma", "category": "data_exfiltration", "mitre": ["T1567.002"], "condition": {"event_type": "web_request", "filter": {"path_contains": ["s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net", "dropbox.com", "drive.google.com"]}, "count_threshold": 3, "time_window_seconds": 300, "group_by": "source_ip"}},
    {"id": "sigma_exfil_email_spike", "title": "Email Attachment Spike", "description": "Unusual volume of email with attachments from single user.", "severity": "medium", "enabled": True, "source": "sigma", "category": "data_exfiltration", "mitre": ["T1048.002"], "condition": {"event_type": "email_sent", "count_threshold": 20, "time_window_seconds": 300, "group_by": "sender", "filter": {"has_attachment": True}}},
    {"id": "sigma_exfil_usb", "title": "USB Storage Device Mounted", "description": "USB mass storage device connected and mounted.", "severity": "medium", "enabled": True, "source": "sigma", "category": "data_exfiltration", "mitre": ["T1052.001"], "condition": {"event_type": "device_connect", "filter": {"device_type": "usb_storage"}}},
    {"id": "sigma_exfil_archive_creation", "title": "Archive Created Before Transfer", "description": "Archive file created shortly before outbound network activity.", "severity": "high", "enabled": True, "source": "sigma", "category": "data_exfiltration", "mitre": ["T1560.001"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["tar", "zip", "7z", "rar", "gzip"]}, "count_threshold": 2, "time_window_seconds": 120, "group_by": "source_ip"}},
    {"id": "sigma_exfil_clipboard", "title": "Clipboard Data Access", "description": "Process accessing clipboard data for potential exfiltration.", "severity": "medium", "enabled": True, "source": "sigma", "category": "data_exfiltration", "mitre": ["T1115"], "condition": {"event_type": "clipboard_access", "count_threshold": 10, "time_window_seconds": 60, "group_by": "process_name"}},
    {"id": "sigma_exfil_encrypted_channel", "title": "Encrypted Channel Data Exfiltration", "description": "High-volume encrypted traffic to unusual destination.", "severity": "high", "enabled": True, "source": "sigma", "category": "data_exfiltration", "mitre": ["T1041"], "condition": {"event_type": "connection", "filter": {"protocol": "tls", "direction": "outbound", "bytes_gt": 10485760}}},
    {"id": "sigma_exfil_steganography", "title": "Steganography Tool Detected", "description": "Known steganography tool execution detected.", "severity": "high", "enabled": True, "source": "sigma", "category": "data_exfiltration", "mitre": ["T1027.003"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["steghide", "openstego", "snow", "outguess"]}}},
    # C2
    {"id": "sigma_c2_beacon_regular", "title": "C2 Beacon - Regular Interval", "description": "Outbound connections at regular intervals suggesting C2 beaconing.", "severity": "critical", "enabled": True, "source": "sigma", "category": "command_and_control", "mitre": ["T1071.001"], "condition": {"event_type": "connection", "count_threshold": 10, "time_window_seconds": 600, "group_by": "destination_ip", "filter": {"direction": "outbound", "target_type": "external"}}},
    {"id": "sigma_c2_dns", "title": "DNS-Based Command and Control", "description": "Suspicious DNS query patterns indicating C2 via DNS protocol.", "severity": "critical", "enabled": True, "source": "sigma", "category": "command_and_control", "mitre": ["T1071.004"], "condition": {"event_type": "dns_query", "count_threshold": 200, "time_window_seconds": 300, "group_by": "source_ip"}},
    {"id": "sigma_c2_https_new_domain", "title": "HTTPS C2 to Newly Registered Domain", "description": "HTTPS connection to recently registered or low-reputation domain.", "severity": "high", "enabled": True, "source": "sigma", "category": "command_and_control", "mitre": ["T1071.001"], "condition": {"event_type": "connection", "filter": {"domain_age_days_lt": 30, "protocol": "tls", "direction": "outbound"}}},
    {"id": "sigma_c2_irc", "title": "IRC C2 Traffic Detected", "description": "IRC protocol traffic detected suggesting botnet C2 channel.", "severity": "high", "enabled": True, "source": "sigma", "category": "command_and_control", "mitre": ["T1071.001"], "condition": {"event_type": "connection", "filter": {"destination_port": [6667, 6668, 6669, 6697]}}},
    {"id": "sigma_c2_tor", "title": "Tor Network Usage Detected", "description": "Connection to known Tor entry/exit nodes.", "severity": "high", "enabled": True, "source": "sigma", "category": "command_and_control", "mitre": ["T1090.003"], "condition": {"event_type": "connection", "filter": {"destination_port": [9001, 9030, 9050, 9051]}}},
    {"id": "sigma_c2_reverse_shell", "title": "Reverse Shell Connection", "description": "Outbound connection from shell process indicating reverse shell.", "severity": "critical", "enabled": True, "source": "sigma", "category": "command_and_control", "mitre": ["T1059"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["bash -i", "nc -e", "ncat", "/dev/tcp/", "mkfifo"]}}},
    {"id": "sigma_c2_encoded_powershell", "title": "Encoded PowerShell Execution", "description": "PowerShell execution with encoded command suggesting C2 stager.", "severity": "critical", "enabled": True, "source": "sigma", "category": "command_and_control", "mitre": ["T1059.001"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["powershell", "-enc", "-EncodedCommand", "FromBase64String"]}}},
    {"id": "sigma_c2_lolbin", "title": "LOLBin Abuse for C2", "description": "Legitimate binary abused for downloading or executing C2 payload.", "severity": "high", "enabled": True, "source": "sigma", "category": "command_and_control", "mitre": ["T1218"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["certutil", "bitsadmin", "mshta", "regsvr32", "rundll32"]}}},
    {"id": "sigma_c2_domain_fronting", "title": "Domain Fronting Detected", "description": "TLS SNI mismatch with HTTP Host header suggesting domain fronting.", "severity": "high", "enabled": True, "source": "sigma", "category": "command_and_control", "mitre": ["T1090.004"], "condition": {"event_type": "web_request", "filter": {"sni_host_mismatch": True}}},
    {"id": "sigma_c2_cobalt_strike", "title": "Cobalt Strike C2 Pattern", "description": "HTTP traffic matching Cobalt Strike malleable C2 profile patterns.", "severity": "critical", "enabled": True, "source": "sigma", "category": "command_and_control", "mitre": ["T1071.001"], "condition": {"event_type": "web_request", "filter": {"path_contains": ["/pixel", "/submit.php", "/updates", "__utm.gif", "/__session"]}, "count_threshold": 5, "time_window_seconds": 300, "group_by": "source_ip"}},
    # Defense evasion
    {"id": "sigma_evasion_log_deletion", "title": "Security Log Deletion", "description": "System or security log files deleted or cleared.", "severity": "critical", "enabled": True, "source": "sigma", "category": "defense_evasion", "mitre": ["T1070.001"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["wevtutil", "cl Security", "rm /var/log", "truncate", "> /var/log"]}}},
    {"id": "sigma_evasion_timestomping", "title": "File Timestomping Detected", "description": "File timestamps modified to evade forensic analysis.", "severity": "high", "enabled": True, "source": "sigma", "category": "defense_evasion", "mitre": ["T1070.006"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["touch -t", "touch -d", "SetFileTime", "timestomp"]}}},
    {"id": "sigma_evasion_process_injection", "title": "Process Injection Detected", "description": "Code injection into running process for defense evasion.", "severity": "critical", "enabled": True, "source": "sigma", "category": "defense_evasion", "mitre": ["T1055"], "condition": {"event_type": "process_injection", "count_threshold": 1, "time_window_seconds": 60, "group_by": "source_ip"}},
    {"id": "sigma_evasion_binary_padding", "title": "Binary Padding Evasion", "description": "Executable modified with padding to evade hash-based detection.", "severity": "medium", "enabled": True, "source": "sigma", "category": "defense_evasion", "mitre": ["T1027.001"], "condition": {"event_type": "file_modification", "filter": {"size_change_gt": 1048576, "path_contains": [".exe", ".dll", ".bin"]}}},
    {"id": "sigma_evasion_indicator_removal", "title": "Indicator Removal on Host", "description": "Removal of forensic artifacts from the host system.", "severity": "high", "enabled": True, "source": "sigma", "category": "defense_evasion", "mitre": ["T1070"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["shred", "wipe", "srm", "sdelete", "cipher /w"]}}},
    {"id": "sigma_evasion_rootkit", "title": "Rootkit Behavior Detected", "description": "Kernel module loading or syscall hooking detected.", "severity": "critical", "enabled": True, "source": "sigma", "category": "defense_evasion", "mitre": ["T1014"], "condition": {"event_type": "kernel_module_load", "filter": {"signed": False}}},
    {"id": "sigma_evasion_av_tamper", "title": "Antivirus/EDR Tampering", "description": "Attempt to disable or tamper with security tools.", "severity": "critical", "enabled": True, "source": "sigma", "category": "defense_evasion", "mitre": ["T1562.001"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["sc stop", "net stop", "taskkill", "Defender", "MsMpEng", "Set-MpPreference"]}}},
    {"id": "sigma_evasion_firewall_mod", "title": "Firewall Rule Modification", "description": "Host firewall rules modified to allow unauthorized traffic.", "severity": "high", "enabled": True, "source": "sigma", "category": "defense_evasion", "mitre": ["T1562.004"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["netsh advfirewall", "iptables -D", "iptables -F", "ufw disable"]}}},
    {"id": "sigma_evasion_process_hollowing", "title": "Process Hollowing Detected", "description": "Legitimate process unmapped and replaced with malicious code.", "severity": "critical", "enabled": True, "source": "sigma", "category": "defense_evasion", "mitre": ["T1055.012"], "condition": {"event_type": "process_injection", "filter": {"technique": "hollowing"}}},
    {"id": "sigma_evasion_amsi_bypass", "title": "AMSI Bypass Attempt", "description": "Attempt to bypass Antimalware Scan Interface.", "severity": "critical", "enabled": True, "source": "sigma", "category": "defense_evasion", "mitre": ["T1562.001"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["AmsiUtils", "amsiInitFailed", "AmsiScanBuffer"]}}},
    # Discovery
    {"id": "sigma_recon_fast_scan", "title": "Fast Port Scan Detected", "description": "Rapid port scanning of single target (SYN scan pattern).", "severity": "high", "enabled": True, "source": "sigma", "category": "discovery", "mitre": ["T1046"], "condition": {"event_type": "connection", "count_threshold": 50, "time_window_seconds": 30, "group_by": "source_ip", "unique_field": "target_port"}},
    {"id": "sigma_recon_slow_scan", "title": "Slow Stealth Port Scan", "description": "Low-and-slow port scanning to evade detection.", "severity": "medium", "enabled": True, "source": "sigma", "category": "discovery", "mitre": ["T1046"], "condition": {"event_type": "connection", "count_threshold": 20, "time_window_seconds": 3600, "group_by": "source_ip", "unique_field": "target_port"}},
    {"id": "sigma_recon_os_fingerprint", "title": "OS Fingerprinting Detected", "description": "TCP/IP stack fingerprinting attempts (nmap -O style).", "severity": "medium", "enabled": True, "source": "sigma", "category": "discovery", "mitre": ["T1046"], "condition": {"event_type": "connection", "filter": {"tcp_flags": ["SYN", "FIN", "URG", "PSH"]}, "count_threshold": 10, "time_window_seconds": 30, "group_by": "source_ip"}},
    {"id": "sigma_recon_service_enum", "title": "Service Version Enumeration", "description": "Service banner grabbing from multiple ports.", "severity": "medium", "enabled": True, "source": "sigma", "category": "discovery", "mitre": ["T1046"], "condition": {"event_type": "connection", "count_threshold": 10, "time_window_seconds": 120, "group_by": "source_ip", "unique_field": "target_port", "filter": {"banner_grab": True}}},
    {"id": "sigma_recon_dir_bruteforce", "title": "Web Directory Brute Force", "description": "Rapid requests to many different paths indicating directory enumeration.", "severity": "medium", "enabled": True, "source": "sigma", "category": "discovery", "mitre": ["T1083"], "condition": {"event_type": "web_request", "count_threshold": 100, "time_window_seconds": 60, "group_by": "source_ip", "unique_field": "path"}},
    {"id": "sigma_recon_subdomain_enum", "title": "Subdomain Enumeration", "description": "DNS queries for many subdomains of same domain.", "severity": "medium", "enabled": True, "source": "sigma", "category": "discovery", "mitre": ["T1590.002"], "condition": {"event_type": "dns_query", "count_threshold": 50, "time_window_seconds": 120, "group_by": "source_ip", "unique_field": "query_subdomain"}},
    {"id": "sigma_recon_share_discovery", "title": "Network Share Discovery", "description": "Enumeration of network shares across multiple hosts.", "severity": "medium", "enabled": True, "source": "sigma", "category": "discovery", "mitre": ["T1135"], "condition": {"event_type": "smb_access", "count_threshold": 10, "time_window_seconds": 120, "group_by": "source_ip", "unique_field": "destination_ip"}},
    {"id": "sigma_recon_ad_enum", "title": "Active Directory Enumeration", "description": "LDAP queries suggesting Active Directory reconnaissance.", "severity": "high", "enabled": True, "source": "sigma", "category": "discovery", "mitre": ["T1087.002"], "condition": {"event_type": "ldap_query", "count_threshold": 20, "time_window_seconds": 120, "group_by": "source_ip"}},
    {"id": "sigma_recon_snmp_scan", "title": "SNMP Community String Scan", "description": "SNMP queries with common community strings to multiple hosts.", "severity": "medium", "enabled": True, "source": "sigma", "category": "discovery", "mitre": ["T1046"], "condition": {"event_type": "connection", "filter": {"destination_port": 161}, "count_threshold": 10, "time_window_seconds": 60, "group_by": "source_ip", "unique_field": "destination_ip"}},
    {"id": "sigma_recon_vuln_scanner", "title": "Vulnerability Scanner Detected", "description": "Traffic patterns matching known vulnerability scanners (Nessus, OpenVAS).", "severity": "medium", "enabled": True, "source": "sigma", "category": "discovery", "mitre": ["T1595.002"], "condition": {"event_type": "web_request", "filter": {"path_contains": ["Nessus", "OpenVAS", "Nikto", "sqlmap", "w3af"]}, "count_threshold": 5, "time_window_seconds": 60, "group_by": "source_ip"}},
    # Container/Cloud
    {"id": "sigma_cloud_container_escape", "title": "Container Escape Attempt", "description": "Process attempting to escape container sandbox.", "severity": "critical", "enabled": True, "source": "sigma", "category": "container_cloud", "mitre": ["T1611"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["nsenter", "chroot", "/proc/1/root", "/.dockerenv"]}}},
    {"id": "sigma_cloud_privileged_container", "title": "Privileged Container Launched", "description": "Docker container started with --privileged flag.", "severity": "critical", "enabled": True, "source": "sigma", "category": "container_cloud", "mitre": ["T1610"], "condition": {"event_type": "container_start", "filter": {"privileged": True}}},
    {"id": "sigma_cloud_docker_socket", "title": "Docker Socket Exposed", "description": "Docker socket mounted inside container allowing host access.", "severity": "critical", "enabled": True, "source": "sigma", "category": "container_cloud", "mitre": ["T1611"], "condition": {"event_type": "container_start", "filter": {"path_contains": ["/var/run/docker.sock"]}}},
    {"id": "sigma_cloud_k8s_api_abuse", "title": "Kubernetes API Abuse", "description": "Suspicious Kubernetes API requests from unexpected source.", "severity": "high", "enabled": True, "source": "sigma", "category": "container_cloud", "mitre": ["T1609"], "condition": {"event_type": "web_request", "filter": {"path_contains": ["/api/v1/pods", "/api/v1/secrets", "/api/v1/namespaces"]}, "count_threshold": 5, "time_window_seconds": 60, "group_by": "source_ip"}},
    {"id": "sigma_cloud_metadata_ssrf", "title": "Cloud Metadata Service SSRF", "description": "Request to cloud instance metadata endpoint from application.", "severity": "critical", "enabled": True, "source": "sigma", "category": "container_cloud", "mitre": ["T1552.005"], "condition": {"event_type": "web_request", "filter": {"path_contains": ["169.254.169.254", "metadata.google.internal", "100.100.100.200"]}, "count_threshold": 1, "time_window_seconds": 60, "group_by": "source_ip"}},
    {"id": "sigma_cloud_iam_enum", "title": "Cloud IAM Enumeration", "description": "Enumeration of IAM users, roles, or policies.", "severity": "high", "enabled": True, "source": "sigma", "category": "container_cloud", "mitre": ["T1087.004"], "condition": {"event_type": "cloud_api", "filter": {"path_contains": ["ListUsers", "ListRoles", "ListPolicies", "GetAccountAuthorizationDetails"]}, "count_threshold": 5, "time_window_seconds": 120, "group_by": "source_ip"}},
    {"id": "sigma_cloud_cryptomining", "title": "Cryptomining in Container", "description": "Cryptocurrency mining process detected inside container.", "severity": "high", "enabled": True, "source": "sigma", "category": "container_cloud", "mitre": ["T1496"], "condition": {"event_type": "process_creation", "filter": {"path_contains": ["xmrig", "minerd", "cpuminer", "stratum+tcp", "cryptonight"]}}},
    {"id": "sigma_cloud_untrusted_image", "title": "Container Image from Untrusted Registry", "description": "Docker image pulled from non-approved registry.", "severity": "medium", "enabled": True, "source": "sigma", "category": "container_cloud", "mitre": ["T1610"], "condition": {"event_type": "container_pull", "filter": {"untrusted_registry": True}}},
    {"id": "sigma_cloud_k8s_secret_access", "title": "Kubernetes Secret Accessed", "description": "Kubernetes secrets accessed from unexpected pod or user.", "severity": "high", "enabled": True, "source": "sigma", "category": "container_cloud", "mitre": ["T1552.007"], "condition": {"event_type": "cloud_api", "filter": {"path_contains": ["/api/v1/secrets", "get secrets"]}, "count_threshold": 3, "time_window_seconds": 60, "group_by": "source_ip"}},
    {"id": "sigma_cloud_bucket_misconfig", "title": "Cloud Storage Bucket Public Access", "description": "Cloud storage bucket configured with public access.", "severity": "high", "enabled": True, "source": "sigma", "category": "container_cloud", "mitre": ["T1530"], "condition": {"event_type": "cloud_api", "filter": {"path_contains": ["PutBucketAcl", "PutBucketPolicy", "public-read"]}}},
]

CHAIN_RULES = [
    {"id": "advanced_intrusion_chain", "title": "Multi-stage intrusion detected", "severity": "critical", "description": "Same IP: port scan -> brute force -> honeypot interaction", "mitre": ["T1046", "T1110", "T1595.002"], "chain": [{"sigma_rule": "port_scan", "within": 3600}, {"sigma_rule": "brute_force_ssh", "within": 1800}, {"event_type": "honeypot_interaction", "within": 900}], "group_by": "source_ip"},
    {"id": "credential_theft_chain", "title": "Credential theft chain detected", "severity": "critical", "description": "Same IP: brute force -> credential stuffing -> lateral movement", "mitre": ["T1110", "T1110.004", "T1021"], "chain": [{"sigma_rule": "brute_force_ssh", "within": 1800}, {"sigma_rule": "credential_stuffing", "within": 1200}, {"sigma_rule": "lateral_movement", "within": 600}], "group_by": "source_ip"},
    {"id": "web_attack_escalation", "title": "Web attack escalation chain", "severity": "critical", "description": "Same IP: SQL injection -> web shell upload -> data exfiltration", "mitre": ["T1190", "T1505.003", "T1041"], "chain": [{"sigma_rule": "sql_injection_chain", "within": 3600}, {"sigma_rule": "web_shell_activity", "within": 1800}, {"sigma_rule": "data_exfiltration", "within": 900}], "group_by": "source_ip"},
    {"id": "c2_establishment_chain", "title": "C2 establishment chain detected", "severity": "critical", "description": "Same IP: port scan -> brute force -> C2 beacon pattern", "mitre": ["T1046", "T1110", "T1071"], "chain": [{"sigma_rule": "port_scan", "within": 7200}, {"sigma_rule": "brute_force_ssh", "within": 3600}, {"sigma_rule": "c2_beacon", "within": 1800}], "group_by": "source_ip"},
    {"id": "priv_esc_exfil_chain", "title": "Privilege escalation to exfiltration chain", "severity": "critical", "description": "Same IP: brute force -> privilege escalation -> data exfiltration", "mitre": ["T1110", "T1068", "T1041"], "chain": [{"sigma_rule": "brute_force_ssh", "within": 3600}, {"sigma_rule": "privilege_escalation", "within": 1800}, {"sigma_rule": "data_exfiltration", "within": 900}], "group_by": "source_ip"},
]


def main():
    base = Path(__file__).parent.parent / "app" / "rules"

    # Sigma rules
    sigma_base = base / "sigma"
    for rule in BUILT_IN_RULES:
        cat = _category_for(rule)
        cat_dir = sigma_base / cat
        cat_dir.mkdir(parents=True, exist_ok=True)
        out_path = cat_dir / f"{rule['id']}.yaml"
        yaml_dict = _rule_to_yaml_dict(rule)
        with out_path.open("w", encoding="utf-8") as fh:
            yaml.dump(yaml_dict, fh, default_flow_style=False, allow_unicode=True, sort_keys=False)
        print(f"  sigma/{cat}/{rule['id']}.yaml")

    # Chain rules
    chain_dir = base / "chains"
    chain_dir.mkdir(parents=True, exist_ok=True)
    for chain in CHAIN_RULES:
        out_path = chain_dir / f"{chain['id']}.yaml"
        yaml_dict = _chain_to_yaml_dict(chain)
        with out_path.open("w", encoding="utf-8") as fh:
            yaml.dump(yaml_dict, fh, default_flow_style=False, allow_unicode=True, sort_keys=False)
        print(f"  chains/{chain['id']}.yaml")

    total_sigma = len(BUILT_IN_RULES)
    total_chains = len(CHAIN_RULES)
    print(f"\nDone: {total_sigma} sigma rules, {total_chains} chain rules")


if __name__ == "__main__":
    main()
