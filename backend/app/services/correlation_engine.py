"""
Sigma-like correlation engine for AEGIS.

Maintains a sliding window of incoming events (deque, max 10 000) and evaluates
each new event against a set of built-in and custom rules.  When a rule fires it
publishes a `correlation_triggered` event on the event bus so that the AI engine
can open an incident.
"""

import asyncio
import ipaddress
import logging
import re
import time
import uuid
from collections import deque, defaultdict
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("aegis.correlation")


# Attacker allow-list loaded once at module load from AEGIS_ATTACKER_IPS.
# IPs in this set bypass the internal-IP filter even if they would otherwise
# match the private/loopback/Tailscale classifier. Intended for pentest lab
# machines (e.g. a pentest box in the CGNAT range) that need to generate real incidents
# despite living inside the Tailscale CGNAT range.
from app.config import settings as _settings

_ATTACKER_IPS: set[str] = {
    ip.strip()
    for ip in (_settings.AEGIS_ATTACKER_IPS or "").split(",")
    if ip.strip()
}
if _ATTACKER_IPS:
    logger.info(f"Attacker allow-list loaded: {sorted(_ATTACKER_IPS)}")


def _is_internal_ip(ip: str) -> bool:
    """True if IP is private, loopback, link-local, or Tailscale (100.64.0.0/10).

    An IP listed in `AEGIS_ATTACKER_IPS` always returns False — the explicit
    allow-list wins over the network-range classification so that lab pentest
    machines on Tailscale CGNAT still generate real incidents.
    """
    if not ip:
        return True
    # Explicit allow-list wins — a pentest host in CGNAT would otherwise
    # be treated as internal Tailscale traffic and have its attacks silenced.
    if ip in _ATTACKER_IPS:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
        return True
    # Tailscale CGNAT range: 100.64.0.0/10
    try:
        ts_net = ipaddress.ip_network("100.64.0.0/10")
        if addr in ts_net:
            return True
    except ValueError:
        pass
    return False

# ---------------------------------------------------------------------------
# Log-line pattern matchers — translate raw PM2 log lines into typed events
# that Sigma rules can evaluate.  Mirrors log_watcher.PATTERNS but produces
# event dicts instead of incidents.
# ---------------------------------------------------------------------------

_LOG_PATTERNS = [
    {
        "event_type": "sql_injection",
        "severity": "high",
        # See log_watcher.PATTERNS[0] for rationale: the bare `--\s*$`
        # alternative was removed to stop matching traceback dividers
        # (40-dash banners and Python ExceptionGroup headers). Real SQL
        # comments always follow a SQL keyword, so we require one.
        "regex": re.compile(
            r"(?i)(union\s+select|or\s+1\s*=\s*1|;\s*select|drop\s+table"
            r"|information_schema|%27"
            r"|\b(?:SELECT|FROM|WHERE|OR|AND|UNION|ORDER|GROUP)\s+[^\n]*--\s*$"
            r"|'\s*OR\s*'|UNION\s+SELECT|OR\s+1=1)"
        ),
    },
    {
        "event_type": "xss",
        "severity": "medium",
        "regex": re.compile(
            r"(?i)(<script|alert\s*\(|onerror\s*=|onload\s*=|javascript:"
            r"|<img\s+src\s*=\s*x|<svg\s+onload|document\.cookie)"
        ),
    },
    {
        "event_type": "web_request",
        "severity": "high",
        "regex": re.compile(
            r"(\.\./|\.\.%2[fF]|%2[eE]%2[eE]|%252e%252e|\.\.[\\/]"
            r"|/etc/passwd|/etc/shadow|/proc/self|/windows/system32|/var/log)"
        ),
        "tag": "path_traversal",
    },
    {
        "event_type": "auth_failure",
        "severity": "medium",
        "regex": re.compile(r'"(?:GET|POST|PUT|DELETE)\s+\S+\s+HTTP/[\d.]+"\s+401\b'),
    },
    {
        "event_type": "http_request",
        "severity": "low",
        "regex": re.compile(
            r"(?i)(nmap|nikto|sqlmap|masscan|gobuster|dirbuster|wfuzz"
            r"|nuclei|zgrab|hydra|burpsuite|nmaplowercheck|/sdk|/evox|/HNAP1)"
        ),
        "tag": "scanner",
    },
    {
        "event_type": "priv_escalation",
        "severity": "critical",
        "regex": re.compile(
            r"(?i)(;\s*cat\s+/etc|\|\s*whoami|&&\s*id\b|`id`|\$\(id\)"
            r"|;\s*ls\s|\|\s*cat\s|\bexec\s*\()"
        ),
    },
]

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_PORT_RE = re.compile(r":(\d{2,5})\b")
_PATH_RE = re.compile(r'"(?:GET|POST|PUT|DELETE)\s+(\S+)\s+HTTP/')

# EDR kind → correlation event_type mapping
_EDR_EVENT_MAP = {
    "fim": "file_modification",
    "file_created": "file_creation",
    "file_modified": "file_modification",
    "file_deleted": "file_modification",
    "process_start": "process_creation",
    "process_stop": "process_creation",
    "network_anomaly": "connection",
}

# ---------------------------------------------------------------------------
# Cooldown defaults per attack class (v1.6.4 protocol-aware tier)
# ---------------------------------------------------------------------------
# Auth-class attacks (brute force / lockouts) get long cooldowns to suppress
# noisy persistent attackers, recon gets medium, exploit-attempts short, and
# chain correlations never re-fire within the same window.
COOLDOWN_AUTH = 3600        # password/credential class
COOLDOWN_RECON = 600        # scans, enumeration
COOLDOWN_EXPLOIT = 300      # single-shot RCE / SQLi / web exploit
COOLDOWN_EXFIL = 600        # data movement
COOLDOWN_CHAIN = 0          # chain rules never silenced
COOLDOWN_HONEYPOT = 0       # every honeypot hit is a fresh signal
COOLDOWN_SUPPLY = 60        # IoC hits — let burst-deduper handle storms
# v1.6.4.0 — DoS Shield (L7 flood) class. dos_shield already applies its own
# per-(ip,reason) event cooldown (AEGIS_DOS_EVENT_COOLDOWN, default 30s) before
# publishing, so the correlation-side cooldown is kept short: it only needs to
# suppress duplicate *incidents* from the same offender, not the underlying
# dos.* event stream. Distributed/under-attack rules use 0 (every escalation of
# a confirmed flood is signal, mirroring COOLDOWN_CHAIN).
COOLDOWN_DOS = 120          # single-source L7 flood incidents
COOLDOWN_DOS_CRITICAL = 0   # distributed / under-attack — never silenced

# v1.6.4.0 — the complete set of dos.* topics dos_shield may publish. The
# correlation engine binds these to the safelist-gated _on_dos_event handler.
# dos.ip_blocked has no matching rule (it is an audit signal) but is bound so
# the whole DoS event surface flows through one gated path.
_DOS_EVENT_TYPES: frozenset[str] = frozenset({
    "dos.http_flood",
    "dos.distributed",
    "dos.expensive_abuse",
    "dos.slowloris",
    "dos.under_attack",
    "dos.ip_blocked",
})

# ---------------------------------------------------------------------------
# Default confidence factor catalog
# ---------------------------------------------------------------------------
# Calling code (apply_confidence_factors) multiplies the base severity score
# by the product of all matching factor weights. A factor with weight 0 is a
# "drop" signal — the rule is suppressed entirely (used for safelist hits).
DEFAULT_CONFIDENCE_FACTORS: list[dict] = [
    {"factor": "scanner_ua",            "weight": 1.3},
    {"factor": "tor_exit",              "weight": 1.5},
    {"factor": "known_attacker_history","weight": 2.0},
    {"factor": "geo_high_risk",         "weight": 1.2},
    {"factor": "burst_rate",            "weight": 1.4},
    {"factor": "safelisted",            "weight": 0.0},  # drop
    {"factor": "internal_ip",           "weight": 0.0},  # drop
]

# Severity ladder used by apply_confidence_factors
_SEVERITY_SCORE = {"low": 1.0, "medium": 2.0, "high": 3.0, "critical": 4.0}
_SCORE_SEVERITY = [(4.0, "critical"), (2.75, "high"), (1.75, "medium"), (0.0, "low")]


def apply_confidence_factors(rule: dict, event_context: dict) -> tuple[str, float]:
    """Return (adjusted_severity, multiplier) for a triggered rule.

    `event_context` is a dict where keys are factor names (as listed in the
    rule's confidence_factors) and values are booleans indicating whether the
    factor applies. A True value with weight=0 drops the alert (severity is
    returned as 'suppressed').
    """
    base = rule.get("severity", "medium")
    factors = rule.get("confidence_factors") or DEFAULT_CONFIDENCE_FACTORS
    multiplier = 1.0
    for f in factors:
        name = f.get("factor")
        weight = f.get("weight", 1.0)
        if event_context.get(name):
            if weight == 0:
                return ("suppressed", 0.0)
            multiplier *= weight
    score = _SEVERITY_SCORE.get(base, 2.0) * multiplier
    for threshold, label in _SCORE_SEVERITY:
        if score >= threshold:
            return (label, multiplier)
    return ("low", multiplier)


# ---------------------------------------------------------------------------
# Built-in Sigma-style rules  (10+ covering common attack patterns)
# v1.6.4 — protocol-aware brute-force split, per-rule cooldowns,
# confidence_factors scoring, composite group_by support.
# ---------------------------------------------------------------------------

BUILT_IN_RULES: list[dict] = [
    # 1a — HTTP auth brute force (split from legacy brute_force_ssh)
    # Listens only on the dedicated http_auth_failure stream so we don't
    # conflate SSH protocol failures with web 401s anymore.
    {
        "id": "http_auth_brute_force",
        "title": "HTTP Authentication Brute Force",
        "description": "15+ HTTP 401 responses from the same source IP within 60s, excluding operator dashboard/login polling paths. Tagged scanner_ua/tor_exit/known_attacker_history factors boost severity.",
        "severity": "high",
        "enabled": True,
        "source": "builtin",
        "mitre": ["T1110"],
        "confidence_factors": [
            {"factor": "scanner_ua",             "weight": 1.3},
            {"factor": "tor_exit",               "weight": 1.5},
            {"factor": "known_attacker_history", "weight": 2.0},
            {"factor": "safelisted",             "weight": 0.0},
        ],
        "condition": {
            "event_type": "http_auth_failure",
            "count_threshold": 15,
            "time_window_seconds": 60,
            "group_by": ["source_ip"],
            "cooldown_seconds": COOLDOWN_AUTH,
            "filter": {
                "path_excludes": [
                    "/api/v1/auth/",
                    "/api/v1/auth/me",
                    "/api/v1/auth/refresh",
                    "/api/v1/auth/logout",
                    "/api/v1/auth/session",
                    "/api/v1/dashboard/",
                    "/dashboard/",
                    "/login",
                    "/ws",
                    "/api/v1/health",
                    "/api/v1/me",
                    "/api/v1/version",
                ],
            },
        },
    },
    # 1b — SSH honeypot hit (split from legacy brute_force_ssh)
    # Any SSH attempt against the honeypot port is a high-signal event by
    # definition — no legitimate user should ever be on 2222. We fire on
    # every event (threshold=1) with no cooldown.
    {
        "id": "ssh_honeypot_attempt",
        "title": "SSH Honeypot Authentication Attempt",
        "description": "Single SSH login attempt against the honeypot (port 2222). No legitimate user should ever interact with this surface, so every event is alert-worthy. No cooldown — burst dedup is handled downstream.",
        "severity": "critical",
        "enabled": True,
        "source": "builtin",
        "mitre": ["T1110", "T1078"],
        "confidence_factors": [
            {"factor": "tor_exit",               "weight": 1.5},
            {"factor": "known_attacker_history", "weight": 2.0},
            {"factor": "internal_ip",            "weight": 0.0},
        ],
        "condition": {
            "event_type": "ssh_honeypot_failure",
            "count_threshold": 1,
            "time_window_seconds": 60,
            "group_by": ["source_ip"],
            "cooldown_seconds": COOLDOWN_HONEYPOT,
        },
    },
    # 1c — Generic credential attack (fallback aggregator)
    # Catches any auth_failure event type not covered by the protocol-specific
    # rules above. Behaves like the historical brute_force_ssh and is the
    # rule referenced by CHAIN_RULES + CampaignTracker for backward compat.
    {
        "id": "generic_credential_attack",
        "title": "Generic Credential Attack",
        "description": "Fallback rule: 25 generic auth_failure events from same source in 300s. Triggers when neither HTTP nor SSH honeypot specific rules match (e.g. FTP/SMTP/RDP without a service tag).",
        "severity": "medium",
        "enabled": True,
        "source": "builtin",
        "mitre": ["T1110"],
        "confidence_factors": [
            {"factor": "scanner_ua",             "weight": 1.3},
            {"factor": "tor_exit",               "weight": 1.5},
            {"factor": "known_attacker_history", "weight": 2.0},
            {"factor": "burst_rate",             "weight": 1.4},
            {"factor": "safelisted",             "weight": 0.0},
            {"factor": "internal_ip",            "weight": 0.0},
        ],
        "condition": {
            "event_type": "auth_failure",
            "count_threshold": 25,
            "time_window_seconds": 300,
            "group_by": ["source_ip"],
            "cooldown_seconds": COOLDOWN_AUTH,
            "filter": {
                "path_excludes": [
                    "/api/v1/auth/",
                    "/api/v1/auth/me",
                    "/api/v1/auth/refresh",
                    "/api/v1/auth/logout",
                    "/api/v1/auth/session",
                    "/api/v1/dashboard/",
                    "/dashboard/",
                    "/login",
                    "/ws",
                    "/api/v1/health",
                    "/api/v1/me",
                    "/api/v1/version",
                ],
            },
        },
    },
    # 1d — Legacy alias preserved for chains / phase map (DISABLED, kept for ID lookup)
    # The historical brute_force_ssh rule is intentionally retained with
    # enabled=False so that CHAIN_RULES, _PHASE_MAP and any operator dashboards
    # referencing it by name don't break. New event handling routes through
    # the three rules above.
    {
        "id": "brute_force_ssh",
        "title": "[DEPRECATED] Auth Brute Force — replaced by http_auth_brute_force / ssh_honeypot_attempt / generic_credential_attack",
        "description": "v1.6.4: superseded by protocol-aware split. Disabled by default; only kept so chain rules and PHASE_MAP lookups continue to resolve. To re-enable for backwards compat, set enabled=True via /api/v1/correlation/rules.",
        "severity": "high",
        "enabled": False,
        "source": "builtin",
        "mitre": ["T1110"],
        "condition": {
            "event_type": "auth_failure",
            "count_threshold": 15,
            "time_window_seconds": 300,
            "group_by": ["source_ip"],
            "cooldown_seconds": COOLDOWN_AUTH,
        },
    },
    # 2 — Lateral movement
    {
        "id": "lateral_movement",
        "title": "Lateral Movement Detected",
        "description": "Internal host accessing multiple internal services rapidly.",
        "severity": "critical",
        "enabled": True,
        "source": "builtin",
        "mitre": ["T1021"],
        "condition": {
            "event_type": "connection",
            "count_threshold": 10,
            "time_window_seconds": 60,
            "group_by": "source_ip",
            "filter": {"target_type": "internal"},
        },
    },
    # 3 — Data exfiltration
    {
        "id": "data_exfiltration",
        "title": "Possible Data Exfiltration",
        "description": "Large outbound data transfer to external IP.",
        "severity": "critical",
        "enabled": True,
        "source": "builtin",
        "mitre": ["T1041"],
        "condition": {
            "event_type": "network",
            "filter": {"direction": "outbound", "bytes_gt": 104_857_600},
        },
    },
    # 4 — Credential stuffing
    {
        "id": "credential_stuffing",
        "title": "Credential Stuffing Attack",
        "description": "Multiple failed logins with different usernames from same IP.",
        "severity": "high",
        "enabled": True,
        "source": "builtin",
        "mitre": ["T1110.004"],
        "condition": {
            "event_type": "auth_failure",
            "count_threshold": 10,
            "time_window_seconds": 120,
            "group_by": "source_ip",
            "unique_field": "username",
        },
    },
    # 5 — Port scan
    {
        "id": "port_scan",
        "title": "Port Scan Detected",
        "description": "Single IP probing multiple ports.",
        "severity": "medium",
        "enabled": True,
        "source": "builtin",
        "mitre": ["T1046"],
        "condition": {
            "event_type": "connection",
            "count_threshold": 20,
            "time_window_seconds": 60,
            "group_by": "source_ip",
            "unique_field": "target_port",
        },
    },
    # 6 — SQL injection chain
    {
        "id": "sql_injection_chain",
        "title": "SQL Injection Attack Chain",
        "description": "Multiple SQLi patterns from the same source.",
        "severity": "critical",
        "enabled": True,
        "source": "builtin",
        "mitre": ["T1190"],
        "condition": {
            "event_type": "sql_injection",
            "count_threshold": 3,
            "time_window_seconds": 300,
            "group_by": "source_ip",
        },
    },
    # 7 — RDP brute-force
    {
        "id": "rdp_brute_force",
        "title": "RDP Brute Force Detected",
        "description": "Multiple failed RDP authentication attempts from same IP.",
        "severity": "high",
        "enabled": True,
        "source": "builtin",
        "mitre": ["T1110.003"],
        "condition": {
            "event_type": "auth_failure",
            "count_threshold": 8,
            "time_window_seconds": 180,
            "group_by": "source_ip",
            "filter": {"service": "rdp"},
        },
    },
    # 8 — DNS tunneling
    {
        "id": "dns_tunneling",
        "title": "Possible DNS Tunneling",
        "description": "Unusually high volume of DNS queries from a single host.",
        "severity": "high",
        "enabled": True,
        "source": "builtin",
        "mitre": ["T1071.004"],
        "condition": {
            "event_type": "dns_query",
            "count_threshold": 100,
            "time_window_seconds": 60,
            "group_by": "source_ip",
        },
    },
    # 9 — C2 beacon (regular periodic connections)
    {
        "id": "c2_beacon",
        "title": "C2 Beacon Pattern Detected",
        "description": "Periodic outbound connections suggesting command-and-control beaconing.",
        "severity": "critical",
        "enabled": True,
        "source": "builtin",
        "mitre": ["T1071"],
        "condition": {
            "event_type": "connection",
            "count_threshold": 5,
            "time_window_seconds": 300,
            "group_by": "source_ip",
            "filter": {"direction": "outbound", "target_type": "external"},
            "unique_field": "destination_ip",
        },
    },
    # 10 — Web shell activity
    {
        "id": "web_shell_activity",
        "title": "Web Shell Activity Detected",
        "description": "Suspicious HTTP requests consistent with web shell usage.",
        "severity": "critical",
        "enabled": True,
        "source": "builtin",
        "mitre": ["T1505.003"],
        "condition": {
            "event_type": "http_request",
            "count_threshold": 3,
            "time_window_seconds": 120,
            "group_by": "source_ip",
            "filter": {"method": "POST", "path_contains": [".php", ".asp", ".jsp"]},
        },
    },
    # 11 — Privilege escalation attempts
    {
        "id": "privilege_escalation",
        "title": "Privilege Escalation Attempt",
        "description": "Multiple privilege escalation attempts detected.",
        "severity": "critical",
        "enabled": True,
        "source": "builtin",
        "mitre": ["T1068"],
        "condition": {
            "event_type": "priv_escalation",
            "count_threshold": 2,
            "time_window_seconds": 300,
            "group_by": "source_ip",
        },
    },
    # 12 — XSS attack chain
    {
        "id": "xss_attack_chain",
        "title": "XSS Attack Chain",
        "description": "Multiple cross-site scripting attempts from same source.",
        "severity": "high",
        "enabled": True,
        "source": "builtin",
        "mitre": ["T1059.007"],
        "condition": {
            "event_type": "xss",
            "count_threshold": 5,
            "time_window_seconds": 300,
            "group_by": "source_ip",
        },
    },

    # ===================================================================
    # SIGMA RULES LIBRARY — 100+ rules organized by MITRE ATT&CK category
    # ===================================================================

    # -------------------------------------------------------------------
    # CATEGORY 1: AUTHENTICATION (15 rules)
    # -------------------------------------------------------------------

    # 13 — Account lockout detection
    # v1.6.4: DISABLED — duplicate of generic_credential_attack. The previous
    # group_by=username variant fired on a single user typing the wrong
    # password repeatedly (caps-lock, wrong keymap) and produced FP spam.
    # Kept for ID stability.
    {
        "id": "sigma_auth_account_lockout",
        "title": "[DEPRECATED] Account Lockout — deduped by generic_credential_attack",
        "description": "v1.6.4: Disabled. Username-grouped lockout detection was a duplicate of generic_credential_attack and fired on legitimate single-user mistype storms (keymap / caps-lock).",
        "severity": "medium",
        "enabled": False,
        "source": "sigma",
        "category": "authentication",
        "mitre": ["T1110"],
        "condition": {
            "event_type": "auth_failure",
            "count_threshold": 10,
            "time_window_seconds": 300,
            "group_by": ["username", "source_ip"],
            "cooldown_seconds": COOLDOWN_AUTH,
        },
    },
    # 14 — Password spray attack
    {
        "id": "sigma_auth_password_spray",
        "title": "Password Spray Attack",
        "description": "Same password tried against many accounts from single source.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "authentication",
        "mitre": ["T1110.003"],
        "condition": {
            "event_type": "auth_failure",
            "count_threshold": 15,
            "time_window_seconds": 600,
            "group_by": "source_ip",
            "unique_field": "username",
        },
    },
    # 15 — Kerberos ticket abuse (overpass-the-hash)
    {
        "id": "sigma_auth_kerberos_abuse",
        "title": "Kerberos Ticket Abuse",
        "description": "Suspicious Kerberos authentication patterns indicating ticket abuse.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "authentication",
        "mitre": ["T1558.003"],
        "condition": {
            "event_type": "kerberos_auth",
            "count_threshold": 3,
            "time_window_seconds": 120,
            "group_by": "source_ip",
            "filter": {"encryption_type": "RC4"},
        },
    },
    # 16 — NTLM relay attack
    {
        "id": "sigma_auth_ntlm_relay",
        "title": "NTLM Relay Attack Detected",
        "description": "NTLM authentication from unexpected source suggesting relay.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "authentication",
        "mitre": ["T1557.001"],
        "condition": {
            "event_type": "ntlm_auth",
            "count_threshold": 3,
            "time_window_seconds": 60,
            "group_by": "source_ip",
            "filter": {"target_type": "internal"},
        },
    },
    # 17 — Pass-the-hash
    {
        "id": "sigma_auth_pass_the_hash",
        "title": "Pass-the-Hash Attack",
        "description": "Authentication using NTLM hash without interactive login.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "authentication",
        "mitre": ["T1550.002"],
        "condition": {
            "event_type": "ntlm_auth",
            "count_threshold": 2,
            "time_window_seconds": 60,
            "group_by": "source_ip",
            "filter": {"logon_type": "network"},
        },
    },
    # 18 — Default credentials (v1.6.2: failure-only, removed cloud-init users)
    {
        "id": "sigma_auth_default_credentials",
        "title": "Default Credentials Brute Force Attempt",
        "description": "Failed login attempt using known default credentials (auth_failure only — successful logins by 'pi'/'ubuntu' are legitimate on Pi/cloud-init hosts).",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "authentication",
        "mitre": ["T1078.001", "T1110"],
        "condition": {
            "event_type": "auth_failure",  # v1.6.2: success → failure
            "filter": {"username": ["admin", "root", "test", "guest", "default", "oracle", "postgres", "redis"]},  # v1.6.2: removed pi, ubuntu
            "count_threshold": 3,
            "time_window_seconds": 300,
            "group_by": "source_ip",
        },
    },
    # 19 — SSH key brute force
    {
        "id": "sigma_auth_ssh_key_brute",
        "title": "SSH Key Brute Force",
        "description": "Multiple SSH key authentication failures from same IP.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "authentication",
        "mitre": ["T1110.004"],
        "condition": {
            "event_type": "auth_failure",
            "count_threshold": 20,
            "time_window_seconds": 120,
            "group_by": "source_ip",
            "filter": {"service": "ssh", "auth_method": "publickey"},
        },
    },
    # 20 — FTP brute force
    {
        "id": "sigma_auth_ftp_brute",
        "title": "FTP Brute Force Detected",
        "description": "Multiple failed FTP login attempts from same source.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "authentication",
        "mitre": ["T1110.001"],
        "condition": {
            "event_type": "auth_failure",
            "count_threshold": 10,
            "time_window_seconds": 300,
            "group_by": "source_ip",
            "filter": {"service": "ftp"},
        },
    },
    # 21 — Golden ticket usage
    {
        "id": "sigma_auth_golden_ticket",
        "title": "Golden Ticket Usage Suspected",
        "description": "Kerberos TGT with abnormally long lifetime detected.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "authentication",
        "mitre": ["T1558.001"],
        "condition": {
            "event_type": "kerberos_auth",
            "filter": {"ticket_lifetime_gt": 36000},
        },
    },
    # 22 — Multi-factor authentication bypass attempt
    {
        "id": "sigma_auth_mfa_bypass",
        "title": "MFA Bypass Attempt",
        "description": "Successful auth without MFA after multiple MFA failures.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "authentication",
        "mitre": ["T1556.006"],
        "condition": {
            "event_type": "mfa_failure",
            "count_threshold": 5,
            "time_window_seconds": 300,
            "group_by": "username",
        },
    },
    # 23 — After-hours authentication
    {
        "id": "sigma_auth_after_hours",
        "title": "After-Hours Authentication",
        "description": "Successful authentication outside normal business hours.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "authentication",
        "mitre": ["T1078"],
        "condition": {
            "event_type": "auth_success",
            "filter": {"time_of_day": "off_hours"},
        },
    },
    # 24 — Concurrent sessions from different geolocations
    {
        "id": "sigma_auth_impossible_travel",
        "title": "Impossible Travel - Concurrent Sessions",
        "description": "Same user authenticated from geographically distant locations simultaneously.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "authentication",
        "mitre": ["T1078"],
        "condition": {
            "event_type": "auth_success",
            "count_threshold": 2,
            "time_window_seconds": 300,
            "group_by": "username",
            "unique_field": "geo_country",
        },
    },
    # 25 — SMTP brute force
    {
        "id": "sigma_auth_smtp_brute",
        "title": "SMTP Authentication Brute Force",
        "description": "Multiple failed SMTP authentication attempts.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "authentication",
        "mitre": ["T1110.001"],
        "condition": {
            "event_type": "auth_failure",
            "count_threshold": 10,
            "time_window_seconds": 600,
            "group_by": "source_ip",
            "filter": {"service": "smtp"},
        },
    },
    # 26 — VPN brute force
    {
        "id": "sigma_auth_vpn_brute",
        "title": "VPN Brute Force Detected",
        "description": "Multiple failed VPN authentication attempts from same source.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "authentication",
        "mitre": ["T1110"],
        "condition": {
            "event_type": "auth_failure",
            "count_threshold": 8,
            "time_window_seconds": 300,
            "group_by": "source_ip",
            "filter": {"service": "vpn"},
        },
    },
    # 27 — Service account abuse
    {
        "id": "sigma_auth_service_account_interactive",
        "title": "Service Account Interactive Login",
        "description": "Service account used for interactive login unexpectedly.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "authentication",
        "mitre": ["T1078.003"],
        "condition": {
            "event_type": "auth_success",
            "filter": {"account_type": "service", "logon_type": "interactive"},
        },
    },

    # -------------------------------------------------------------------
    # CATEGORY 2: WEB ATTACKS (15 rules)
    # -------------------------------------------------------------------

    # 28 — SQL injection UNION SELECT
    {
        "id": "sigma_web_sqli_union",
        "title": "SQL Injection - UNION SELECT",
        "description": "Detects UNION SELECT SQL injection attempts in web requests.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "web_attacks",
        "mitre": ["T1190"],
        "condition": {
            "event_type": "web_request",
            "filter": {"path_contains": ["UNION", "SELECT", "union", "select"]},
            "count_threshold": 1,
            "time_window_seconds": 60,
            "group_by": "source_ip",
        },
    },
    # 29 — Blind SQL injection
    {
        "id": "sigma_web_sqli_blind",
        "title": "Blind SQL Injection Attempt",
        "description": "Detects blind SQL injection attempts using boolean/time techniques.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "web_attacks",
        "mitre": ["T1190"],
        "condition": {
            "event_type": "web_request",
            "filter": {"path_contains": ["SLEEP(", "BENCHMARK(", "WAITFOR", "1=1", "1'='1", "OR 1=1"]},
            "count_threshold": 1,
            "time_window_seconds": 60,
            "group_by": "source_ip",
        },
    },
    # 30 — Time-based SQL injection
    {
        "id": "sigma_web_sqli_time",
        "title": "Time-Based SQL Injection",
        "description": "Detects time-based blind SQL injection via slow response patterns.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "web_attacks",
        "mitre": ["T1190"],
        "condition": {
            "event_type": "web_request",
            "filter": {"path_contains": ["SLEEP", "pg_sleep", "DBMS_PIPE", "WAITFOR DELAY"]},
            "count_threshold": 2,
            "time_window_seconds": 120,
            "group_by": "source_ip",
        },
    },
    # 31 — Reflected XSS
    {
        "id": "sigma_web_xss_reflected",
        "title": "Reflected XSS Attempt",
        "description": "Detects reflected cross-site scripting payloads in URL parameters.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "web_attacks",
        "mitre": ["T1059.007"],
        "condition": {
            "event_type": "web_request",
            "filter": {"path_contains": ["<script", "javascript:", "onerror=", "onload=", "alert("]},
            "count_threshold": 1,
            "time_window_seconds": 60,
            "group_by": "source_ip",
        },
    },
    # 32 — Stored XSS
    {
        "id": "sigma_web_xss_stored",
        "title": "Stored XSS Attempt",
        "description": "Detects stored XSS via POST requests with script payloads.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "web_attacks",
        "mitre": ["T1059.007"],
        "condition": {
            "event_type": "web_request",
            "filter": {"method": "POST", "path_contains": ["<script", "<img", "<svg", "onmouseover="]},
            "count_threshold": 1,
            "time_window_seconds": 60,
            "group_by": "source_ip",
        },
    },
    # 33 — CSRF attack
    {
        "id": "sigma_web_csrf",
        "title": "CSRF Attack Detected",
        "description": "Cross-site request forgery detected via missing/invalid CSRF token.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "web_attacks",
        "mitre": ["T1189"],
        "condition": {
            "event_type": "web_request",
            "filter": {"csrf_valid": False, "method": "POST"},
            "count_threshold": 5,
            "time_window_seconds": 120,
            "group_by": "source_ip",
        },
    },
    # 34 — Path traversal
    {
        "id": "sigma_web_path_traversal",
        "title": "Path Traversal Attack",
        "description": "Directory traversal attempt to access files outside web root.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "web_attacks",
        "mitre": ["T1083"],
        "condition": {
            "event_type": "web_request",
            "filter": {"path_contains": ["../", "..\\", "%2e%2e", "/etc/passwd", "/etc/shadow"]},
            "count_threshold": 1,
            "time_window_seconds": 60,
            "group_by": "source_ip",
        },
    },
    # 35 — Command injection
    {
        "id": "sigma_web_command_injection",
        "title": "OS Command Injection",
        "description": "Detects OS command injection patterns in web requests.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "web_attacks",
        "mitre": ["T1059"],
        "condition": {
            "event_type": "web_request",
            "filter": {"path_contains": ["; ls", "| cat", "&& whoami", "`id`", "$(id)", "; curl"]},
            "count_threshold": 1,
            "time_window_seconds": 60,
            "group_by": "source_ip",
        },
    },
    # 36 — SSRF
    {
        "id": "sigma_web_ssrf",
        "title": "Server-Side Request Forgery (SSRF)",
        "description": "Detects SSRF attempts targeting internal resources or cloud metadata.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "web_attacks",
        "mitre": ["T1190"],
        "condition": {
            "event_type": "web_request",
            "filter": {"path_contains": ["169.254.169.254", "localhost", "127.0.0.1", "0.0.0.0", "metadata.google"]},
            "count_threshold": 1,
            "time_window_seconds": 60,
            "group_by": "source_ip",
        },
    },
    # 37 — Malicious file upload
    {
        "id": "sigma_web_file_upload",
        "title": "Malicious File Upload Attempt",
        "description": "Upload of potentially malicious file types detected.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "web_attacks",
        "mitre": ["T1505.003"],
        "condition": {
            "event_type": "web_request",
            "filter": {"method": "POST", "path_contains": [".php", ".jsp", ".aspx", ".sh", ".exe", ".phtml"]},
            "count_threshold": 1,
            "time_window_seconds": 300,
            "group_by": "source_ip",
        },
    },
    # 38 — XXE injection (v1.6.2: multi-token markers, no bare "SYSTEM")
    {
        "id": "sigma_web_xxe",
        "title": "XML External Entity (XXE) Injection",
        "description": "Detects XXE injection in XML request bodies. v1.6.2: requires multi-token markers (not bare 'SYSTEM') eliminating FPs from legitimate paths like /admin/system-info.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "web_attacks",
        "mitre": ["T1190"],
        "condition": {
            "event_type": "web_request",
            "filter": {"path_contains": ["<!ENTITY SYSTEM", "<!DOCTYPE", "PUBLIC \"-//", "SYSTEM \"file:", "SYSTEM \"http:", "SYSTEM \"expect:"]},
            "count_threshold": 1,
            "time_window_seconds": 60,
            "group_by": "source_ip",
        },
    },
    # 39 — Open redirect
    {
        "id": "sigma_web_open_redirect",
        "title": "Open Redirect Attempt",
        "description": "Detects open redirect abuse via URL parameters.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "web_attacks",
        "mitre": ["T1189"],
        "condition": {
            "event_type": "web_request",
            "filter": {"path_contains": ["redirect=http", "url=http", "next=http", "return_to=http"]},
            "count_threshold": 3,
            "time_window_seconds": 120,
            "group_by": "source_ip",
        },
    },
    # 40 — Insecure deserialization
    {
        "id": "sigma_web_deserialization",
        "title": "Insecure Deserialization Attack",
        "description": "Detects serialized object injection attempts.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "web_attacks",
        "mitre": ["T1190"],
        "condition": {
            "event_type": "web_request",
            "filter": {"path_contains": ["rO0AB", "O:4:", "a:2:{", "aced0005"]},
            "count_threshold": 1,
            "time_window_seconds": 60,
            "group_by": "source_ip",
        },
    },
    # 41 — HTTP request smuggling
    # v1.6.4: threshold raised 1→3 in 60s, composite group_by, explicit
    # cooldown=COOLDOWN_EXPLOIT to suppress legitimate proxy double-headers.
    {
        "id": "sigma_web_request_smuggling",
        "title": "HTTP Request Smuggling (TE.CL desync)",
        "description": "Detects HTTP request smuggling via conflicting Transfer-Encoding/Content-Length headers. v1.6.4 raised threshold to 3 simultaneous offenders to suppress legitimate reverse-proxy normalisation.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "web_attacks",
        "mitre": ["T1190"],
        "confidence_factors": [
            {"factor": "scanner_ua",             "weight": 1.5},
            {"factor": "known_attacker_history", "weight": 2.0},
            {"factor": "safelisted",             "weight": 0.0},
            {"factor": "internal_ip",            "weight": 0.0},
        ],
        "condition": {
            "event_type": "web_request",
            "filter": {"path_contains_all": ["Transfer-Encoding:", "Content-Length:"]},
            "count_threshold": 3,
            "time_window_seconds": 60,
            "group_by": ["source_ip", "request_path"],
            "cooldown_seconds": COOLDOWN_EXPLOIT,
        },
    },
    # 42 — API abuse / enumeration
    # v1.6.4: threshold raised 50→120 unique paths; composite group_by so
    # an attacker who probes ANY API path is grouped per (ip,target_port),
    # not flooded per-endpoint. cooldown=COOLDOWN_RECON.
    {
        "id": "sigma_web_api_abuse",
        "title": "API Endpoint Enumeration",
        "description": "Rapid unique-path requests to /api/* suggesting enumeration. v1.6.4 raised threshold to 120 and excluded /health, /metrics, /version, /me probes to suppress legitimate SPA polling.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "web_attacks",
        "mitre": ["T1190"],
        "confidence_factors": [
            {"factor": "scanner_ua",             "weight": 1.5},
            {"factor": "known_attacker_history", "weight": 2.0},
            {"factor": "safelisted",             "weight": 0.0},
            {"factor": "internal_ip",            "weight": 0.0},
        ],
        "condition": {
            "event_type": "web_request",
            "filter": {
                "path_contains": ["/api/"],
                "path_excludes": ["/api/v1/health", "/api/v1/metrics", "/api/v1/version", "/api/v1/me"],
            },
            "count_threshold": 120,
            "time_window_seconds": 60,
            "group_by": ["source_ip", "target_port"],
            "unique_field": "path",
            "cooldown_seconds": COOLDOWN_RECON,
        },
    },
    # 43 — v1.6.2: Coordinated /29 campaign (3+ sibling IPs from same /29 hitting same threat_type)
    {
        "id": "sigma_campaign_cidr_cluster",
        "title": "Coordinated /29 Campaign Detected",
        "description": "v1.6.2: 3+ source IPs from the same /29 CIDR block firing the same threat_type within 1 hour. Indicates a coordinated infrastructure campaign (rented VPS cluster, botnet, or APT) rather than single-IP brute force. Auto-escalates to CRITICAL and triggers /29 CIDR blocking.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "campaign",
        "mitre": ["T1583.003", "T1090"],
        "condition": {
            "event_type": "incident_emitted",
            "count_threshold": 3,
            "time_window_seconds": 3600,
            "group_by": "source_cidr_29",
            "unique_field": "source_ip",
        },
    },

    # -------------------------------------------------------------------
    # CATEGORY 3: LATERAL MOVEMENT (10 rules)
    # -------------------------------------------------------------------

    # 43 — SMB enumeration
    {
        "id": "sigma_lateral_smb_enum",
        "title": "SMB Share Enumeration",
        "description": "Multiple SMB share access attempts suggesting network enumeration.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "lateral_movement",
        "mitre": ["T1021.002"],
        "condition": {
            "event_type": "smb_access",
            "count_threshold": 5,
            "time_window_seconds": 120,
            "group_by": "source_ip",
            "unique_field": "share_name",
        },
    },
    # 44 — WMI remote execution
    {
        "id": "sigma_lateral_wmi_exec",
        "title": "WMI Remote Execution",
        "description": "Remote process creation via WMI detected.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "lateral_movement",
        "mitre": ["T1047"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"parent_process": "wmiprvse.exe"},
        },
    },
    # 45 — PsExec usage
    {
        "id": "sigma_lateral_psexec",
        "title": "PsExec Remote Execution",
        "description": "PsExec service installation or usage detected on remote host.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "lateral_movement",
        "mitre": ["T1569.002"],
        "condition": {
            "event_type": "service_install",
            "filter": {"service_name": ["PSEXESVC", "psexec"]},
        },
    },
    # 46 — RDP pivoting
    {
        "id": "sigma_lateral_rdp_pivot",
        "title": "RDP Lateral Pivot",
        "description": "RDP connection from internal host to multiple internal targets.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "lateral_movement",
        "mitre": ["T1021.001"],
        "condition": {
            "event_type": "connection",
            "count_threshold": 3,
            "time_window_seconds": 300,
            "group_by": "source_ip",
            "unique_field": "destination_ip",
            "filter": {"destination_port": 3389, "target_type": "internal"},
        },
    },
    # 47 — SSH tunneling
    {
        "id": "sigma_lateral_ssh_tunnel",
        "title": "SSH Tunneling Detected",
        "description": "SSH connection with port forwarding flags detected.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "lateral_movement",
        "mitre": ["T1572"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["ssh", "-L", "-R", "-D"]},
        },
    },
    # 48 — Port forwarding
    {
        "id": "sigma_lateral_port_forward",
        "title": "Port Forwarding Detected",
        "description": "Local or remote port forwarding established.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "lateral_movement",
        "mitre": ["T1572"],
        "condition": {
            "event_type": "network",
            "filter": {"port_forward": True},
        },
    },
    # 49 — DCOM remote execution
    {
        "id": "sigma_lateral_dcom",
        "title": "DCOM Remote Execution",
        "description": "Process creation via DCOM lateral movement technique.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "lateral_movement",
        "mitre": ["T1021.003"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"parent_process": "mmc.exe", "path_contains": ["excel.exe", "powershell.exe"]},
        },
    },
    # 50 — WinRM lateral movement
    {
        "id": "sigma_lateral_winrm",
        "title": "WinRM Lateral Movement",
        "description": "Remote command execution via WinRM/PowerShell Remoting.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "lateral_movement",
        "mitre": ["T1021.006"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"parent_process": "wsmprovhost.exe"},
        },
    },
    # 51 — Internal port scan
    {
        "id": "sigma_lateral_internal_scan",
        "title": "Internal Network Port Scan",
        "description": "Internal host scanning other internal hosts on multiple ports.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "lateral_movement",
        "mitre": ["T1046"],
        "condition": {
            "event_type": "connection",
            "count_threshold": 15,
            "time_window_seconds": 60,
            "group_by": "source_ip",
            "unique_field": "destination_ip",
            "filter": {"target_type": "internal"},
        },
    },
    # 52 — ARP spoofing
    {
        "id": "sigma_lateral_arp_spoof",
        "title": "ARP Spoofing Detected",
        "description": "Gratuitous ARP packets suggesting ARP cache poisoning.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "lateral_movement",
        "mitre": ["T1557.002"],
        "condition": {
            "event_type": "arp_anomaly",
            "count_threshold": 5,
            "time_window_seconds": 30,
            "group_by": "source_mac",
        },
    },

    # -------------------------------------------------------------------
    # CATEGORY 4: PERSISTENCE (10 rules)
    # -------------------------------------------------------------------

    # 53 — Cron job creation
    {
        "id": "sigma_persist_cron",
        "title": "Suspicious Cron Job Created",
        "description": "New cron job created with potentially malicious command.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "persistence",
        "mitre": ["T1053.003"],
        "condition": {
            "event_type": "file_modification",
            "filter": {"path_contains": ["/etc/crontab", "/var/spool/cron", "/etc/cron.d"]},
        },
    },
    # 54 — Systemd service creation
    {
        "id": "sigma_persist_systemd",
        "title": "Suspicious Systemd Service Created",
        "description": "New systemd service unit file created or modified.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "persistence",
        "mitre": ["T1543.002"],
        "condition": {
            "event_type": "file_modification",
            "filter": {"path_contains": ["/etc/systemd/system/", "/lib/systemd/system/"]},
        },
    },
    # 55 — Registry Run key (Windows persistence)
    {
        "id": "sigma_persist_registry_run",
        "title": "Registry Run Key Persistence",
        "description": "Modification of Windows registry Run key for persistence.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "persistence",
        "mitre": ["T1547.001"],
        "condition": {
            "event_type": "registry_modification",
            "filter": {"path_contains": ["\\Run", "\\RunOnce"]},
        },
    },
    # 56 — Scheduled task creation (Windows)
    {
        "id": "sigma_persist_scheduled_task",
        "title": "Scheduled Task Created",
        "description": "New scheduled task created via schtasks or Task Scheduler.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "persistence",
        "mitre": ["T1053.005"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["schtasks", "/create"]},
        },
    },
    # 57 — SSH authorized_keys modification
    {
        "id": "sigma_persist_ssh_keys",
        "title": "SSH Authorized Keys Modified",
        "description": "Modification of SSH authorized_keys file for persistent access.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "persistence",
        "mitre": ["T1098.004"],
        "condition": {
            "event_type": "file_modification",
            "filter": {"path_contains": ["authorized_keys"]},
        },
    },
    # 58 — Web shell deployment
    {
        "id": "sigma_persist_webshell",
        "title": "Web Shell File Deployed",
        "description": "Suspicious script file created in web-accessible directory.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "persistence",
        "mitre": ["T1505.003"],
        "condition": {
            "event_type": "file_creation",
            "filter": {"path_contains": ["/var/www/", "/public_html/", "wwwroot", ".php", ".jsp", ".aspx"]},
        },
    },
    # 59 — Startup folder persistence (Windows)
    {
        "id": "sigma_persist_startup_folder",
        "title": "Startup Folder Persistence",
        "description": "File placed in Windows Startup folder for automatic execution.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "persistence",
        "mitre": ["T1547.001"],
        "condition": {
            "event_type": "file_creation",
            "filter": {"path_contains": ["\\Start Menu\\Programs\\Startup", "\\Startup\\"]},
        },
    },
    # 60 — Login hook (macOS)
    {
        "id": "sigma_persist_login_hook",
        "title": "macOS Login Hook Persistence",
        "description": "Login or logout hook configured for persistence on macOS.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "persistence",
        "mitre": ["T1037.002"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["defaults write", "LoginHook", "LogoutHook"]},
        },
    },
    # 61 — Launch Agent/Daemon (macOS)
    {
        "id": "sigma_persist_launch_agent",
        "title": "macOS Launch Agent/Daemon Created",
        "description": "New LaunchAgent or LaunchDaemon plist created on macOS.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "persistence",
        "mitre": ["T1543.001"],
        "condition": {
            "event_type": "file_creation",
            "filter": {"path_contains": ["/LaunchAgents/", "/LaunchDaemons/"]},
        },
    },
    # 62 — Init script modification
    {
        "id": "sigma_persist_init_script",
        "title": "Init Script Modified",
        "description": "System init script modified for persistence.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "persistence",
        "mitre": ["T1037.004"],
        "condition": {
            "event_type": "file_modification",
            "filter": {"path_contains": ["/etc/init.d/", "/etc/rc.local", "/etc/rc.d/"]},
        },
    },

    # -------------------------------------------------------------------
    # CATEGORY 5: PRIVILEGE ESCALATION (10 rules)
    # -------------------------------------------------------------------

    # 63 — SUID binary abuse
    {
        "id": "sigma_privesc_suid",
        "title": "SUID Binary Exploitation",
        "description": "Execution of uncommon SUID binary suggesting privilege escalation.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "privilege_escalation",
        "mitre": ["T1548.001"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"suid": True, "path_contains": ["find", "vim", "nmap", "python", "perl"]},
        },
    },
    # 64 — Sudo misconfiguration exploitation
    {
        "id": "sigma_privesc_sudo_abuse",
        "title": "Sudo Misconfiguration Exploitation",
        "description": "Exploitation of permissive sudo rules to gain root access.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "privilege_escalation",
        "mitre": ["T1548.003"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["sudo", "-u root", "NOPASSWD"]},
            "count_threshold": 3,
            "time_window_seconds": 60,
            "group_by": "username",
        },
    },
    # 65 — Kernel exploit attempt
    {
        "id": "sigma_privesc_kernel_exploit",
        "title": "Kernel Exploit Attempt",
        "description": "Suspicious binary execution patterns consistent with kernel exploitation.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "privilege_escalation",
        "mitre": ["T1068"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["/tmp/", "exploit", "pwn", "dirty"]},
        },
    },
    # 66 — Service account privilege abuse
    {
        "id": "sigma_privesc_service_account",
        "title": "Service Account Privilege Abuse",
        "description": "Service account performing actions beyond normal scope.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "privilege_escalation",
        "mitre": ["T1078.003"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"account_type": "service", "path_contains": ["cmd.exe", "powershell", "/bin/bash"]},
        },
    },
    # 67 — Token manipulation
    {
        "id": "sigma_privesc_token_manipulation",
        "title": "Access Token Manipulation",
        "description": "Token impersonation or theft for privilege escalation.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "privilege_escalation",
        "mitre": ["T1134"],
        "condition": {
            "event_type": "token_manipulation",
            "count_threshold": 1,
            "time_window_seconds": 60,
            "group_by": "source_ip",
        },
    },
    # 68 — DLL hijacking
    {
        "id": "sigma_privesc_dll_hijack",
        "title": "DLL Hijacking Attempt",
        "description": "DLL loaded from unexpected path suggesting DLL hijacking.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "privilege_escalation",
        "mitre": ["T1574.001"],
        "condition": {
            "event_type": "dll_load",
            "filter": {"path_contains": ["\\Temp\\", "\\Downloads\\", "\\AppData\\"]},
        },
    },
    # 69 — Named pipe impersonation
    {
        "id": "sigma_privesc_named_pipe",
        "title": "Named Pipe Impersonation",
        "description": "Named pipe created for token impersonation.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "privilege_escalation",
        "mitre": ["T1134.001"],
        "condition": {
            "event_type": "pipe_creation",
            "filter": {"path_contains": ["\\\\.\\pipe\\", "ImpersonateNamedPipeClient"]},
        },
    },
    # 70 — Unquoted service path exploitation
    {
        "id": "sigma_privesc_unquoted_path",
        "title": "Unquoted Service Path Exploitation",
        "description": "Executable placed in path to exploit unquoted service path vulnerability.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "privilege_escalation",
        "mitre": ["T1574.009"],
        "condition": {
            "event_type": "file_creation",
            "filter": {"path_contains": ["Program.exe", "Common.exe"]},
        },
    },
    # 71 — Setuid/setgid bit modification
    {
        "id": "sigma_privesc_setuid_change",
        "title": "SUID/SGID Bit Modified",
        "description": "File permissions changed to add SUID or SGID bit.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "privilege_escalation",
        "mitre": ["T1548.001"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["chmod", "+s", "4755", "2755"]},
        },
    },
    # 72 — Capability abuse (Linux)
    {
        "id": "sigma_privesc_capabilities",
        "title": "Linux Capability Abuse",
        "description": "Binary with dangerous capabilities executed for privilege escalation.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "privilege_escalation",
        "mitre": ["T1548"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["cap_setuid", "cap_sys_admin", "setcap"]},
        },
    },

    # -------------------------------------------------------------------
    # CATEGORY 6: DATA EXFILTRATION (10 rules)
    # -------------------------------------------------------------------

    # 73 — Large outbound data transfer
    {
        "id": "sigma_exfil_large_transfer",
        "title": "Large Outbound Data Transfer",
        "description": "Unusually large data transfer to external destination.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "data_exfiltration",
        "mitre": ["T1048"],
        "condition": {
            "event_type": "network",
            "filter": {"direction": "outbound", "bytes_gt": 52_428_800, "target_type": "external"},
        },
    },
    # 74 — DNS data exfiltration
    # v1.6.4: query_length_gt raised 50→180 (matches real base64-encoded
    # exfil payloads, not legitimate long SaaS subdomains). Composite
    # group_by so legitimate resolver caching doesn't mask attacker host.
    {
        "id": "sigma_exfil_dns",
        "title": "DNS Data Exfiltration",
        "description": "Large/encoded DNS queries (>=180 chars) suggesting data exfiltration via DNS. v1.6.4 raised length threshold from 50 to 180 to eliminate FPs from legitimate long subdomain chains.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "data_exfiltration",
        "mitre": ["T1048.003"],
        "confidence_factors": [
            {"factor": "tor_exit",               "weight": 1.5},
            {"factor": "known_attacker_history", "weight": 2.0},
            {"factor": "safelisted",             "weight": 0.0},
        ],
        "condition": {
            "event_type": "dns_query",
            "count_threshold": 50,
            "time_window_seconds": 60,
            "group_by": ["source_ip"],
            "filter": {"query_length_gt": 180},
            "cooldown_seconds": COOLDOWN_EXFIL,
        },
    },
    # 75 — HTTPS to uncommon port
    {
        "id": "sigma_exfil_uncommon_port",
        "title": "HTTPS on Uncommon Port",
        "description": "TLS traffic on non-standard port suggesting covert channel.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "data_exfiltration",
        "mitre": ["T1571"],
        "condition": {
            "event_type": "connection",
            "filter": {"protocol": "tls", "target_type": "external"},
            "count_threshold": 5,
            "time_window_seconds": 300,
            "group_by": "source_ip",
        },
    },
    # 76 — Cloud storage upload
    {
        "id": "sigma_exfil_cloud_upload",
        "title": "Cloud Storage Upload Detected",
        "description": "Data upload to cloud storage services detected.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "data_exfiltration",
        "mitre": ["T1567.002"],
        "condition": {
            "event_type": "web_request",
            "filter": {"path_contains": ["s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net", "dropbox.com", "drive.google.com"]},
            "count_threshold": 3,
            "time_window_seconds": 300,
            "group_by": "source_ip",
        },
    },
    # 77 — Email attachment spike
    {
        "id": "sigma_exfil_email_spike",
        "title": "Email Attachment Spike",
        "description": "Unusual volume of email with attachments from single user.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "data_exfiltration",
        "mitre": ["T1048.002"],
        "condition": {
            "event_type": "email_sent",
            "count_threshold": 20,
            "time_window_seconds": 300,
            "group_by": "sender",
            "filter": {"has_attachment": True},
        },
    },
    # 78 — USB storage mount
    {
        "id": "sigma_exfil_usb",
        "title": "USB Storage Device Mounted",
        "description": "USB mass storage device connected and mounted.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "data_exfiltration",
        "mitre": ["T1052.001"],
        "condition": {
            "event_type": "device_connect",
            "filter": {"device_type": "usb_storage"},
        },
    },
    # 79 — Archive creation before transfer
    {
        "id": "sigma_exfil_archive_creation",
        "title": "Archive Created Before Transfer",
        "description": "Archive file created shortly before outbound network activity.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "data_exfiltration",
        "mitre": ["T1560.001"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["tar", "zip", "7z", "rar", "gzip"]},
            "count_threshold": 2,
            "time_window_seconds": 120,
            "group_by": "source_ip",
        },
    },
    # 80 — Clipboard data exfiltration
    {
        "id": "sigma_exfil_clipboard",
        "title": "Clipboard Data Access",
        "description": "Process accessing clipboard data for potential exfiltration.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "data_exfiltration",
        "mitre": ["T1115"],
        "condition": {
            "event_type": "clipboard_access",
            "count_threshold": 10,
            "time_window_seconds": 60,
            "group_by": "process_name",
        },
    },
    # 81 — Encrypted channel exfiltration
    {
        "id": "sigma_exfil_encrypted_channel",
        "title": "Encrypted Channel Data Exfiltration",
        "description": "High-volume encrypted traffic to unusual destination.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "data_exfiltration",
        "mitre": ["T1041"],
        "condition": {
            "event_type": "connection",
            "filter": {"protocol": "tls", "direction": "outbound", "bytes_gt": 10_485_760},
        },
    },
    # 82 — Steganography tool usage
    {
        "id": "sigma_exfil_steganography",
        "title": "Steganography Tool Detected",
        "description": "Known steganography tool execution detected.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "data_exfiltration",
        "mitre": ["T1027.003"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["steghide", "openstego", "snow", "outguess"]},
        },
    },

    # -------------------------------------------------------------------
    # CATEGORY 7: COMMAND & CONTROL (10 rules)
    # -------------------------------------------------------------------

    # 83 — Beacon pattern (regular intervals)
    # v1.6.4: composite group_by, explicit cooldown=COOLDOWN_EXPLOIT.
    {
        "id": "sigma_c2_beacon_regular",
        "title": "C2 Beacon - Regular Interval",
        "description": "Outbound connections at regular intervals suggesting C2 beaconing. v1.6.4 groups by (source_ip, destination_ip) so multiple internal hosts beaconing to the same C2 each get their own incident.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "command_and_control",
        "mitre": ["T1071.001"],
        "confidence_factors": [
            {"factor": "tor_exit",               "weight": 1.5},
            {"factor": "known_attacker_history", "weight": 2.0},
            {"factor": "geo_high_risk",          "weight": 1.2},
            {"factor": "safelisted",             "weight": 0.0},
        ],
        "condition": {
            "event_type": "connection",
            "count_threshold": 10,
            "time_window_seconds": 600,
            "group_by": ["source_ip", "destination_ip"],
            "filter": {"direction": "outbound", "target_type": "external"},
            "cooldown_seconds": COOLDOWN_EXPLOIT,
        },
    },
    # 84 — DNS-based C2
    {
        "id": "sigma_c2_dns",
        "title": "DNS-Based Command and Control",
        "description": "Suspicious DNS query patterns indicating C2 via DNS protocol.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "command_and_control",
        "mitre": ["T1071.004"],
        "condition": {
            "event_type": "dns_query",
            "count_threshold": 200,
            "time_window_seconds": 300,
            "group_by": "source_ip",
        },
    },
    # 85 — HTTPS C2 to new domain
    {
        "id": "sigma_c2_https_new_domain",
        "title": "HTTPS C2 to Newly Registered Domain",
        "description": "HTTPS connection to recently registered or low-reputation domain.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "command_and_control",
        "mitre": ["T1071.001"],
        "condition": {
            "event_type": "connection",
            "filter": {"domain_age_days_lt": 30, "protocol": "tls", "direction": "outbound"},
        },
    },
    # 86 — IRC traffic
    {
        "id": "sigma_c2_irc",
        "title": "IRC C2 Traffic Detected",
        "description": "IRC protocol traffic detected suggesting botnet C2 channel.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "command_and_control",
        "mitre": ["T1071.001"],
        "condition": {
            "event_type": "connection",
            "filter": {"destination_port": [6667, 6668, 6669, 6697]},
        },
    },
    # 87 — Tor network usage
    {
        "id": "sigma_c2_tor",
        "title": "Tor Network Usage Detected",
        "description": "Connection to known Tor entry/exit nodes.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "command_and_control",
        "mitre": ["T1090.003"],
        "condition": {
            "event_type": "connection",
            "filter": {"destination_port": [9001, 9030, 9050, 9051]},
        },
    },
    # 88 — Reverse shell
    {
        "id": "sigma_c2_reverse_shell",
        "title": "Reverse Shell Connection",
        "description": "Outbound connection from shell process indicating reverse shell.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "command_and_control",
        "mitre": ["T1059"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["bash -i", "nc -e", "ncat", "/dev/tcp/", "mkfifo"]},
        },
    },
    # 89 — Encoded PowerShell
    {
        "id": "sigma_c2_encoded_powershell",
        "title": "Encoded PowerShell Execution",
        "description": "PowerShell execution with encoded command suggesting C2 stager.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "command_and_control",
        "mitre": ["T1059.001"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["powershell", "-enc", "-EncodedCommand", "FromBase64String"]},
        },
    },
    # 90 — LOLBin abuse for C2
    {
        "id": "sigma_c2_lolbin",
        "title": "LOLBin Abuse for C2",
        "description": "Legitimate binary abused for downloading or executing C2 payload.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "command_and_control",
        "mitre": ["T1218"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["certutil", "bitsadmin", "mshta", "regsvr32", "rundll32"]},
        },
    },
    # 91 — Domain fronting
    {
        "id": "sigma_c2_domain_fronting",
        "title": "Domain Fronting Detected",
        "description": "TLS SNI mismatch with HTTP Host header suggesting domain fronting.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "command_and_control",
        "mitre": ["T1090.004"],
        "condition": {
            "event_type": "web_request",
            "filter": {"sni_host_mismatch": True},
        },
    },
    # 92 — Cobalt Strike malleable C2 pattern
    {
        "id": "sigma_c2_cobalt_strike",
        "title": "Cobalt Strike C2 Pattern",
        "description": "HTTP traffic matching Cobalt Strike malleable C2 profile patterns.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "command_and_control",
        "mitre": ["T1071.001"],
        "condition": {
            "event_type": "web_request",
            "filter": {"path_contains": ["/pixel", "/submit.php", "/updates", "__utm.gif", "/__session"]},
            "count_threshold": 5,
            "time_window_seconds": 300,
            "group_by": "source_ip",
        },
    },

    # -------------------------------------------------------------------
    # CATEGORY 8: DEFENSE EVASION (10 rules)
    # -------------------------------------------------------------------

    # 93 — Log deletion
    {
        "id": "sigma_evasion_log_deletion",
        "title": "Security Log Deletion",
        "description": "System or security log files deleted or cleared.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "defense_evasion",
        "mitre": ["T1070.001"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["wevtutil", "cl Security", "rm /var/log", "truncate", "> /var/log"]},
        },
    },
    # 94 — Timestomping
    {
        "id": "sigma_evasion_timestomping",
        "title": "File Timestomping Detected",
        "description": "File timestamps modified to evade forensic analysis.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "defense_evasion",
        "mitre": ["T1070.006"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["touch -t", "touch -d", "SetFileTime", "timestomp"]},
        },
    },
    # 95 — Process injection
    {
        "id": "sigma_evasion_process_injection",
        "title": "Process Injection Detected",
        "description": "Code injection into running process for defense evasion.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "defense_evasion",
        "mitre": ["T1055"],
        "condition": {
            "event_type": "process_injection",
            "count_threshold": 1,
            "time_window_seconds": 60,
            "group_by": "source_ip",
        },
    },
    # 96 — Binary padding
    {
        "id": "sigma_evasion_binary_padding",
        "title": "Binary Padding Evasion",
        "description": "Executable modified with padding to evade hash-based detection.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "defense_evasion",
        "mitre": ["T1027.001"],
        "condition": {
            "event_type": "file_modification",
            "filter": {"size_change_gt": 1048576, "path_contains": [".exe", ".dll", ".bin"]},
        },
    },
    # 97 — Indicator removal on host
    {
        "id": "sigma_evasion_indicator_removal",
        "title": "Indicator Removal on Host",
        "description": "Removal of forensic artifacts from the host system.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "defense_evasion",
        "mitre": ["T1070"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["shred", "wipe", "srm", "sdelete", "cipher /w"]},
        },
    },
    # 98 — Rootkit behavior
    {
        "id": "sigma_evasion_rootkit",
        "title": "Rootkit Behavior Detected",
        "description": "Kernel module loading or syscall hooking detected.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "defense_evasion",
        "mitre": ["T1014"],
        "condition": {
            "event_type": "kernel_module_load",
            "filter": {"signed": False},
        },
    },
    # 99 — AV/EDR tampering
    {
        "id": "sigma_evasion_av_tamper",
        "title": "Antivirus/EDR Tampering",
        "description": "Attempt to disable or tamper with security tools.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "defense_evasion",
        "mitre": ["T1562.001"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["sc stop", "net stop", "taskkill", "Defender", "MsMpEng", "Set-MpPreference"]},
        },
    },
    # 100 — Firewall rule modification
    {
        "id": "sigma_evasion_firewall_mod",
        "title": "Firewall Rule Modification",
        "description": "Host firewall rules modified to allow unauthorized traffic.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "defense_evasion",
        "mitre": ["T1562.004"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["netsh advfirewall", "iptables -D", "iptables -F", "ufw disable"]},
        },
    },
    # 101 — Process hollowing
    {
        "id": "sigma_evasion_process_hollowing",
        "title": "Process Hollowing Detected",
        "description": "Legitimate process unmapped and replaced with malicious code.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "defense_evasion",
        "mitre": ["T1055.012"],
        "condition": {
            "event_type": "process_injection",
            "filter": {"technique": "hollowing"},
        },
    },
    # 102 — AMSI bypass
    {
        "id": "sigma_evasion_amsi_bypass",
        "title": "AMSI Bypass Attempt",
        "description": "Attempt to bypass Antimalware Scan Interface.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "defense_evasion",
        "mitre": ["T1562.001"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["AmsiUtils", "amsiInitFailed", "AmsiScanBuffer"]},
        },
    },

    # -------------------------------------------------------------------
    # CATEGORY 9: DISCOVERY / RECONNAISSANCE (10 rules)
    # -------------------------------------------------------------------

    # 103 — Fast port scan
    {
        "id": "sigma_recon_fast_scan",
        "title": "Fast Port Scan Detected",
        "description": "Rapid port scanning of single target (SYN scan pattern).",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "discovery",
        "mitre": ["T1046"],
        "condition": {
            "event_type": "connection",
            "count_threshold": 50,
            "time_window_seconds": 30,
            "group_by": "source_ip",
            "unique_field": "target_port",
        },
    },
    # 104 — Slow/stealth port scan
    {
        "id": "sigma_recon_slow_scan",
        "title": "Slow Stealth Port Scan",
        "description": "Low-and-slow port scanning to evade detection.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "discovery",
        "mitre": ["T1046"],
        "condition": {
            "event_type": "connection",
            "count_threshold": 20,
            "time_window_seconds": 3600,
            "group_by": "source_ip",
            "unique_field": "target_port",
        },
    },
    # 105 — OS fingerprinting
    {
        "id": "sigma_recon_os_fingerprint",
        "title": "OS Fingerprinting Detected",
        "description": "TCP/IP stack fingerprinting attempts (nmap -O style).",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "discovery",
        "mitre": ["T1046"],
        "condition": {
            "event_type": "connection",
            "filter": {"tcp_flags": ["SYN", "FIN", "URG", "PSH"]},
            "count_threshold": 10,
            "time_window_seconds": 30,
            "group_by": "source_ip",
        },
    },
    # 106 — Service version enumeration
    {
        "id": "sigma_recon_service_enum",
        "title": "Service Version Enumeration",
        "description": "Service banner grabbing from multiple ports.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "discovery",
        "mitre": ["T1046"],
        "condition": {
            "event_type": "connection",
            "count_threshold": 10,
            "time_window_seconds": 120,
            "group_by": "source_ip",
            "unique_field": "target_port",
            "filter": {"banner_grab": True},
        },
    },
    # 107 — Directory brute force
    # v1.6.4: threshold 100→250, excludes static asset trees, composite group_by.
    {
        "id": "sigma_recon_dir_bruteforce",
        "title": "Web Directory Brute Force",
        "description": "Rapid unique-path requests indicating directory enumeration. v1.6.4 raised threshold to 250 and excluded /static, /assets, /images, /_next to avoid FPs from large static sites.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "discovery",
        "mitre": ["T1083"],
        "confidence_factors": [
            {"factor": "scanner_ua",             "weight": 1.5},
            {"factor": "known_attacker_history", "weight": 2.0},
            {"factor": "safelisted",             "weight": 0.0},
            {"factor": "internal_ip",            "weight": 0.0},
        ],
        "condition": {
            "event_type": "web_request",
            "filter": {
                "path_excludes": ["/static/", "/assets/", "/images/", "/_next/", "/favicon"],
            },
            "count_threshold": 250,
            "time_window_seconds": 60,
            "group_by": ["source_ip", "target_port"],
            "unique_field": "path",
            "cooldown_seconds": COOLDOWN_RECON,
        },
    },
    # 108 — Subdomain enumeration
    {
        "id": "sigma_recon_subdomain_enum",
        "title": "Subdomain Enumeration",
        "description": "DNS queries for many subdomains of same domain.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "discovery",
        "mitre": ["T1590.002"],
        "condition": {
            "event_type": "dns_query",
            "count_threshold": 50,
            "time_window_seconds": 120,
            "group_by": "source_ip",
            "unique_field": "query_subdomain",
        },
    },
    # 109 — Network share discovery
    {
        "id": "sigma_recon_share_discovery",
        "title": "Network Share Discovery",
        "description": "Enumeration of network shares across multiple hosts.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "discovery",
        "mitre": ["T1135"],
        "condition": {
            "event_type": "smb_access",
            "count_threshold": 10,
            "time_window_seconds": 120,
            "group_by": "source_ip",
            "unique_field": "destination_ip",
        },
    },
    # 110 — Active Directory enumeration
    {
        "id": "sigma_recon_ad_enum",
        "title": "Active Directory Enumeration",
        "description": "LDAP queries suggesting Active Directory reconnaissance.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "discovery",
        "mitre": ["T1087.002"],
        "condition": {
            "event_type": "ldap_query",
            "count_threshold": 20,
            "time_window_seconds": 120,
            "group_by": "source_ip",
        },
    },
    # 111 — SNMP community string scan
    {
        "id": "sigma_recon_snmp_scan",
        "title": "SNMP Community String Scan",
        "description": "SNMP queries with common community strings to multiple hosts.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "discovery",
        "mitre": ["T1046"],
        "condition": {
            "event_type": "connection",
            "filter": {"destination_port": 161},
            "count_threshold": 10,
            "time_window_seconds": 60,
            "group_by": "source_ip",
            "unique_field": "destination_ip",
        },
    },
    # 112 — Vulnerability scanner detection
    {
        "id": "sigma_recon_vuln_scanner",
        "title": "Vulnerability Scanner Detected",
        "description": "Traffic patterns matching known vulnerability scanners (Nessus, OpenVAS).",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "discovery",
        "mitre": ["T1595.002"],
        "condition": {
            "event_type": "web_request",
            "filter": {"path_contains": ["Nessus", "OpenVAS", "Nikto", "sqlmap", "w3af"]},
            "count_threshold": 5,
            "time_window_seconds": 60,
            "group_by": "source_ip",
        },
    },

    # -------------------------------------------------------------------
    # CATEGORY 10: CONTAINER / CLOUD (10 rules)
    # -------------------------------------------------------------------

    # 113 — Container escape attempt
    {
        "id": "sigma_cloud_container_escape",
        "title": "Container Escape Attempt",
        "description": "Process attempting to escape container sandbox.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "container_cloud",
        "mitre": ["T1611"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["nsenter", "chroot", "/proc/1/root", "/.dockerenv"]},
        },
    },
    # 114 — Privileged container launched
    {
        "id": "sigma_cloud_privileged_container",
        "title": "Privileged Container Launched",
        "description": "Docker container started with --privileged flag.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "container_cloud",
        "mitre": ["T1610"],
        "condition": {
            "event_type": "container_start",
            "filter": {"privileged": True},
        },
    },
    # 115 — Exposed Docker socket
    {
        "id": "sigma_cloud_docker_socket",
        "title": "Docker Socket Exposed",
        "description": "Docker socket mounted inside container allowing host access.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "container_cloud",
        "mitre": ["T1611"],
        "condition": {
            "event_type": "container_start",
            "filter": {"path_contains": ["/var/run/docker.sock"]},
        },
    },
    # 116 — Kubernetes API abuse
    {
        "id": "sigma_cloud_k8s_api_abuse",
        "title": "Kubernetes API Abuse",
        "description": "Suspicious Kubernetes API requests from unexpected source.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "container_cloud",
        "mitre": ["T1609"],
        "condition": {
            "event_type": "web_request",
            "filter": {"path_contains": ["/api/v1/pods", "/api/v1/secrets", "/api/v1/namespaces"]},
            "count_threshold": 5,
            "time_window_seconds": 60,
            "group_by": "source_ip",
        },
    },
    # 117 — Cloud metadata SSRF
    {
        "id": "sigma_cloud_metadata_ssrf",
        "title": "Cloud Metadata Service SSRF",
        "description": "Request to cloud instance metadata endpoint from application.",
        "severity": "critical",
        "enabled": True,
        "source": "sigma",
        "category": "container_cloud",
        "mitre": ["T1552.005"],
        "condition": {
            "event_type": "web_request",
            "filter": {"path_contains": ["169.254.169.254", "metadata.google.internal", "100.100.100.200"]},
            "count_threshold": 1,
            "time_window_seconds": 60,
            "group_by": "source_ip",
        },
    },
    # 118 — IAM enumeration
    {
        "id": "sigma_cloud_iam_enum",
        "title": "Cloud IAM Enumeration",
        "description": "Enumeration of IAM users, roles, or policies.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "container_cloud",
        "mitre": ["T1087.004"],
        "condition": {
            "event_type": "cloud_api",
            "filter": {"path_contains": ["ListUsers", "ListRoles", "ListPolicies", "GetAccountAuthorizationDetails"]},
            "count_threshold": 5,
            "time_window_seconds": 120,
            "group_by": "source_ip",
        },
    },
    # 119 — Cryptomining in container
    {
        "id": "sigma_cloud_cryptomining",
        "title": "Cryptomining in Container",
        "description": "Cryptocurrency mining process detected inside container.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "container_cloud",
        "mitre": ["T1496"],
        "condition": {
            "event_type": "process_creation",
            "filter": {"path_contains": ["xmrig", "minerd", "cpuminer", "stratum+tcp", "cryptonight"]},
        },
    },
    # 120 — Container image from untrusted registry
    {
        "id": "sigma_cloud_untrusted_image",
        "title": "Container Image from Untrusted Registry",
        "description": "Docker image pulled from non-approved registry.",
        "severity": "medium",
        "enabled": True,
        "source": "sigma",
        "category": "container_cloud",
        "mitre": ["T1610"],
        "condition": {
            "event_type": "container_pull",
            "filter": {"untrusted_registry": True},
        },
    },
    # 121 — Kubernetes secret access
    {
        "id": "sigma_cloud_k8s_secret_access",
        "title": "Kubernetes Secret Accessed",
        "description": "Kubernetes secrets accessed from unexpected pod or user.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "container_cloud",
        "mitre": ["T1552.007"],
        "condition": {
            "event_type": "cloud_api",
            "filter": {"path_contains": ["/api/v1/secrets", "get secrets"]},
            "count_threshold": 3,
            "time_window_seconds": 60,
            "group_by": "source_ip",
        },
    },
    # 122 — Cloud storage bucket misconfiguration
    {
        "id": "sigma_cloud_bucket_misconfig",
        "title": "Cloud Storage Bucket Public Access",
        "description": "Cloud storage bucket configured with public access.",
        "severity": "high",
        "enabled": True,
        "source": "sigma",
        "category": "container_cloud",
        "mitre": ["T1530"],
        "condition": {
            "event_type": "cloud_api",
            "filter": {"path_contains": ["PutBucketAcl", "PutBucketPolicy", "public-read"]},
        },
    },
    # v1.6.3: sigma_web_jce_joomla_rce
{
    "id": "sigma_web_jce_joomla_rce",
    "title": "Joomla JCE Editor Unauthenticated RCE (CVE-2026-48907)",
    "description": "Detects JCE exploit chain: profiles.import + plugin.rpc browser upload calls within a short window.",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "web_attacks",
    "mitre": ["T1190"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains": ["option=com_jce&task=profiles.import", "option=com_jce&task=plugin.rpc"]},
        "count_threshold": 2,
        "time_window_seconds": 10,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_web_mirasvit_cachewarmer_deser
{
    "id": "sigma_web_mirasvit_cachewarmer_deser",
    "title": "Magento Mirasvit CacheWarmer PHP Deserialization (CVE-2026-45247)",
    "description": "CacheWarmer cookie carrying base64-encoded PHP serialized object (Tz=O:, Qz=C:, YT=a:).",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "web_attacks",
    "mitre": ["T1190"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains": ["CacheWarmer=Tz", "CacheWarmer=Qz", "CacheWarmer=YT"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_web_ivanti_sentry_cmdinject
{
    "id": "sigma_web_ivanti_sentry_cmdinject",
    "title": "Ivanti Sentry MICS API Unauth Command Injection (CVE-2026-10520)",
    "description": "POST to /mics/api/v2/sentry/mics-config/handleMessage containing commandexec payload.",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "web_attacks",
    "mitre": ["T1190", "T1059"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains_all": ["/mics/api/v2/sentry/mics-config/handleMessage", "commandexec"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_ai_litellm_mcp_cmdinject
{
    "id": "sigma_ai_litellm_mcp_cmdinject",
    "title": "LiteLLM MCP REST stdio Command Injection (CVE-2026-42271)",
    "description": "POST to /mcp-rest/test/connection or /mcp-rest/test/tools/list with stdio transport + command/args fields.",
    "severity": "high",
    "enabled": True,
    "source": "sigma",
    "category": "ai_infra",
    "mitre": ["T1059", "T1190"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains_all": ["/mcp-rest/test/", "stdio", "\"command\""]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_web_splunk_postgres_recovery_rce
{
    "id": "sigma_web_splunk_postgres_recovery_rce",
    "title": "Splunk Postgres Sidecar Unauth File Op RCE (CVE-2026-20253)",
    "description": "POST to /splunkd/__raw/v1/postgres/recovery/* with empty Basic Auth header.",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "web_attacks",
    "mitre": ["T1190"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains": ["/splunkd/__raw/v1/postgres/recovery/"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_ai_marimo_terminal_rce
{
    "id": "sigma_ai_marimo_terminal_rce",
    "title": "Marimo Notebook Pre-Auth Terminal RCE (CVE-2026-39987)",
    "description": "WebSocket upgrade to /terminal/ws — pre-auth RCE in Marimo notebook server.",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "ai_infra",
    "mitre": ["T1190", "T1059"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains": ["/terminal/ws", "/marimo/terminal"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_ai_sglang_rerank_ssti
{
    "id": "sigma_ai_sglang_rerank_ssti",
    "title": "SGLang /v1/rerank Jinja2 SSTI RCE (CVE-2026-5760)",
    "description": "POST /v1/rerank with Jinja2 SSTI payloads (__import__, subprocess, {{ ... }}).",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "ai_infra",
    "mitre": ["T1190", "T1059"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains_all": ["/v1/rerank", "{{"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_supply_mastra_easyday_c2
{
    "id": "sigma_supply_mastra_easyday_c2",
    "title": "Mastra easy-day-js typosquat C2 IOC (npm jun17 2026)",
    "description": "Outbound to 23.254.164.92/123 /update/* — Mastra scope takeover dropper.",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "supply_chain",
    "mitre": ["T1195.002", "T1071.001"],
    "condition": {
        "event_type": "network_connection",
        "filter": {"destination_ip": ["23.254.164.92", "23.254.164.123"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_supply_nodeipc_azure_c2
{
    "id": "sigma_supply_nodeipc_azure_c2",
    "title": "node-ipc HMAC C2 to sh.azurestaticprovider.net (jun12 2026)",
    "description": "Outbound to sh.azurestaticprovider.net / 37.16.75.69 — node-ipc supply chain C2.",
    "severity": "high",
    "enabled": True,
    "source": "sigma",
    "category": "supply_chain",
    "mitre": ["T1195.002", "T1071.001"],
    "condition": {
        "event_type": "network_connection",
        "filter": {"destination_ip": ["37.16.75.69"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_supply_shai_hulud_miasma_anthropic_spoof
{
    "id": "sigma_supply_shai_hulud_miasma_anthropic_spoof",
    "title": "Shai-Hulud Miasma Anthropic API Path Spoof (jun01 2026)",
    "description": "HTTP POST to api.anthropic.com/v1/api (lookalike of /v1/messages) — Miasma C2 indicator.",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "supply_chain",
    "mitre": ["T1071.001", "T1036"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains_all": ["api.anthropic.com", "/v1/api"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_supply_solana_fakefix_telegram
{
    "id": "sigma_supply_solana_fakefix_telegram",
    "title": "Solana FakeFix PyPI Telegram Exfil (jun11 2026)",
    "description": "HTTP POST to api.telegram.org/bot* — Solana FakeFix PyPI exfil to attacker Telegram bot.",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "supply_chain",
    "mitre": ["T1567", "T1071.001"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains_all": ["api.telegram.org", "/bot"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_network_fortibleed_ioc
{
    "id": "sigma_network_fortibleed_ioc",
    "title": "FortiBleed Credential Exposure Campaign Source IP (jun13 2026)",
    "description": "Inbound traffic from 85.11.187.8 — FortiBleed campaign IOC.",
    "severity": "high",
    "enabled": True,
    "source": "sigma",
    "category": "network",
    "mitre": ["T1190"],
    "condition": {
        "event_type": "network_connection",
        "filter": {"source_ip": ["85.11.187.8"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_ai_litellm_bearer_sqli
{
    "id": "sigma_ai_litellm_bearer_sqli",
    "title": "LiteLLM Proxy Pre-Auth SQLi via Bearer Quote (CVE-2026-42208)",
    "description": "POST /chat/completions with single-quote in Bearer token — pre-auth SQL injection.",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "ai_infra",
    "mitre": ["T1190"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains_all": ["/chat/completions", "Bearer ", "'"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_web_nextjs_ws_ssrf
{
    "id": "sigma_web_nextjs_ws_ssrf",
    "title": "Next.js WebSocket Upgrade SSRF (CVE-2026-44578)",
    "description": "GET with Upgrade: websocket header AND absolute-form URI in request line (http(s)://...).",
    "severity": "high",
    "enabled": True,
    "source": "sigma",
    "category": "web_attacks",
    "mitre": ["T1190", "T1090"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains_all": ["Upgrade: websocket", "GET http"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_web_ghost_content_api_sqli
{
    "id": "sigma_web_ghost_content_api_sqli",
    "title": "Ghost CMS Content API Blind SQLi (CVE-2026-26980)",
    "description": "/ghost/api/* with filter=slug: or order=slug: containing SQL keywords (UNION SELECT, information_schema, etc.).",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "web_attacks",
    "mitre": ["T1190"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains_all": ["/ghost/api", "slug:"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_supply_shai_hulud_hades_firedalazer
{
    "id": "sigma_supply_shai_hulud_hades_firedalazer",
    "title": "Shai-Hulud Hades 'firedalazer' GitHub C2 Marker (jun08 2026)",
    "description": "Outbound GET to github.com/search/commits with 'firedalazer' query — Hades PyPI .pth persistence C2.",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "supply_chain",
    "mitre": ["T1071.001", "T1546"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains_all": ["github.com/search/commits", "firedalazer"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_ransomware_prinz_eugen_ext
{
    "id": "sigma_ransomware_prinz_eugen_ext",
    "title": "Prinz Eugen Ransomware Extension (.prinzeugen)",
    "description": "File creation with .prinzeugen extension — Prinz Eugen ransomware encryption marker.",
    "severity": "high",
    "enabled": True,
    "source": "sigma",
    "category": "ransomware",
    "mitre": ["T1486"],
    "condition": {
        "event_type": "file_create",
        "filter": {"path_contains": [".prinzeugen"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_ransomware_shinysp1d3r_ext
{
    "id": "sigma_ransomware_shinysp1d3r_ext",
    "title": "ShinySp1d3r Ransomware Extension (.shinysp1d3r)",
    "description": "File creation with .shinysp1d3r extension — ShinySp1d3r RaaS encryption marker (often ESXi/VMDK targets).",
    "severity": "high",
    "enabled": True,
    "source": "sigma",
    "category": "ransomware",
    "mitre": ["T1486"],
    "condition": {
        "event_type": "file_create",
        "filter": {"path_contains": [".shinysp1d3r"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_web_schneider_saitel_path_traversal
{
    "id": "sigma_web_schneider_saitel_path_traversal",
    "title": "Schneider EasyLogic T150 / Saitel DP Path Traversal (CVE-2026-6865)",
    "description": "Auth path traversal sequences targeting Schneider Saitel device. Narrow to user-agent or known Schneider IPs in higher tier.",
    "severity": "high",
    "enabled": True,
    "source": "sigma",
    "category": "web_attacks",
    "mitre": ["T1190", "T1083"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains_all": ["saitel", "../"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_web_aver_ptc_cgi_rce
{
    "id": "sigma_web_aver_ptc_cgi_rce",
    "title": "AVer PTC Camera cgi-bin RCE (CVE-2026-40624)",
    "description": "POST/GET to cgi-bin or upload endpoints with bash -i / eval / system( / null byte in body.",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "web_attacks",
    "mitre": ["T1190", "T1059"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains_all": ["cgi-bin", "bash -i"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_web_panos_globalprotect_bypass
{
    "id": "sigma_web_panos_globalprotect_bypass",
    "title": "Palo Alto PAN-OS GlobalProtect Auth Bypass (CVE-2026-0257)",
    "description": "POST to GlobalProtect /ssl-vpn/hipreport.esp or /ssl-vpn/getconfig.esp — cookie-forging auth bypass.",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "web_attacks",
    "mitre": ["T1190", "T1556"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains": ["/ssl-vpn/hipreport.esp", "/ssl-vpn/getconfig.esp"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_network_checkpoint_qilin_c2
{
    "id": "sigma_network_checkpoint_qilin_c2",
    "title": "Check Point IKEv1 Bypass + Qilin Payload IPs (CVE-2026-50751)",
    "description": "Inbound traffic from Qilin payload hosts (45.77.149.152, 209.182.225.136, 38.60.157.139).",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "network",
    "mitre": ["T1190", "T1105"],
    "condition": {
        "event_type": "network_connection",
        "filter": {"source_ip": ["45.77.149.152", "209.182.225.136", "38.60.157.139"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_network_ayysshush_asus_c2
{
    "id": "sigma_network_ayysshush_asus_c2",
    "title": "AyySSHush ASUS Botnet C2 IPs and SSH Port 53282 (CVE-2023-39780)",
    "description": "Inbound from AyySSHush C2 (101.99.91.151, 101.99.94.173, 79.141.163.179, 111.90.146.237) or SSH to non-standard port 53282.",
    "severity": "high",
    "enabled": True,
    "source": "sigma",
    "category": "network",
    "mitre": ["T1190", "T1571"],
    "condition": {
        "event_type": "network_connection",
        "filter": {"source_ip": ["101.99.91.151", "101.99.94.173", "79.141.163.179", "111.90.146.237"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_supply_axios_sfrclak_c2
{
    "id": "sigma_supply_axios_sfrclak_c2",
    "title": "Axios npm Typosquat C2 sfrclak.com (mar26 2026)",
    "description": "Outbound to sfrclak.com / 142.11.206.73:8000 — axios typosquat C2 IOC.",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "supply_chain",
    "mitre": ["T1195.002", "T1071.001"],
    "condition": {
        "event_type": "network_connection",
        "filter": {"destination_ip": ["142.11.206.73"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_web_cpanel_whm_crlf
{
    "id": "sigma_web_cpanel_whm_crlf",
    "title": "cPanel/WHM whostmgrsession CRLF Injection (CVE-2026-41940)",
    "description": "POST /login with whostmgrsession cookie containing CRLF (\\r\\n) sequences.",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "web_attacks",
    "mitre": ["T1190", "T1556"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains_all": ["whostmgrsession", "\\r\\n"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},
    # v1.6.3: sigma_web_drupal_jsonapi_sqli
{
    "id": "sigma_web_drupal_jsonapi_sqli",
    "title": "Drupal PostgreSQL JSON:API SQL Injection (CVE-2026-9082)",
    "description": "Drupal /jsonapi/* with SQL keywords (UNION SELECT, information_schema, pg_*) in body or params.",
    "severity": "critical",
    "enabled": True,
    "source": "sigma",
    "category": "web_attacks",
    "mitre": ["T1190"],
    "condition": {
        "event_type": "web_request",
        "filter": {"path_contains_all": ["/jsonapi/", "UNION"]},
        "count_threshold": 1,
        "time_window_seconds": 60,
        "group_by": "source_ip",
    },
},

    # -------------------------------------------------------------------
    # CATEGORY: DoS SHIELD (L7 flood) — v1.6.4.0
    # -------------------------------------------------------------------
    # These rules consume the dos.* events published by the dos_shield
    # singleton (app.services.dos_shield). The event payload already carries
    # event_type / source_ip / subnet / per_ip_rps / subnet_rps / global_rps /
    # concurrency / reason / mode / under_attack, so each event flows through
    # evaluate() unchanged and the engine auto-subscribes to these event_types
    # via _collect_subscribed_types().
    #
    # Severity policy (honest severities):
    #   single-source flood                        -> high
    #   distributed (subnet/global) / sustained    -> critical
    #   under-attack mode entered                  -> critical
    #
    # dos_shield NEVER blocks in monitor mode (the default posture); these
    # correlation rules only open incidents / surface on the threat map. Actual
    # blocking is delegated to dos_shield.escalate() (active mode only) which
    # reuses ip_blocker_service + firewall_client — no new mechanism here.

    # DoS-1 — single-source HTTP flood
    {
        "id": "dos_http_flood",
        "title": "HTTP Flood (single source)",
        "description": "A single source IP crossed the per-IP request-rate threshold (AEGIS_DOS_PER_IP_RPS) reported by dos_shield. Correlates 3+ dos.http_flood events (each already event-cooldown deduped by dos_shield) from the same IP within 5 min into one incident. High severity — a lone flooder against AEGIS's single-worker event loop.",
        "severity": "high",
        "enabled": True,
        "source": "builtin",
        "category": "dos",
        "mitre": ["T1498.001", "T1499.002"],
        "confidence_factors": [
            {"factor": "scanner_ua",             "weight": 1.3},
            {"factor": "tor_exit",               "weight": 1.5},
            {"factor": "known_attacker_history", "weight": 2.0},
            {"factor": "burst_rate",             "weight": 1.4},
            {"factor": "safelisted",             "weight": 0.0},
            {"factor": "internal_ip",            "weight": 0.0},
        ],
        "condition": {
            "event_type": "dos.http_flood",
            "count_threshold": 3,
            "time_window_seconds": 300,
            "group_by": ["source_ip"],
            "cooldown_seconds": COOLDOWN_DOS,
        },
    },
    # DoS-2 — distributed flood (subnet / global). Grouped by `subnet`
    # (a.b.c.0/24, present on the dos_shield payload) so a botnet clustered in
    # one address block correlates even when each member IP stays under the
    # per-IP limit. dos.distributed is emitted for BOTH subnet and global
    # floods; grouping on subnet keeps global floods (subnet varies) firing
    # per-block while still catching the clustered case. Critical.
    {
        "id": "dos_distributed",
        "title": "Distributed DoS Flood (subnet/global)",
        "description": "dos_shield reported an aggregate flood: either a /24 subnet crossed AEGIS_DOS_SUBNET_RPS or the global request rate crossed AEGIS_DOS_GLOBAL_RPS. Grouped by /24 subnet so botnets clustered in one address block correlate even when every member IP stays below the per-IP threshold. Critical — distributed floods are DDoS-blind to the legacy per-IP detectors.",
        "severity": "critical",
        "enabled": True,
        "source": "builtin",
        "category": "dos",
        "mitre": ["T1498", "T1499"],
        "confidence_factors": [
            {"factor": "tor_exit",               "weight": 1.5},
            {"factor": "known_attacker_history", "weight": 2.0},
            {"factor": "burst_rate",             "weight": 1.4},
            {"factor": "safelisted",             "weight": 0.0},
        ],
        "condition": {
            "event_type": "dos.distributed",
            "count_threshold": 2,
            "time_window_seconds": 120,
            "group_by": ["subnet"],
            "cooldown_seconds": COOLDOWN_DOS_CRITICAL,
        },
    },
    # DoS-3 — expensive-endpoint hammering (/api/v1/ask, /surface/scan). These
    # spend OpenRouter tokens / spawn subprocesses, so a much lower budget trips
    # (AEGIS_DOS_EXPENSIVE_RPM). High severity — resource/quota exhaustion.
    {
        "id": "dos_expensive_abuse",
        "title": "Expensive Endpoint Abuse",
        "description": "A source IP hammered an EXPENSIVE_PATHS endpoint (AI inference / scan trigger) above the dedicated per-IP budget (AEGIS_DOS_EXPENSIVE_RPM). Correlates 2+ dos.expensive_abuse events from the same IP within 5 min. High — drives OpenRouter token spend and subprocess/DB-pool exhaustion.",
        "severity": "high",
        "enabled": True,
        "source": "builtin",
        "category": "dos",
        "mitre": ["T1499.003"],
        "confidence_factors": [
            {"factor": "scanner_ua",             "weight": 1.3},
            {"factor": "known_attacker_history", "weight": 2.0},
            {"factor": "burst_rate",             "weight": 1.4},
            {"factor": "safelisted",             "weight": 0.0},
            {"factor": "internal_ip",            "weight": 0.0},
        ],
        "condition": {
            "event_type": "dos.expensive_abuse",
            "count_threshold": 2,
            "time_window_seconds": 300,
            "group_by": ["source_ip"],
            "cooldown_seconds": COOLDOWN_DOS,
        },
    },
    # DoS-4 — slow-loris / slow-POST / slow-read heuristic (per-IP concurrency
    # or long-lived request signal from dos_shield). High severity.
    {
        "id": "dos_slowloris",
        "title": "Slow-Loris / Connection Exhaustion",
        "description": "dos_shield flagged excessive concurrent in-flight requests (AEGIS_DOS_CONCURRENCY_PER_IP) or long-lived requests (AEGIS_DOS_SLOW_REQUEST_SECONDS) from a single IP — a slow-loris / slow-POST / slow-read signature that holds connections open to exhaust the single uvicorn worker. Correlates 2+ dos.slowloris events from the same IP within 5 min. High.",
        "severity": "high",
        "enabled": True,
        "source": "builtin",
        "category": "dos",
        "mitre": ["T1499.002"],
        "confidence_factors": [
            {"factor": "known_attacker_history", "weight": 2.0},
            {"factor": "safelisted",             "weight": 0.0},
            {"factor": "internal_ip",            "weight": 0.0},
        ],
        "condition": {
            "event_type": "dos.slowloris",
            "count_threshold": 2,
            "time_window_seconds": 300,
            "group_by": ["source_ip"],
            "cooldown_seconds": COOLDOWN_DOS,
        },
    },
    # DoS-5 — global under-attack mode entered. dos_shield sets this adaptive
    # flag when the global request rate crosses AEGIS_DOS_GLOBAL_RPS. This is a
    # system-wide condition (not attributable to one IP), so it is single-shot
    # (no count_threshold) and critical. group_by is a constant so the whole
    # platform shares one cooldown window and we don't storm incidents.
    {
        "id": "dos_under_attack",
        "title": "AEGIS Under Active DoS (global)",
        "description": "dos_shield entered adaptive under-attack mode — the GLOBAL request rate crossed AEGIS_DOS_GLOBAL_RPS (~70x headroom over real API baseline). A platform-wide condition; fires once per event (dos_shield emits enter/clear transitions). Critical — the whole service is degrading, not a single offender.",
        "severity": "critical",
        "enabled": True,
        "source": "builtin",
        "category": "dos",
        "mitre": ["T1498", "T1499"],
        "condition": {
            "event_type": "dos.under_attack",
            # Only the "entered" transition (under_attack=True) opens an
            # incident; the matching "cleared" event (under_attack=False) is
            # ignored so we don't raise a critical alert when the flood subsides.
            "filter": {"under_attack": True},
            "group_by": ["detector"],
            "cooldown_seconds": COOLDOWN_DOS,
        },
    },
    # DoS-6 — Sustained DoS Campaign. Escalates a *persistent* single-source
    # flooder to CRITICAL: 6+ dos.http_flood events (dos_shield emits at most
    # one per AEGIS_DOS_EVENT_COOLDOWN=30s per ip, so 6 ≈ 3+ minutes of
    # unrelenting flooding) from the same IP within 10 min. This is the
    # long-horizon companion to dos_http_flood — a brief burst stays high, but
    # sustained hammering becomes a critical campaign incident.
    {
        "id": "dos_sustained_campaign",
        "title": "Sustained DoS Campaign",
        "description": "A single source produced 6+ dos.http_flood events over 10 min (dos_shield event-cooldown = 30s, so this represents several minutes of unrelenting flooding). Promotes a persistent flooder from a high single-source alert to a CRITICAL sustained-campaign incident. Never silenced (cooldown 0) so ongoing campaigns keep surfacing on the threat map.",
        "severity": "critical",
        "enabled": True,
        "source": "builtin",
        "category": "dos",
        "mitre": ["T1498", "T1499.002"],
        "confidence_factors": [
            {"factor": "tor_exit",               "weight": 1.5},
            {"factor": "known_attacker_history", "weight": 2.0},
            {"factor": "burst_rate",             "weight": 1.4},
            {"factor": "safelisted",             "weight": 0.0},
            {"factor": "internal_ip",            "weight": 0.0},
        ],
        "condition": {
            "event_type": "dos.http_flood",
            "count_threshold": 6,
            "time_window_seconds": 600,
            "group_by": ["source_ip"],
            "cooldown_seconds": COOLDOWN_DOS_CRITICAL,
        },
    },
]


# ---------------------------------------------------------------------------
# Multi-event temporal chain rules
# ---------------------------------------------------------------------------

CHAIN_RULES: list[dict] = [
    # 1 - Classic intrusion sequence: recon -> brute force -> honeypot
    {
        "id": "advanced_intrusion_chain",
        "title": "Multi-stage intrusion detected",
        "severity": "critical",
        "description": "Same IP: port scan -> brute force -> honeypot interaction",
        "mitre": ["T1046", "T1110", "T1595"],
        "chain": [
            {"sigma_rule": "port_scan", "within": 3600},
            {"sigma_rule": "generic_credential_attack", "within": 1800},
            {"event_type": "honeypot_interaction", "within": 900},
        ],
        "group_by": "source_ip",
    },
    # 2 - Credential theft chain: brute force -> credential stuffing -> lateral movement
    {
        "id": "credential_theft_chain",
        "title": "Credential theft chain detected",
        "severity": "critical",
        "description": "Same IP: brute force -> credential stuffing -> lateral movement",
        "mitre": ["T1110", "T1110.004", "T1021"],
        "chain": [
            {"sigma_rule": "generic_credential_attack", "within": 1800},
            {"sigma_rule": "credential_stuffing", "within": 1200},
            {"sigma_rule": "lateral_movement", "within": 600},
        ],
        "group_by": "source_ip",
    },
    # 3 - Web attack escalation: SQL injection -> web shell -> data exfiltration
    {
        "id": "web_attack_escalation",
        "title": "Web attack escalation chain",
        "severity": "critical",
        "description": "Same IP: SQL injection -> web shell upload -> data exfiltration",
        "mitre": ["T1190", "T1505.003", "T1041"],
        "chain": [
            {"sigma_rule": "sql_injection_chain", "within": 3600},
            {"sigma_rule": "web_shell_activity", "within": 1800},
            {"sigma_rule": "data_exfiltration", "within": 900},
        ],
        "group_by": "source_ip",
    },
    # 4 - C2 establishment: port scan -> brute force -> C2 beacon
    {
        "id": "c2_establishment_chain",
        "title": "C2 establishment chain detected",
        "severity": "critical",
        "description": "Same IP: port scan -> brute force -> C2 beacon pattern",
        "mitre": ["T1046", "T1110", "T1071"],
        "chain": [
            {"sigma_rule": "port_scan", "within": 7200},
            {"sigma_rule": "brute_force_ssh", "within": 3600},
            {"sigma_rule": "c2_beacon", "within": 1800},
        ],
        "group_by": "source_ip",
    },
    # 5 - Privilege escalation chain: brute force -> priv esc -> data exfil
    {
        "id": "priv_esc_exfil_chain",
        "title": "Privilege escalation to exfiltration chain",
        "severity": "critical",
        "description": "Same IP: brute force -> privilege escalation -> data exfiltration",
        "mitre": ["T1110", "T1068", "T1041"],
        "chain": [
            {"sigma_rule": "brute_force_ssh", "within": 3600},
            {"sigma_rule": "privilege_escalation", "within": 1800},
            {"sigma_rule": "data_exfiltration", "within": 900},
        ],
        "group_by": "source_ip",
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_ts() -> float:
    return datetime.utcnow().timestamp()


def _matches_filter(event: dict, filt: dict) -> bool:
    """Return True when all filter key/value pairs match the event."""
    for key, expected in filt.items():
        actual = event.get(key)

        # Numeric greater-than check: bytes_gt → bytes > value
        if key.endswith("_gt"):
            field = key[:-3]  # strip "_gt"
            actual_val = event.get(field)
            if actual_val is None or actual_val <= expected:
                return False
            continue

        # Regex match: command_line_regex → re.search(pattern, event["command_line"])
        if key.endswith("_regex"):
            field = key[:-6]  # strip "_regex"
            actual_val = event.get(field)
            if actual_val is None or not re.search(str(expected), str(actual_val)):
                return False
            continue

        # List membership check
        if isinstance(expected, list):
            # path_contains: any element must be a substring of actual
            if key == "path_contains":
                path = event.get("path", "") or event.get("url", "") or ""
                if not any(fragment in path for fragment in expected):
                    return False
                continue
            # path_contains_all: every element must be a substring
            if key == "path_contains_all":
                path = event.get("path", "") or event.get("url", "") or ""
                if not all(fragment in path for fragment in expected):
                    return False
                continue
            # v1.6.3.5: path_excludes — fail the rule if path contains ANY listed fragment
            if key == "path_excludes":
                path = event.get("path", "") or event.get("url", "") or ""
                if any(fragment in path for fragment in expected):
                    return False
                continue
            if actual not in expected:
                return False
            continue

        if actual != expected:
            return False
    return True


# ---------------------------------------------------------------------------
# CorrelationEngine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """
    Sliding-window, in-memory Sigma-like rule evaluator.

    Architecture
    ~~~~~~~~~~~~
    - _window  : deque of (timestamp, event_dict) capped at MAX_EVENTS
    - _rules   : list of rule dicts (built-in + custom)
    - evaluate : called per-event; returns list of triggered rule dicts
    - _fired   : set of (rule_id, group_key) tuples that recently fired,
                 used for basic suppression (cooldown per group/rule).
    """

    MAX_EVENTS = 10_000
    # Minimum seconds between re-firing the same rule for the same group key.
    COOLDOWN_SECONDS = 60

    def __init__(self):
        self._window: deque[tuple[float, dict]] = deque(maxlen=self.MAX_EVENTS)

        # Hybrid rule-pack loading (v1.6.4+):
        # 1. Load YAML pack from app/rules/ — operator-curated Sigma + chain rules.
        # 2. MERGE BUILT_IN_RULES / CHAIN_RULES in-code definitions on top, with
        #    YAML rules winning on `id` collision (operator override).
        # 3. If YAML loading fails entirely, fall back to deepcopy(BUILT_IN_RULES)
        #    and deepcopy(CHAIN_RULES) so the engine still has a working baseline.
        # The merge guarantees that in-code rules like http_auth_brute_force,
        # ssh_honeypot_attempt, and generic_credential_attack are always present
        # (CHAIN_RULES reference generic_credential_attack), even when a YAML pack
        # is installed but partial.
        try:
            from app.services.rules_loader import load_rules, start_watcher
            from pathlib import Path
            _rules_path = Path(__file__).parent.parent / "rules"
            self._rule_pack = load_rules(_rules_path)
            # Flatten YAML rules across event types into a single list for
            # CRUD / stats / list_rules compatibility.
            self._rules: list = [r for rules in self._rule_pack.rules.values() for r in rules]
            self._chain_rules: list = list(self._rule_pack.chains)

            yaml_sigma_count = len(self._rules)
            yaml_chain_count = len(self._chain_rules)

            # ---- MERGE in-code BUILT_IN_RULES (YAML wins on id collision) ----
            yaml_rule_ids = {r["id"] for r in self._rules}
            yaml_chain_ids = {c["id"] for c in self._chain_rules}

            builtin_added_ids: list[str] = []
            builtin_dedup = 0
            for builtin in BUILT_IN_RULES:
                rid = builtin.get("id")
                if not rid:
                    continue
                if rid in yaml_rule_ids:
                    builtin_dedup += 1
                    continue
                self._rules.append(deepcopy(builtin))
                yaml_rule_ids.add(rid)
                builtin_added_ids.append(rid)
            builtin_added = len(builtin_added_ids)

            chain_added_ids: list[str] = []
            chain_dedup = 0
            for builtin_chain in CHAIN_RULES:
                cid = builtin_chain.get("id")
                if not cid:
                    continue
                if cid in yaml_chain_ids:
                    chain_dedup += 1
                    continue
                self._chain_rules.append(deepcopy(builtin_chain))
                yaml_chain_ids.add(cid)
                chain_added_ids.append(cid)
            chain_added = len(chain_added_ids)

            # Start hot-reload watcher (no-op if watchdog not installed)
            self._watcher = start_watcher(self._rule_pack, _rules_path)

            logger.info(
                f"rules loaded: {len(self._rules)} sigma + {len(self._chain_rules)} chain "
                f"(yaml={yaml_sigma_count}, builtin={builtin_added}, dedup={builtin_dedup}) "
                f"| chains (yaml={yaml_chain_count}, builtin={chain_added}, dedup={chain_dedup})"
            )
            if builtin_added_ids:
                logger.info(
                    f"In-code rules merged into YAML pack: {builtin_added_ids}"
                )
            if chain_added_ids:
                logger.info(
                    f"In-code chain rules merged into YAML pack: {chain_added_ids}"
                )
        except Exception as _load_err:
            logger.warning(
                f"YAML rule load failed ({_load_err}); "
                f"falling back to in-code BUILT_IN_RULES only"
            )
            self._rules = deepcopy(BUILT_IN_RULES)
            self._chain_rules = deepcopy(CHAIN_RULES)
            self._rule_pack = None
            self._watcher = None
            logger.info(
                f"rules loaded: {len(self._rules)} sigma + {len(self._chain_rules)} chain "
                f"(yaml=0, builtin={len(self._rules)}, dedup=0) [fallback path]"
            )

        # O(1) event-type dispatch index — rebuilt AFTER the YAML+builtin merge
        # so newly-merged in-code rules (http_auth_brute_force, ssh_honeypot_attempt,
        # generic_credential_attack) are routable from the first event onward.
        self._rules_by_type: dict[str, list] = self._build_type_index(self._rules)

        self._fired: dict[tuple[str, str], float] = {}  # (rule_id, group_key) → last_fired_ts
        self._chain_fired: dict[tuple[str, str], float] = {}  # chain cooldowns
        # Track sigma rule firings per group key for chain evaluation
        # key: (rule_id, group_key) -> list of timestamps when rule fired
        self._sigma_fire_log: dict[tuple[str, str], list[float]] = defaultdict(list)
        self._stats = {
            "events_processed": 0,
            "rules_triggered": 0,
            "chains_triggered": 0,
            "custom_rules": 0,
            "started_at": datetime.utcnow().isoformat(),
        }
        # Lazily imported to avoid circular dependency at module load time
        self._event_bus = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def register_event_bus(self, bus: Any) -> None:
        self._event_bus = bus

    async def start(self) -> None:
        """Subscribe to all relevant event types on the event bus."""
        if self._event_bus is None:
            logger.warning("No event bus registered; correlation subscriptions skipped")
            return

        event_types = self._collect_subscribed_types()
        for et in event_types:
            # v1.6.4.0: dos.* topics are routed through the safelist-gated
            # _on_dos_event handler below (mirrors _on_normalized_event), NOT
            # the generic _on_event — otherwise a safelisted crawler/Tailscale
            # peer that somehow reached dos_shield would open a DoS incident.
            # They are still collected here from the DoS rule conditions so we
            # know which dos.* topics to bind, but we skip the generic bind to
            # avoid double-processing the same event.
            if et in _DOS_EVENT_TYPES:
                continue
            self._event_bus.subscribe(et, self._on_event)

        # v1.6.4.0: bind every dos.* topic dos_shield can publish (including
        # dos.ip_blocked, which has no matching correlation rule but is part of
        # the shared contract) to the gated DoS handler. Subscribing all six
        # keeps the DoS event surface flowing into the incident/threat-map
        # pipeline without a parallel path.
        for et in _DOS_EVENT_TYPES:
            self._event_bus.subscribe(et, self._on_dos_event)

        # v1.6.3.8: ONLY subscribe to the typed `log_event` channel emitted by
        # log_watcher AFTER event_normalizer translation + safelist gate.
        # The legacy `log_line` topic still fires for the "Live Log" UI widget
        # but is no longer consumed here — subscribing to both was causing
        # exact 1:1 double-counting (226 correlation_engine + 226 fast_triage
        # for the same event burst).  _on_log_line remains as a manually
        # callable fallback used by tests.
        self._event_bus.subscribe("log_event", self._on_normalized_event)
        self._event_bus.subscribe("edr.event", self._on_edr_event)
        self._event_bus.subscribe("edr.process_start", self._on_edr_event)
        self._event_bus.subscribe("honeypot_interaction", self._on_honeypot_event)
        logger.info(
            f"Correlation engine subscribed to {len(event_types)} rule types "
            f"({len(_DOS_EVENT_TYPES)} dos.* via gated handler) "
            f"+ log_line, log_event, edr.event, edr.process_start, honeypot_interaction"
        )

    async def _on_normalized_event(self, data: dict) -> None:
        """Handle pre-normalized events from log_watcher (v1.6.4+).

        These events already carry typed event_type, source_ip, target_port,
        protocol, request_path, request_method, response_status, user_agent.
        No regex re-matching needed — feed straight into evaluate().
        """
        if not isinstance(data, dict):
            return
        if not data.get("event_type") or not data.get("source_ip"):
            return
        # Safelist gate (defence in depth — log_watcher should already have gated)
        try:
            from app.core.attack_detector import _is_safe_ip
            if _is_safe_ip(data["source_ip"]):
                return
        except Exception as exc:
            logger.warning(f"correlation_engine _on_normalized_event safelist check failed: {exc}")
        await self.evaluate(data)

    async def evaluate(self, event: dict) -> list[dict]:
        """
        Ingest one event and return a list of rule dicts that fired.
        Side-effects: appends to the sliding window, publishes correlation alerts,
        evaluates chain rules, and triggers fast_triage pipeline.
        """
        ts = _now_ts()
        self._window.append((ts, event))
        self._stats["events_processed"] += 1

        triggered = []
        # O(1) dispatch: _rules_by_type covers both YAML pack rules and any
        # custom rules added at runtime via add_rule().
        _t0 = time.perf_counter_ns()
        event_type = event.get("event_type", "")
        candidates = self._rules_by_type.get(event_type, [])
        for rule in candidates:
            if not rule.get("enabled", True):
                continue
            if self._check_rule(rule, event, ts):
                triggered.append(rule)
                self._stats["rules_triggered"] += 1

                # Record sigma fire for chain rule evaluation
                group_key = event.get("source_ip", "__all__")
                self._sigma_fire_log[(rule["id"], group_key)].append(ts)
                # Trim old entries (keep last hour)
                self._sigma_fire_log[(rule["id"], group_key)] = [
                    t for t in self._sigma_fire_log[(rule["id"], group_key)]
                    if ts - t < 7200
                ]

                await self._on_rule_triggered(rule, event)

        _eval_ns = time.perf_counter_ns() - _t0
        logger.debug(
            f"Rule eval: event_type={event_type!r} candidates={len(candidates)} "
            f"triggered={len(triggered)} elapsed_us={_eval_ns // 1000}"
        )

        # Evaluate chain rules
        chain_triggered = self._evaluate_chains(event, ts)
        for chain_rule in chain_triggered:
            self._stats["chains_triggered"] += 1
            await self._on_chain_triggered(chain_rule, event)

        # Campaign tracking — check for multi-phase attack campaigns
        source_ip = event.get("source_ip")
        for rule in triggered:
            campaign_alert = _campaign_tracker.track(rule["id"], source_ip, ts)
            if campaign_alert:
                logger.critical(
                    f"[CAMPAIGN] Multi-phase campaign from {source_ip} | "
                    f"phases={campaign_alert['phases']}"
                )
                if self._event_bus:
                    await self._event_bus.publish_critical(
                        "correlation_triggered", campaign_alert
                    )
                asyncio.create_task(
                    self._create_incident(
                        {"id": "campaign_multi_phase", "severity": "critical"},
                        campaign_alert,
                    )
                )

        # Also track event_type directly (for attack_detector detections)
        event_type = event.get("event_type", "")
        if event_type and source_ip:
            campaign_alert = _campaign_tracker.track(event_type, source_ip, ts)
            if campaign_alert:
                logger.critical(
                    f"[CAMPAIGN] Multi-phase campaign from {source_ip} | "
                    f"phases={campaign_alert['phases']}"
                )
                if self._event_bus:
                    await self._event_bus.publish_critical(
                        "correlation_triggered", campaign_alert
                    )

        # Trigger fast_triage if we have sigma matches
        if triggered:
            asyncio.create_task(self._run_fast_triage(event, triggered))

        return triggered

    # ------------------------------------------------------------------
    # Rule CRUD
    # ------------------------------------------------------------------

    def list_rules(self) -> list[dict]:
        return deepcopy(self._rules)

    def add_rule(self, rule: dict) -> dict:
        # Validate required fields
        for field in ("id", "title", "severity", "condition"):
            if field not in rule:
                raise ValueError(f"Rule missing required field: '{field}'")
        if rule["severity"] not in ("low", "medium", "high", "critical"):
            raise ValueError("severity must be one of: low, medium, high, critical")
        if "event_type" not in rule["condition"]:
            raise ValueError("condition must include 'event_type'")

        # Prevent duplicate IDs
        existing_ids = {r["id"] for r in self._rules}
        if rule["id"] in existing_ids:
            raise ValueError(f"Rule id '{rule['id']}' already exists")

        new_rule = deepcopy(rule)
        new_rule.setdefault("enabled", True)
        new_rule.setdefault("source", "custom")
        new_rule.setdefault("mitre", [])
        new_rule.setdefault("description", "")
        self._rules.append(new_rule)
        # Keep the O(1) dispatch index in sync.
        et = new_rule["condition"]["event_type"]
        self._rules_by_type.setdefault(et, []).append(new_rule)
        self._stats["custom_rules"] += 1
        logger.info(f"Correlation rule added: {new_rule['id']}")
        return deepcopy(new_rule)

    def remove_rule(self, rule_id: str) -> bool:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r["id"] != rule_id]
        removed = len(self._rules) < before
        if removed:
            # Rebuild the dispatch index to avoid stale references.
            self._rules_by_type = self._build_type_index(self._rules)
            logger.info(f"Correlation rule removed: {rule_id}")
        return removed

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        return {
            **self._stats,
            "rules_total": len(self._rules),
            "rules_enabled": sum(1 for r in self._rules if r.get("enabled", True)),
            "chain_rules_total": len(self._chain_rules),
            "window_size": len(self._window),
            "sigma_fire_log_size": len(self._sigma_fire_log),
        }

    def list_chain_rules(self) -> list[dict]:
        return deepcopy(self._chain_rules)

    # ------------------------------------------------------------------
    # Internal evaluation logic
    # ------------------------------------------------------------------

    @staticmethod
    def _build_type_index(rules: list) -> dict[str, list]:
        """Build event_type → [rule, ...] dict for O(1) dispatch in evaluate()."""
        index: dict[str, list] = {}
        for rule in rules:
            cond = rule.get("condition") or {}
            et = cond.get("event_type") if hasattr(cond, "get") else None
            if et:
                index.setdefault(et, []).append(rule)
        return index

    @staticmethod
    def _resolve_group_key(event: dict, group_by) -> str:
        """Resolve group key from an event for a scalar or composite group_by.

        v1.6.4: `group_by` may be a string (legacy) or a list of field names
        (composite). When a list is supplied the values are joined with ``|``
        producing a stable composite key, so a single attacker IP probing
        many endpoints fires once per (ip,port) tuple rather than per-path.
        """
        if group_by is None:
            return "__all__"
        if isinstance(group_by, str):
            return str(event.get(group_by, "__all__"))
        if isinstance(group_by, (list, tuple)):
            parts = [str(event.get(field, "__all__")) for field in group_by]
            return "|".join(parts)
        return "__all__"

    @staticmethod
    def _group_matches(event: dict, group_by, expected_key: str) -> bool:
        """True when `event`'s resolved group key equals `expected_key`."""
        if group_by is None:
            return True
        return CorrelationEngine._resolve_group_key(event, group_by) == expected_key

    def _check_rule(self, rule: dict, event: dict, now: float) -> bool:
        cond = rule["condition"]
        event_type = cond.get("event_type")

        # Must match the event type declared in the rule
        if event.get("event_type") != event_type:
            return False

        # Apply top-level field filter (if present)
        top_filter = cond.get("filter", {})
        if top_filter and not _matches_filter(event, top_filter):
            return False

        # v1.6.4: per-rule cooldown matched to attack class. Falls back to the
        # legacy class-level COOLDOWN_SECONDS only when the rule omits one.
        rule_cooldown = cond.get("cooldown_seconds", self.COOLDOWN_SECONDS)

        # Rules with no count_threshold fire immediately (single-event match)
        if "count_threshold" not in cond:
            # Even single-shot rules respect cooldown to avoid duplicate
            # incidents from a burst of identical events.
            group_by = cond.get("group_by")
            group_key = self._resolve_group_key(event, group_by)
            cooldown_key = (rule["id"], group_key)
            last_fired = self._fired.get(cooldown_key, 0)
            if rule_cooldown > 0 and now - last_fired < rule_cooldown:
                return False
            self._fired[cooldown_key] = now
            return True

        # Sliding-window count evaluation
        threshold: int = cond["count_threshold"]
        window_secs: int = cond.get("time_window_seconds", 60)
        group_by = cond.get("group_by")
        unique_field: str | None = cond.get("unique_field")

        # Determine group key from the triggering event — supports list group_by
        group_key = self._resolve_group_key(event, group_by)

        # Cooldown check: avoid re-firing the same rule for the same group too rapidly
        cooldown_key = (rule["id"], group_key)
        # v1.6.3.2: TTL eviction so _fired can't grow unbounded under storms.
        if len(self._fired) > 2048:
            stale_cutoff = now - max(rule_cooldown, self.COOLDOWN_SECONDS) * 4
            self._fired = {k: v for k, v in self._fired.items() if v >= stale_cutoff}
        last_fired = self._fired.get(cooldown_key, 0)
        # v1.6.4: cooldown=0 means "always fire" (used by ssh_honeypot_attempt
        # and chain rules where every event is signal).
        if rule_cooldown > 0 and now - last_fired < rule_cooldown:
            return False

        # Count matching events within the time window
        cutoff = now - window_secs
        matching_events = [
            ev for ts, ev in self._window
            if ts >= cutoff
            and ev.get("event_type") == event_type
            and self._group_matches(ev, group_by, group_key)
            and (not top_filter or _matches_filter(ev, top_filter))
        ]

        if unique_field:
            # Count distinct values of unique_field
            unique_values = {ev.get(unique_field) for ev in matching_events if ev.get(unique_field) is not None}
            count = len(unique_values)
        else:
            count = len(matching_events)

        if count >= threshold:
            self._fired[cooldown_key] = now
            return True

        return False

    def _evaluate_chains(self, event: dict, now: float) -> list[dict]:
        """
        Evaluate multi-event temporal chain rules.
        Check if all events in a chain occurred from the same group (IP)
        within their respective time windows.
        """
        triggered = []
        group_key = event.get("source_ip", "__all__")

        for chain_rule in self._chain_rules:
            chain_id = chain_rule["id"]
            chain_group = chain_rule.get("group_by", "source_ip")
            group_val = event.get(chain_group, "__all__")

            # Cooldown check
            cooldown_key = (chain_id, str(group_val))
            last_fired = self._chain_fired.get(cooldown_key, 0)
            if now - last_fired < self.COOLDOWN_SECONDS * 5:  # 5x cooldown for chains
                continue

            # Check each step in the chain
            chain = chain_rule.get("chain", [])
            all_steps_met = True
            for step in chain:
                step_rule = step.get("sigma_rule")
                step_event_type = step.get("event_type")
                within = step.get("within", 3600)

                if step_rule:
                    # Check if this sigma rule fired for this group within the window
                    fire_times = self._sigma_fire_log.get((step_rule, group_val), [])
                    recent = [t for t in fire_times if now - t <= within]
                    if not recent:
                        all_steps_met = False
                        break
                elif step_event_type:
                    # Check raw events in the window
                    found = False
                    for ts, ev in self._window:
                        if (now - ts <= within
                                and ev.get("event_type") == step_event_type
                                and ev.get(chain_group) == group_val):
                            found = True
                            break
                    if not found:
                        all_steps_met = False
                        break

            if all_steps_met:
                self._chain_fired[cooldown_key] = now
                triggered.append(chain_rule)

        return triggered

    async def _on_chain_triggered(self, chain_rule: dict, triggering_event: dict) -> None:
        """Handle a triggered chain rule — always critical."""
        # Drop events with no attributable source (null IP) AND events from
        # internal/private/Tailscale IPs. A correlation rule with no attacker
        # identity cannot produce an actionable incident, and null-IP events
        # from self-referential log processing historically grouped together
        # under `source_ip=None` and caused feedback-loop SQLi chain fires.
        source_ip = triggering_event.get("source_ip")
        if not source_ip or _is_internal_ip(source_ip):
            logger.debug(
                f"Skipping chain correlation (source_ip={source_ip!r}): "
                f"rule={chain_rule.get('id', 'chain')}"
            )
            return

        # v1.6.4.1: gate AEGIS_SAFE_IPS (crawlers/CDNs/monitors) BEFORE the
        # event-bus publish. Previously this check lived only in the async
        # _create_incident() at line ~3716, which ran ~100ms AFTER
        # publish_critical() below. That race meant a safelisted crawler
        # (e.g. Twitterbot from 199.16.156.0/22 hitting a URL that matched the
        # SQLi mega-regex) would flash a "SQL Injection Attack Chain" alert on
        # the dashboard even though the incident was correctly dropped in DB.
        # Gating here suppresses both the dashboard alert and the incident.
        if source_ip:
            try:
                from app.core.attack_detector import _is_safe_ip
                if _is_safe_ip(source_ip):
                    logger.debug(
                        f"Skipping chain correlation for safe IP {source_ip} "
                        f"(rule={chain_rule.get('id', 'chain')})"
                    )
                    return
            except Exception as exc:
                logger.warning(f"correlation_engine chain safelist import failed: {exc}")

        alert_data = {
            "event_type": "chain_correlation_triggered",
            "chain_id": chain_rule["id"],
            "chain_title": chain_rule["title"],
            "severity": chain_rule.get("severity", "critical"),
            "mitre": chain_rule.get("mitre", []),
            "description": chain_rule.get("description", ""),
            "chain_steps": [s.get("sigma_rule") or s.get("event_type") for s in chain_rule.get("chain", [])],
            "triggering_event": triggering_event,
            "source_ip": triggering_event.get("source_ip"),
            "source": "correlation_engine_chain",
            "timestamp": datetime.utcnow().isoformat(),
        }

        logger.critical(
            f"[CHAIN CORRELATION] Chain '{chain_rule['id']}' fired | "
            f"severity=CRITICAL | source_ip={triggering_event.get('source_ip')} | "
            f"steps={len(chain_rule.get('chain', []))}"
        )

        if self._event_bus:
            await self._event_bus.publish_critical("correlation_triggered", alert_data)

        # Create incident via AI engine (fire-and-forget)
        asyncio.create_task(self._create_incident(chain_rule, alert_data))

    async def _run_fast_triage(self, event: dict, sigma_matches: list[dict]) -> None:
        """Run the fast triage pipeline when sigma rules fire."""
        try:
            from app.services.ai_engine import ai_engine
            from app.services.threat_feeds import threat_feed_manager

            # Quick IOC cache check (<5ms for cached blocklists)
            source_ip = event.get("source_ip")
            ioc_check = None
            if source_ip:
                ioc_check = await threat_feed_manager.check_ip_reputation(source_ip)

            # Run fast triage (<300ms total)
            await ai_engine.fast_triage(event, sigma_matches, ioc_check)

        except Exception as e:
            logger.error(f"Fast triage pipeline error: {e}")

    def _build_event_context(self, event: dict) -> dict:
        """Assemble the confidence-factor context dict for an event.

        v1.6.4: feeds apply_confidence_factors() so each rule can boost or
        drop its severity based on per-event signals (Tor exit, scanner UA,
        known-attacker history, safelist hit, internal IP, burst rate).
        """
        source_ip = event.get("source_ip")
        ctx = {
            "scanner_ua": bool(event.get("scanner_ua") or event.get("tag") == "scanner"),
            "tor_exit": bool(event.get("tor_exit")),
            "known_attacker_history": bool(event.get("known_attacker")),
            "geo_high_risk": bool(event.get("geo_high_risk")),
            "burst_rate": bool(event.get("burst_rate")),
            "safelisted": False,
            "internal_ip": _is_internal_ip(source_ip) if source_ip else False,
        }
        if source_ip:
            try:
                from app.core.attack_detector import _is_safe_ip
                ctx["safelisted"] = bool(_is_safe_ip(source_ip))
            except Exception:
                pass
            try:
                from app.services.threat_feeds import threat_feed_manager  # type: ignore
                if hasattr(threat_feed_manager, "is_tor_exit"):
                    ctx["tor_exit"] = ctx["tor_exit"] or bool(threat_feed_manager.is_tor_exit(source_ip))
            except Exception:
                pass
        return ctx

    async def _on_rule_triggered(self, rule: dict, triggering_event: dict) -> None:
        """Publish correlation alert and optionally create an AI incident."""
        # Drop events with no attributable source (null IP) AND internal IPs.
        # See _on_chain_triggered for full rationale.
        source_ip = triggering_event.get("source_ip")
        if not source_ip or _is_internal_ip(source_ip):
            logger.debug(
                f"Skipping correlation (source_ip={source_ip!r}): "
                f"rule={rule.get('id', 'chain')}"
            )
            return

        # v1.6.4: apply per-event confidence factors to adjust severity.
        # A safelisted/internal source returns ('suppressed', 0) and we drop.
        event_ctx = self._build_event_context(triggering_event)
        adjusted_severity, multiplier = apply_confidence_factors(rule, event_ctx)
        if adjusted_severity == "suppressed":
            logger.debug(
                f"Correlation rule '{rule['id']}' suppressed by confidence "
                f"factor (source_ip={source_ip})"
            )
            return

        alert_data = {
            "event_type": "correlation_triggered",
            "rule_id": rule["id"],
            "rule_title": rule["title"],
            "severity": adjusted_severity,
            "base_severity": rule["severity"],
            "confidence_multiplier": multiplier,
            "incident_title": f"{adjusted_severity.upper()}: {rule['title']}",
            "incident_severity": adjusted_severity,
            "mitre": rule.get("mitre", []),
            "description": rule.get("description", ""),
            "triggering_event": triggering_event,
            "source_ip": triggering_event.get("source_ip"),
            "source": "correlation_engine",
            "pattern": rule["id"],
            "timestamp": datetime.utcnow().isoformat(),
        }

        logger.warning(
            f"[CORRELATION] Rule '{rule['id']}' fired | severity={rule['severity']} "
            f"| source_ip={triggering_event.get('source_ip')} "
            f"| event_type={triggering_event.get('event_type')}"
        )

        if self._event_bus:
            await self._event_bus.publish("correlation_triggered", alert_data)

        # Create an AI-engine incident asynchronously (fire-and-forget) so we
        # never block the event processing loop.
        asyncio.create_task(self._create_incident(rule, alert_data))

    async def _create_incident(self, rule: dict, alert_data: dict) -> None:
        """Open a new incident — tries AI engine first, falls back to direct DB insert."""
        source_ip = alert_data.get("source_ip")
        if source_ip:
            try:
                from app.core.attack_detector import _is_safe_ip
                if _is_safe_ip(source_ip):
                    logger.debug(f"correlation_engine: skipping incident for safe IP {source_ip} (rule={rule.get('id')})")
                    return
            except Exception as exc:
                logger.warning(f"correlation_engine safelist import failed: {exc}")
        try:
            from app.database import async_session
            from app.services.ai_engine import ai_engine
            from sqlalchemy import select
            from app.models.client import Client

            async with async_session() as db:
                result = await db.execute(select(Client).order_by(Client.created_at.asc()).limit(1))
                client = result.scalar_one_or_none()
                if client is None:
                    logger.error("Correlation engine: no client found, cannot create incident")
                    return

                try:
                    await ai_engine.process_alert(alert_data, client, db)
                except Exception as ai_err:
                    # AI failed (rate limit, network, etc.) — create incident directly
                    logger.warning(f"AI engine failed, creating incident directly: {ai_err}")
                    from app.models.incident import Incident
                    mitre_list = rule.get("mitre", [])
                    if mitre_list:
                        first = mitre_list[0]
                        mitre_technique = first.get("technique") if isinstance(first, dict) else str(first)
                        mitre_tactic = first.get("tactic") if isinstance(first, dict) else None
                    else:
                        mitre_technique = None
                        mitre_tactic = None
                    from datetime import datetime as _dt
                    incident = Incident(
                        client_id=client.id,
                        title=f"{rule['severity'].upper()}: {rule['title']}",
                        description=rule.get("description", "") or alert_data.get("description", ""),
                        severity=rule["severity"],
                        status="investigating",
                        source="correlation_engine",
                        mitre_technique=mitre_technique,
                        mitre_tactic=mitre_tactic,
                        source_ip=alert_data.get("source_ip"),
                        ai_analysis={
                            "rule_id": rule["id"],
                            "ai_fallback": True,
                            "_origin": {
                                "kind": "algorithm",
                                "source": "correlation_engine",
                                "rule": rule["id"],
                                "ts": _dt.utcnow().isoformat(),
                            },
                        },
                        raw_alert=alert_data.get("triggering_event"),
                    )
                    db.add(incident)
                    await db.commit()
                    logger.info(f"Correlation incident created (no AI): {incident.id}")

        except Exception as exc:
            logger.error(f"Correlation engine failed to create incident for rule '{rule['id']}': {exc}")

    # ------------------------------------------------------------------
    # Event bus subscription callback
    # ------------------------------------------------------------------

    async def _on_event(self, data: dict) -> None:
        """Handler registered with the event bus; called for every subscribed event."""
        if isinstance(data, dict):
            await self.evaluate(data)

    async def _on_dos_event(self, data: dict) -> None:
        """Handle dos.* events emitted by the dos_shield singleton (v1.6.4.0).

        dos_shield's middleware already short-circuits on _is_safe_ip() before
        ever calling record_request(), so a safelisted peer normally never
        produces a dos.* event. This handler re-applies the same safelist gate
        as defence-in-depth (mirrors _on_normalized_event) so a safelisted
        source_ip can never open a DoS incident, then feeds the payload — which
        already carries event_type/source_ip/subnet/*_rps — straight into
        evaluate() with no re-normalisation.
        """
        if not isinstance(data, dict):
            return
        if not data.get("event_type"):
            return
        source_ip = data.get("source_ip")
        # under_attack / ip_blocked payloads are system-wide and may carry a
        # placeholder or empty source_ip; only gate when a real IP is present.
        if source_ip:
            try:
                from app.core.attack_detector import _is_safe_ip
                if _is_safe_ip(source_ip):
                    return
            except Exception as exc:
                logger.warning(
                    f"correlation_engine _on_dos_event safelist check failed: {exc}"
                )
        await self.evaluate(data)

    # ------------------------------------------------------------------
    # Raw-source event translators
    # ------------------------------------------------------------------

    async def _on_log_line(self, data: dict) -> None:
        """Translate raw log_line events into typed security events for Sigma rules."""
        if not isinstance(data, dict):
            return
        line = data.get("line", "")
        if not line:
            return

        # Extract IP and request path from the log line
        ip_match = _IP_RE.search(line)
        source_ip = ip_match.group(1) if ip_match else None

        # Drop events with no attributable source (null IP) AND internal IPs.
        # A log line with no extractable IP cannot be an attack we can
        # attribute to an attacker — previously these leaked through and
        # grouped under source_ip=None in sigma rules like `sql_injection_chain`,
        # producing the feedback-loop false positives from traceback dividers.
        if not source_ip or _is_internal_ip(source_ip):
            return
        # v1.6.3.5: also gate AEGIS_SAFE_IPS here — safelisted IPs (operator's
        # Claro DR residential, Twitter/X, Bingbot, etc) should never feed
        # auth_failure / sql_injection / scanner events into the rule window.
        try:
            from app.core.attack_detector import _is_safe_ip
            if _is_safe_ip(source_ip):
                return
        except Exception as exc:
            logger.warning(f"correlation_engine _on_log_line safelist import failed: {exc}")
        path_match = _PATH_RE.search(line)
        request_path = path_match.group(1) if path_match else ""
        port_match = _PORT_RE.search(line)
        target_port = int(port_match.group(1)) if port_match else None

        ts = data.get("timestamp", datetime.utcnow().isoformat())

        for pat in _LOG_PATTERNS:
            if pat["regex"].search(line):
                event = {
                    "event_type": pat["event_type"],
                    "source_ip": source_ip,
                    "severity": pat["severity"],
                    "timestamp": ts,
                    "log_line": line[:500],
                    "path": request_path,
                    "source": "log_watcher",
                }
                if target_port:
                    event["target_port"] = target_port
                if pat.get("tag"):
                    event["tag"] = pat["tag"]
                await self.evaluate(event)

    async def _on_edr_event(self, data: dict) -> None:
        """Translate EDR events into correlation event types."""
        if not isinstance(data, dict):
            return
        kind = data.get("kind") or data.get("type", "")
        mapped_type = _EDR_EVENT_MAP.get(kind)
        if not mapped_type:
            return

        event = {
            "event_type": mapped_type,
            "source_ip": data.get("source_ip", "127.0.0.1"),
            "severity": data.get("severity", "medium"),
            "timestamp": data.get("timestamp", datetime.utcnow().isoformat()),
            "source": "edr",
            "agent_id": data.get("agent_id"),
            "pid": data.get("pid"),
            "path": data.get("path", data.get("exe", "")),
            "process_name": data.get("name", ""),
            "cmdline": data.get("cmdline", ""),
        }
        await self.evaluate(event)

    async def _on_honeypot_event(self, data: dict) -> None:
        """Forward honeypot interactions with the correct event_type for chain rules."""
        if not isinstance(data, dict):
            return
        event = {
            **data,
            "event_type": "honeypot_interaction",
        }
        await self.evaluate(event)

    # ------------------------------------------------------------------
    # Helper: collect all event_types from rules
    # ------------------------------------------------------------------

    def _collect_subscribed_types(self) -> set[str]:
        types: set[str] = set()
        for rule in self._rules:
            et = rule.get("condition", {}).get("event_type")
            if et:
                types.add(et)
        # Also collect event types referenced in chain rule steps
        for chain in self._chain_rules:
            for step in chain.get("chain", []):
                et = step.get("event_type")
                if et:
                    types.add(et)
        return types


# ---------------------------------------------------------------------------
# CampaignTracker — multi-phase attack campaign detection
# ---------------------------------------------------------------------------

# Map rule IDs (and event types) to kill-chain phases
_PHASE_MAP: dict[str, str] = {
    # Recon
    "port_scan": "recon",
    "scanner": "recon",
    "sigma_recon_port_sweep": "recon",
    "sigma_recon_service_enum": "recon",
    # Exploit / Initial Access
    "brute_force_ssh": "exploit",          # legacy alias (rule disabled but ID still resolves)
    "brute_force": "exploit",
    "http_auth_brute_force": "exploit",    # v1.6.4 split — HTTP 401 brute force
    "ssh_honeypot_attempt": "exploit",     # v1.6.4 split — honeypot SSH hit
    "generic_credential_attack": "exploit",# v1.6.4 split — fallback auth_failure
    "sql_injection": "exploit",
    "sql_injection_chain": "exploit",
    "xss": "exploit",
    "xss_attack_chain": "exploit",
    "command_injection": "exploit",
    "credential_stuffing": "exploit",
    "path_traversal": "exploit",
    "ssrf": "exploit",
    "sigma_auth_password_spray": "exploit",
    "sigma_auth_default_credentials": "exploit",
    # Persistence
    "web_shell_activity": "persist",
    "c2_beacon": "persist",
    "sigma_persist_backdoor": "persist",
    "sigma_persist_cron": "persist",
    # Exfiltration
    "data_exfiltration": "exfil",
    "dns_tunneling": "exfil",
    "sigma_exfil_dns_tunnel": "exfil",
    "sigma_exfil_large_upload": "exfil",
    # Lateral Movement
    "lateral_movement": "lateral",
    "sigma_lateral_smb_spread": "lateral",
    "sigma_lateral_wmi_exec": "lateral",
    # Breadcrumb (immediate critical)
    "breadcrumb_credential_used": "persist",
}


class CampaignTracker:
    """
    Tracks attack phases per source IP.  When a single IP triggers
    rules from 3+ distinct kill-chain phases, it emits a critical
    campaign alert.
    """

    CAMPAIGN_THRESHOLD = 3  # distinct phases needed

    def __init__(self):
        # source_ip -> set of phases observed
        self._ip_phases: dict[str, set[str]] = defaultdict(set)
        # Cooldown: source_ip -> last campaign alert timestamp
        self._alerted: dict[str, float] = {}
        self._cooldown = 600  # 10 min cooldown per IP

    def track(self, rule_id: str, source_ip: str, now: float) -> dict | None:
        """
        Record a rule firing.  Returns a campaign alert dict if
        the IP has hit 3+ distinct phases, else None.
        """
        if not source_ip or source_ip == "__all__":
            return None

        phase = _PHASE_MAP.get(rule_id)
        if not phase:
            return None

        self._ip_phases[source_ip].add(phase)

        if len(self._ip_phases[source_ip]) >= self.CAMPAIGN_THRESHOLD:
            last = self._alerted.get(source_ip, 0)
            if now - last < self._cooldown:
                return None
            self._alerted[source_ip] = now
            phases = sorted(self._ip_phases[source_ip])
            return {
                "event_type": "campaign_detected",
                "rule_id": "campaign_multi_phase",
                "rule_title": f"Multi-Phase Attack Campaign from {source_ip}",
                "severity": "critical",
                "mitre": ["TA0043", "TA0001", "TA0003", "TA0010"],
                "description": (
                    f"IP {source_ip} has triggered rules across {len(phases)} "
                    f"kill-chain phases: {', '.join(phases)}. "
                    f"This indicates a coordinated attack campaign."
                ),
                "source_ip": source_ip,
                "phases": phases,
                "source": "campaign_tracker",
                "timestamp": datetime.utcnow().isoformat(),
            }
        return None


_campaign_tracker = CampaignTracker()


# Singleton
correlation_engine = CorrelationEngine()
