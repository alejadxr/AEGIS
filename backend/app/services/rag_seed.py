"""
Seed the RAG knowledge base with built-in security knowledge.

Run once on first startup or via the /api/v1/rag/rebuild endpoint.
Includes MITRE ATT&CK top techniques, common vulnerability patterns,
remediation guides, and AEGIS usage documentation.
"""

import logging

logger = logging.getLogger("aegis.rag_seed")

# ---------------------------------------------------------------------------
# MITRE ATT&CK -- Top 50 technique descriptions
# ---------------------------------------------------------------------------

MITRE_TECHNIQUES = [
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use brute force techniques to gain access to accounts when "
            "passwords are unknown or when password hashes are obtained. Techniques include "
            "password guessing, password spraying, and credential stuffing. Mitigations: "
            "account lockout policies, MFA, strong password requirements, rate limiting."
        ),
    },
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to get a listing of services running on remote hosts "
            "and local network infrastructure devices, including those that may be vulnerable "
            "to remote software exploitation. Common tools: nmap, masscan. Detection: monitor "
            "for unusual network scanning activity, SYN floods to multiple ports."
        ),
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may attempt to exploit a weakness in an Internet-facing host or system "
            "to initially access a network. Common targets: web servers, databases, VPNs, "
            "firewalls. Includes SQL injection, command injection, path traversal, SSRF. "
            "Mitigations: WAF, input validation, regular patching, vulnerability scanning."
        ),
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse command and script interpreters to execute commands, scripts, "
            "or binaries. Includes PowerShell (T1059.001), Unix Shell (T1059.004), Python "
            "(T1059.006), JavaScript (T1059.007). Detection: command-line logging, script "
            "block logging, behavioral analysis."
        ),
    },
    {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may send phishing messages to gain access to victim systems. Includes "
            "spearphishing attachments (T1566.001), spearphishing links (T1566.002), and "
            "spearphishing via services (T1566.003). Mitigations: email filtering, user "
            "training, sandbox detonation, URL filtering."
        ),
    },
    {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may use valid accounts to log into a service that accepts remote "
            "connections, such as SSH, RDP, SMB, VNC, or WinRM. Once authenticated, they can "
            "perform actions as the logged-on user. Detection: monitor for unusual remote "
            "login patterns, impossible travel, after-hours access."
        ),
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": (
            "Adversaries may steal data by exfiltrating it over an existing command and control "
            "channel. The data is encoded or encrypted before exfiltration. Detection: monitor "
            "for large data transfers, unusual DNS queries, beaconing patterns, high-entropy data."
        ),
    },
    {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": (
            "Adversaries may exploit software vulnerabilities to escalate privileges. Common "
            "targets: kernel exploits (dirty pipe, dirty cow), SUID binaries, misconfigured "
            "sudo, service account exploitation. Mitigations: regular patching, least privilege, "
            "process sandboxing."
        ),
    },
    {
        "id": "T1204",
        "name": "User Execution",
        "tactic": "Execution",
        "description": (
            "An adversary may rely upon specific actions by a user to gain execution. This "
            "includes malicious links (T1204.001) and malicious files (T1204.002). Users may "
            "be subjected to social engineering to get them to execute malicious code."
        ),
    },
    {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate using OSI application layer protocols to avoid "
            "detection/network filtering. Includes HTTP/HTTPS (T1071.001), DNS (T1071.004), "
            "and mail protocols (T1071.003). Detection: protocol anomaly detection, JA3/JA4 "
            "fingerprinting, DNS analytics."
        ),
    },
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may attempt to dump credentials to obtain account login and credential "
            "material. Tools: mimikatz, secretsdump, procdump, hashdump. Targets: LSASS, SAM, "
            "NTDS.dit, /etc/shadow. Detection: monitor for process access to LSASS, credential "
            "file access attempts."
        ),
    },
    {
        "id": "T1505.003",
        "name": "Web Shell",
        "tactic": "Persistence",
        "description": (
            "Adversaries may backdoor web servers with web shells to establish persistent access. "
            "Web shells can be written in PHP, ASP, JSP, or Python. They allow remote command "
            "execution through HTTP requests. Detection: file integrity monitoring, web log "
            "analysis, process spawning from web server processes."
        ),
    },
    {
        "id": "T1486",
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": (
            "Adversaries may encrypt data on target systems (ransomware) to interrupt "
            "availability. They may demand ransom for decryption keys. Detection: monitor for "
            "mass file encryption, unusual file extensions, ransom notes. Response: isolate "
            "affected systems, restore from backups, preserve forensic evidence."
        ),
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Initial Access",
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts. Includes default "
            "accounts (T1078.001), domain accounts (T1078.002), local accounts (T1078.003), "
            "and cloud accounts (T1078.004). Detection: impossible travel, unusual login times, "
            "credential monitoring services."
        ),
    },
    {
        "id": "T1053",
        "name": "Scheduled Task/Job",
        "tactic": "Execution, Persistence",
        "description": (
            "Adversaries may abuse task scheduling functionality to facilitate initial or "
            "recurring execution of malicious code. Includes cron (T1053.003), systemd timers "
            "(T1053.006), Windows Task Scheduler (T1053.005). Detection: monitor for new "
            "scheduled tasks, crontab modifications."
        ),
    },
    {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may attempt to make an executable or file difficult to discover or "
            "analyze by encrypting, encoding, or otherwise obfuscating its contents. Techniques: "
            "base64 encoding, XOR encryption, packing, steganography. Detection: entropy "
            "analysis, sandbox detonation, behavioral analysis."
        ),
    },
    {
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Persistence, Privilege Escalation",
        "description": (
            "Adversaries may manipulate accounts to maintain and/or elevate access. This "
            "includes modifying credentials, permissions, or security settings. Includes SSH "
            "authorized keys (T1098.004), adding to admin groups. Detection: monitor for "
            "account modifications, permission changes, group membership changes."
        ),
    },
    {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": (
            "Adversaries may steal data by exfiltrating it over a different protocol than the "
            "existing command and control channel. Includes DNS tunneling, ICMP tunneling, "
            "HTTPS to cloud storage. Detection: monitor for unusual protocol usage, data volume "
            "anomalies, DNS query length/frequency."
        ),
    },
    {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may transfer tools or other files from an external system into a "
            "compromised environment. Common methods: wget, curl, certutil, PowerShell "
            "download cradles, BITSAdmin. Detection: monitor for downloads from unusual "
            "sources, executable file transfers."
        ),
    },
    {
        "id": "T1070",
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may delete or modify artifacts generated within systems to remove "
            "evidence of their presence. Includes clearing event logs (T1070.001), clearing "
            "bash history (T1070.003), timestomping (T1070.006). Detection: log forwarding "
            "to SIEM, file integrity monitoring."
        ),
    },
    {
        "id": "T1036",
        "name": "Masquerading",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may attempt to manipulate features of their artifacts to make them "
            "appear legitimate. Includes renaming utilities, matching legitimate file names, "
            "right-to-left override, invalid code signatures. Detection: process name vs path "
            "analysis, signature verification."
        ),
    },
    {
        "id": "T1569",
        "name": "System Services",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse system services or daemons to execute commands or programs. "
            "Includes service execution (T1569.002) via sc.exe, systemctl. Detection: monitor "
            "for new services, unusual service start commands, services running as SYSTEM."
        ),
    },
    {
        "id": "T1547",
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence, Privilege Escalation",
        "description": (
            "Adversaries may configure system settings to automatically execute a program "
            "during system boot or logon. Includes registry run keys (T1547.001), init scripts, "
            "login hooks, plist modifications. Detection: monitor autostart locations, registry "
            "key changes, startup folder modifications."
        ),
    },
    {
        "id": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion, Privilege Escalation",
        "description": (
            "Adversaries may inject code into processes to evade process-based defenses and "
            "possibly elevate privileges. Includes DLL injection (T1055.001), process hollowing "
            "(T1055.012), ptrace injection (T1055.008). Detection: API monitoring, process "
            "behavior analysis, memory analysis."
        ),
    },
    {
        "id": "T1218",
        "name": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may bypass process and signature-based defenses by proxying execution "
            "of malicious content with signed binaries (LOLBins). Includes mshta (T1218.005), "
            "rundll32 (T1218.011), regsvr32 (T1218.010). Detection: monitor for unusual parent-"
            "child process relationships."
        ),
    },
    {
        "id": "T1543",
        "name": "Create or Modify System Process",
        "tactic": "Persistence, Privilege Escalation",
        "description": (
            "Adversaries may create or modify system-level processes to repeatedly execute "
            "malicious payloads. Includes Windows services (T1543.003), systemd services "
            "(T1543.002), launch daemons (T1543.004). Detection: monitor for new system "
            "services, daemon installations."
        ),
    },
    {
        "id": "T1012",
        "name": "Query Registry",
        "tactic": "Discovery",
        "description": (
            "Adversaries may interact with the Windows Registry to gather information about "
            "the system, configuration, and installed software. Detection: monitor for excessive "
            "registry queries, reg.exe usage, especially accessing security-sensitive keys."
        ),
    },
    {
        "id": "T1082",
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": (
            "An adversary may attempt to get detailed information about the operating system "
            "and hardware. Commands: uname, systeminfo, hostname, cat /etc/os-release. "
            "Detection: monitor for reconnaissance command sequences from a single source."
        ),
    },
    {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may enumerate files and directories or may search in specific locations "
            "for certain information within a file system. Commands: dir, find, ls, tree. "
            "Detection: monitor for broad file system enumeration, especially in sensitive dirs."
        ),
    },
    {
        "id": "T1057",
        "name": "Process Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to get information about running processes. Commands: "
            "ps, tasklist, Get-Process. Used to identify security tools, find targets for "
            "injection, understand system state. Detection: monitor for unusual process "
            "enumeration activity."
        ),
    },
    {
        "id": "T1016",
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may look for details about the network configuration and settings. "
            "Commands: ipconfig, ifconfig, route, arp, netstat. Detection: monitor for network "
            "configuration enumeration commands, especially from unusual processes."
        ),
    },
    {
        "id": "T1049",
        "name": "System Network Connections Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to get a listing of network connections to or from the "
            "compromised system. Commands: netstat, ss, lsof. Detection: monitor for network "
            "connection enumeration from unexpected processes."
        ),
    },
    {
        "id": "T1018",
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to get a listing of other systems by IP address, hostname, "
            "or other logical identifier. Methods: ping sweep, ARP scanning, net view, LDAP "
            "queries. Detection: monitor for internal network scanning patterns."
        ),
    },
    {
        "id": "T1560",
        "name": "Archive Collected Data",
        "tactic": "Collection",
        "description": (
            "An adversary may compress and/or encrypt data prior to exfiltration. Tools: tar, "
            "zip, 7z, rar, gzip. Detection: monitor for archive creation of sensitive data, "
            "unusual compression activity, staging of archives in temp directories."
        ),
    },
    {
        "id": "T1074",
        "name": "Data Staged",
        "tactic": "Collection",
        "description": (
            "Adversaries may stage collected data in a central location or directory prior to "
            "exfiltration. This can be on the local system (T1074.001) or a remote share "
            "(T1074.002). Detection: monitor for data aggregation in unusual locations."
        ),
    },
    {
        "id": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse PowerShell for execution. PowerShell is a powerful command-line "
            "shell and scripting environment. Attack techniques: download cradles, encoded "
            "commands, AMSI bypass, constrained language mode bypass. Detection: ScriptBlock "
            "logging, module logging, transcription."
        ),
    },
    {
        "id": "T1059.004",
        "name": "Unix Shell",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse Unix shell commands and scripts for execution. Shells: bash, "
            "sh, zsh, fish. Techniques: reverse shells, cron persistence, environment variable "
            "manipulation, heredoc execution. Detection: auditd, command logging, process trees."
        ),
    },
    {
        "id": "T1059.007",
        "name": "JavaScript",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse JavaScript for execution. This includes server-side (Node.js) "
            "and client-side (browser) JavaScript. Techniques: XSS, prototype pollution, "
            "deserialization attacks, eval injection. Detection: CSP, input validation, WAF rules."
        ),
    },
    {
        "id": "T1562",
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may maliciously modify components of a victim environment to hinder or "
            "disable defensive mechanisms. Includes disabling security tools (T1562.001), "
            "disabling logging (T1562.002), firewall modification (T1562.004). Detection: "
            "monitor for security tool process termination, log gaps."
        ),
    },
    {
        "id": "T1090",
        "name": "Proxy",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may use connection proxies to direct network traffic between systems "
            "or act as an intermediary. Includes internal proxy (T1090.001), external proxy "
            "(T1090.002), multi-hop proxy (T1090.003), domain fronting (T1090.004). Detection: "
            "network flow analysis, proxy log monitoring."
        ),
    },
    {
        "id": "T1571",
        "name": "Non-Standard Port",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate using a protocol and port pairing that are typically "
            "not associated. Example: HTTP on port 8443, SSH on port 2222. Detection: protocol-"
            "port mismatch analysis, deep packet inspection."
        ),
    },
    {
        "id": "T1572",
        "name": "Protocol Tunneling",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may tunnel network communications to and from a victim system within "
            "a separate protocol to avoid detection. Includes DNS tunneling, ICMP tunneling, "
            "HTTP tunneling. Detection: payload size analysis, frequency analysis, entropy."
        ),
    },
    {
        "id": "T1132",
        "name": "Data Encoding",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may encode data to make C2 traffic less conspicuous. Includes standard "
            "encoding (T1132.001) like base64, and non-standard encoding (T1132.002) like custom "
            "XOR. Detection: entropy analysis, pattern matching, protocol anomalies."
        ),
    },
    {
        "id": "T1573",
        "name": "Encrypted Channel",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may employ encryption to conceal C2 traffic. Includes symmetric "
            "cryptography (T1573.001) and asymmetric cryptography (T1573.002). Detection: "
            "JA3/JA4 fingerprinting, certificate analysis, traffic pattern analysis."
        ),
    },
    {
        "id": "T1489",
        "name": "Service Stop",
        "tactic": "Impact",
        "description": (
            "Adversaries may stop or disable services on a system to render those services "
            "unavailable to legitimate users. Often done before ransomware deployment to stop "
            "backup agents, security tools, databases. Detection: monitor for service stop "
            "commands, especially for critical services."
        ),
    },
    {
        "id": "T1499",
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": (
            "Adversaries may perform DoS attacks to degrade or block availability of services. "
            "Includes OS exhaustion flood (T1499.001), service exhaustion flood (T1499.002), "
            "application exhaustion flood (T1499.003). Detection: traffic baseline monitoring, "
            "rate limiting, CDN/WAF protection."
        ),
    },
    {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": (
            "Adversaries may perform network DoS attacks to degrade availability. Includes "
            "direct network flood (T1498.001) and reflection amplification (T1498.002). "
            "Detection: NetFlow analysis, BGP monitoring, upstream filtering, scrubbing centers."
        ),
    },
    {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": (
            "Adversaries may execute active reconnaissance scans to gather information for "
            "targeting. Includes scanning IP blocks (T1595.001) and vulnerability scanning "
            "(T1595.002). Detection: monitor for scanning patterns, IDS/IPS signatures, "
            "honeypot interactions."
        ),
    },
    {
        "id": "T1592",
        "name": "Gather Victim Host Information",
        "tactic": "Reconnaissance",
        "description": (
            "Adversaries may gather information about the victim's hosts that can be used during "
            "targeting. Includes hardware (T1592.001), software (T1592.002), firmware (T1592.003), "
            "client configurations (T1592.004). Detection: web analytics, honeypot data."
        ),
    },
    {
        "id": "T1136",
        "name": "Create Account",
        "tactic": "Persistence",
        "description": (
            "Adversaries may create an account to maintain access. Includes local accounts "
            "(T1136.001), domain accounts (T1136.002), cloud accounts (T1136.003). Detection: "
            "monitor for account creation events, especially during off-hours or by non-admin "
            "processes."
        ),
    },
]

# ---------------------------------------------------------------------------
# Common vulnerability patterns and remediation
# ---------------------------------------------------------------------------

VULNERABILITY_PATTERNS = [
    {
        "title": "SQL Injection (SQLi)",
        "description": (
            "SQL injection occurs when an attacker can insert or manipulate SQL queries in the "
            "application. Types: in-band (union-based, error-based), blind (boolean-based, "
            "time-based), out-of-band. Impact: data breach, authentication bypass, data "
            "modification, OS command execution. Remediation: parameterized queries/prepared "
            "statements, ORM usage, input validation, WAF rules, least privilege DB accounts."
        ),
    },
    {
        "title": "Cross-Site Scripting (XSS)",
        "description": (
            "XSS allows attackers to inject malicious scripts into web pages viewed by other "
            "users. Types: reflected, stored, DOM-based. Impact: session hijacking, credential "
            "theft, defacement, keylogging. Remediation: output encoding, Content Security "
            "Policy (CSP), input validation, HttpOnly/Secure cookie flags, DOMPurify."
        ),
    },
    {
        "title": "Remote Code Execution (RCE)",
        "description": (
            "RCE allows an attacker to execute arbitrary code on the target system. Causes: "
            "deserialization vulnerabilities, command injection, buffer overflow, eval injection, "
            "template injection. Impact: full system compromise. Remediation: input validation, "
            "sandboxing, disable dangerous functions, regular patching, WAF."
        ),
    },
    {
        "title": "Server-Side Request Forgery (SSRF)",
        "description": (
            "SSRF allows an attacker to make the server send requests to internal resources. "
            "Impact: internal network scanning, cloud metadata access (169.254.169.254), "
            "internal service exploitation. Remediation: allowlist outbound URLs, disable "
            "unnecessary URL schemes, network segmentation, IMDS v2."
        ),
    },
    {
        "title": "Insecure Direct Object Reference (IDOR)",
        "description": (
            "IDOR occurs when an application uses user-supplied input to access objects directly "
            "without proper authorization checks. Impact: unauthorized data access, data "
            "modification, privilege escalation. Remediation: implement proper authorization "
            "checks, use indirect references, validate user permissions per request."
        ),
    },
    {
        "title": "Authentication Bypass",
        "description": (
            "Authentication bypass allows attackers to access protected resources without valid "
            "credentials. Causes: JWT vulnerabilities (none algorithm, key confusion), default "
            "credentials, logic flaws, race conditions. Remediation: strong auth libraries, "
            "MFA, session management best practices, regular auth testing."
        ),
    },
    {
        "title": "Privilege Escalation",
        "description": (
            "Privilege escalation allows attackers to gain higher-level permissions than intended. "
            "Types: vertical (user to admin), horizontal (user A to user B). Causes: SUID "
            "misconfigurations, sudo misconfigurations, kernel exploits, service account abuse. "
            "Remediation: least privilege principle, regular audits, kernel patching, sudo hardening."
        ),
    },
    {
        "title": "Path Traversal / Directory Traversal",
        "description": (
            "Path traversal allows attackers to access files outside the intended directory. "
            "Payloads: ../, ....//,  %2e%2e/, ..\\. Impact: configuration file access, source "
            "code disclosure, credential theft. Remediation: canonicalize paths, chroot/jail, "
            "input validation, avoid user input in file paths."
        ),
    },
    {
        "title": "Misconfigured CORS",
        "description": (
            "Cross-Origin Resource Sharing misconfigurations allow unauthorized domains to "
            "interact with APIs. Impact: credential theft, data exfiltration via victim's browser. "
            "Remediation: restrict Access-Control-Allow-Origin to specific trusted domains, "
            "never reflect arbitrary origins, disable credentials for wildcard origins."
        ),
    },
    {
        "title": "Exposed Sensitive Data",
        "description": (
            "Sensitive data exposure includes unencrypted credentials, API keys in source code, "
            "debug endpoints in production, .env files accessible, .git directory exposed. "
            "Impact: full compromise. Remediation: secrets management (Vault, SOPS), .gitignore, "
            "environment variable injection, disable debug in production, restrict sensitive paths."
        ),
    },
]

# ---------------------------------------------------------------------------
# AEGIS usage documentation
# ---------------------------------------------------------------------------

AEGIS_DOCS = [
    {
        "title": "AEGIS Overview",
        "content": (
            "AEGIS is an AI-powered autonomous cybersecurity defense platform. It provides "
            "real-time threat detection, automated incident response, vulnerability scanning, "
            "honeypot deployment, and threat intelligence correlation. The platform uses a "
            "multi-model AI pipeline with fast triage (sub-300ms deterministic path) and full "
            "AI analysis for complex threats."
        ),
    },
    {
        "title": "AEGIS Alert Pipeline",
        "content": (
            "The alert pipeline has two modes: Fast Triage and Full AI. Fast Triage handles "
            "80%+ of alerts in under 300ms using Sigma rules, IOC cache, and playbook automation. "
            "Full AI is used for complex/unknown threats and involves AI triage, classification, "
            "incident creation, action recommendation, and audit logging. Both paths feed into "
            "the event bus for real-time WebSocket updates."
        ),
    },
    {
        "title": "AEGIS Scanning Capabilities",
        "content": (
            "AEGIS supports multiple scan types: Nuclei (vulnerability scanning), Nmap (port "
            "and service discovery), Subfinder (subdomain enumeration), HTTPX (HTTP probing). "
            "Scans can be scheduled or triggered manually. Results are correlated with threat "
            "intelligence feeds and stored for historical analysis."
        ),
    },
    {
        "title": "AEGIS Honeypot System",
        "content": (
            "The phantom module deploys configurable honeypots that emulate services like SSH, "
            "HTTP, FTP, MySQL, and Redis. Honeypots capture attacker TTPs, commands, payloads, "
            "and credentials. AI generates realistic decoy content. Interactions are logged and "
            "correlated with other security events."
        ),
    },
    {
        "title": "AEGIS Incident Response",
        "content": (
            "Automated response actions include: block_ip (firewall rule), isolate_host (network "
            "isolation), revoke_creds (credential revocation), kill_process (process termination), "
            "quarantine_file (file isolation), firewall_rule (custom rules), shutdown_service, "
            "network_segment. Actions are governed by guardrails: auto_approve, require_approval, "
            "or never_auto depending on severity and action type."
        ),
    },
    {
        "title": "AEGIS Correlation Engine",
        "content": (
            "The Sigma-based correlation engine detects attack patterns across multiple events. "
            "It supports chain rules, temporal correlation, and IOC enrichment. When correlation "
            "patterns match, it triggers automated playbooks and escalates severity. Common "
            "detections: brute force chains, lateral movement patterns, data exfiltration sequences."
        ),
    },
    {
        "title": "AEGIS Threat Intelligence",
        "content": (
            "Threat intelligence feeds provide real-time IOC data including malicious IPs, "
            "domains, hashes, and URLs. Sources include community feeds, commercial feeds, and "
            "internal honeypot data. IOCs are cached for fast lookup during the triage pipeline. "
            "Confidence scoring helps prioritize actionable intelligence."
        ),
    },
    {
        "title": "AEGIS RAG Knowledge Base",
        "content": (
            "The embedded RAG (Retrieval-Augmented Generation) system provides semantic search "
            "over AEGIS's accumulated knowledge. It stores incidents, scan results, threat "
            "intel, correlation events, and security reference material. When Ask AI receives "
            "a question, it queries the RAG for relevant context before sending to the LLM, "
            "enabling answers grounded in the platform's actual data and history."
        ),
    },
]

# ---------------------------------------------------------------------------
# Best practice remediation guides
# ---------------------------------------------------------------------------

REMEDIATION_GUIDES = [
    {
        "title": "Network Hardening Best Practices",
        "content": (
            "1. Segment networks using VLANs and firewall zones. 2. Implement zero-trust "
            "architecture: verify every connection. 3. Use IDS/IPS at network boundaries. "
            "4. Enable NetFlow/sFlow for traffic analysis. 5. Block unnecessary outbound ports. "
            "6. Use DNS sinkholes for known malicious domains. 7. Implement 802.1X for network "
            "access control. 8. Monitor for ARP spoofing and rogue DHCP. 9. Use encrypted "
            "protocols (TLS 1.3, SSH). 10. Regular firewall rule audits."
        ),
    },
    {
        "title": "Server Hardening Checklist",
        "content": (
            "1. Minimal installation (remove unnecessary packages). 2. Disable unused services "
            "and ports. 3. Apply security patches within 24-72 hours for critical CVEs. "
            "4. Configure host firewall (iptables/nftables/ufw). 5. Enable audit logging "
            "(auditd). 6. Implement SSH hardening (key-only auth, disable root login, change "
            "port). 7. Set up file integrity monitoring (AIDE, OSSEC). 8. Configure automatic "
            "security updates. 9. Use SELinux/AppArmor. 10. Implement log forwarding to SIEM."
        ),
    },
    {
        "title": "Web Application Security Checklist",
        "content": (
            "1. Input validation on all user-supplied data. 2. Output encoding for XSS "
            "prevention. 3. Parameterized queries for SQL injection prevention. 4. CSRF tokens "
            "on state-changing operations. 5. Security headers: CSP, X-Frame-Options, HSTS, "
            "X-Content-Type-Options. 6. Rate limiting on authentication endpoints. 7. Session "
            "management: secure cookies, timeout, regeneration. 8. Error handling: generic "
            "messages, detailed logging. 9. File upload validation. 10. API authentication "
            "and authorization on every endpoint."
        ),
    },
    {
        "title": "Incident Response Playbook Template",
        "content": (
            "Phase 1 - Detection: Identify the incident through monitoring, alerts, or reports. "
            "Classify severity (critical/high/medium/low). Phase 2 - Containment: Isolate "
            "affected systems. Block attacker IPs. Preserve evidence. Phase 3 - Eradication: "
            "Remove malware/backdoors. Patch vulnerabilities. Reset compromised credentials. "
            "Phase 4 - Recovery: Restore systems from clean backups. Verify integrity. Monitor "
            "for re-infection. Phase 5 - Lessons Learned: Document timeline. Identify gaps. "
            "Update playbooks and detection rules."
        ),
    },
    {
        "title": "Container Security Best Practices",
        "content": (
            "1. Use minimal base images (Alpine, distroless). 2. Scan images for vulnerabilities "
            "(Trivy, Grype). 3. Never run containers as root. 4. Use read-only file systems. "
            "5. Implement resource limits (CPU, memory). 6. Use network policies (Kubernetes). "
            "7. Sign and verify images. 8. Don't store secrets in images (use secrets managers). "
            "9. Keep images up to date. 10. Monitor container runtime (Falco, Sysdig)."
        ),
    },
]


# ---------------------------------------------------------------------------
# Seed function
# ---------------------------------------------------------------------------

async def seed_knowledge(rag) -> int:
    """Ingest all built-in knowledge into the RAG service.

    Returns the number of documents ingested.
    """
    if not rag.enabled:
        logger.warning("RAG not enabled -- skipping seed")
        return 0

    count = 0

    # MITRE ATT&CK techniques
    for tech in MITRE_TECHNIQUES:
        text = (
            f"MITRE ATT&CK Technique {tech['id']}: {tech['name']}\n"
            f"Tactic: {tech['tactic']}\n"
            f"{tech['description']}"
        )
        await rag.ingest(
            text,
            {"technique_id": tech["id"], "tactic": tech["tactic"], "name": tech["name"]},
            doc_type="mitre_attack",
            doc_id=f"mitre_{tech['id']}",
        )
        count += 1

    # Vulnerability patterns
    for vuln in VULNERABILITY_PATTERNS:
        await rag.ingest(
            f"{vuln['title']}\n{vuln['description']}",
            {"category": "vulnerability_pattern", "title": vuln["title"]},
            doc_type="vulnerability_pattern",
            doc_id=f"vuln_{vuln['title'].lower().replace(' ', '_')[:40]}",
        )
        count += 1

    # AEGIS docs
    for doc in AEGIS_DOCS:
        await rag.ingest(
            f"{doc['title']}\n{doc['content']}",
            {"category": "documentation", "title": doc["title"]},
            doc_type="documentation",
            doc_id=f"doc_{doc['title'].lower().replace(' ', '_')[:40]}",
        )
        count += 1

    # Remediation guides
    for guide in REMEDIATION_GUIDES:
        await rag.ingest(
            f"{guide['title']}\n{guide['content']}",
            {"category": "remediation", "title": guide["title"]},
            doc_type="remediation_guide",
            doc_id=f"guide_{guide['title'].lower().replace(' ', '_')[:40]}",
        )
        count += 1

    logger.info("RAG knowledge seeded: %d documents", count)
    return count
