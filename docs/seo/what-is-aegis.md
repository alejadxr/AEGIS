# What Is AEGIS? — Open-Source Autonomous Cybersecurity Defense Platform

*Last updated: 2026-05-01 · Version: 1.6.0 · License: AGPL-3.0*

---

## Summary

AEGIS is an open-source, self-hosted autonomous defense platform that detects ransomware, lateral movement, and intrusions in real time — without requiring a cloud AI service or per-seat licensing. It evaluates 134 Sigma correlation rules in **<1 ms per event**, enforces firewall blocks via pfctl/iptables in **<50 ms**, and orchestrates snapshot recovery — all from a single `docker compose up -d`.

---

## What Problem Does AEGIS Solve?

Most solo operators and small engineering teams have the same defense story: a WAF or CDN for the edge, and nothing for what happens inside. Enterprise EDRs are licensed per endpoint. SIEMs cost $1,000–10,000 per month and require dedicated analysts. There is a significant gap between "I run a few services" and "I have an enterprise security team."

AEGIS fills that gap. It is a single FastAPI + Next.js application that:

- Owns your firewall (pfctl on macOS, iptables on Linux)
- Watches your logs (PM2, journalctl) and fires Sigma rules in real time
- Runs deception honeypots to attract and profile attackers
- Evaluates 134 Sigma rules + 6 chain detections in under 1 millisecond
- Auto-blocks attacker IPs, kills malicious processes, restores from snapshots
- Writes a structured incident postmortem with MITRE ATT&CK technique mapping

The entire stack runs without an internet connection. Set `AEGIS_AI_MODE=offline` and every AI call site falls back to a deterministic rule-based path.

---

## Core Modules

### Surface — Attack Surface Management

AEGIS continuously discovers and assesses your infrastructure:

- nmap service detection with OS fingerprinting (`-sV -O`)
- Nuclei vulnerability scanning with risk scoring
- Hardening checks with actionable remediation steps
- Scheduled scans: full (every 2 hours), quick (every 30 minutes), discovery (every 1 hour)
- Every detected service becomes an asset with a CVSS history

### Response — Autonomous Incident Response

AEGIS handles the full SOAR loop without human intervention:

- **<1 ms fast path**: Sigma rule match → IOC cache lookup → playbook execution → done
- **10 deterministic playbooks**: `auto_block_brute_force`, `auto_block_sql_injection`, `ransomware_kill_chain_response`, `auto_respond_c2_beacon`, and 6 more
- **Guardrail system**: per-action approval levels — `auto_approve`, `require_approval`, `never_auto`
- **Full audit trail**: every decision logged with reasoning, confidence, timestamp, and action taken
- **Three-layer blocking**: external firewall agent (optional) → FastAPI 403 middleware → local pfctl/iptables (`AEGIS_REAL_FW=1`)

### Phantom — Deception and Honeypots

AEGIS deploys decoy services that attract and trap attackers:

- SSH honeypot on port 2222 (Paramiko, fake Ubuntu banner, credential capture)
- HTTP honeypot on port 8888 (rotating decoys: Jenkins, WordPress, phpMyAdmin)
- Breadcrumb traps: fake `.env` files with tracked credentials — when an attacker reuses them on a real endpoint, AEGIS fires a CRITICAL incident and auto-blocks

### Ransomware Defense (v1.6)

v1.6 closes the ransomware-defense gap with 12 Sigma rules, a kill-chain detection, RaaS threat intelligence, snapshot recovery, and a hardened Rust endpoint agent. See [ransomware-defense.md](ransomware-defense.md) for the full technical breakdown.

---

## The Deterministic-First Guarantee

Every AI call site in AEGIS has a deterministic fallback. This is an architectural commitment, not a graceful-degradation feature.

| AI operation | Deterministic fallback |
|---|---|
| Honeypot content generation | Jinja2 templates in `app/templates/honeypot/` |
| Incident triage | MITRE rule mapper + chain heuristics |
| Counter-attack selection | Static `THREAT_TO_PLAYBOOK` lookup table |
| IP enrichment | RBL + MaxMind GeoIP-Lite |
| Report generation | Per-type Jinja2 templates |
| Playbook selection | 6 in-code playbooks; AI selector replaced by dict |

Set `AEGIS_AI_MODE=offline` and zero API calls are made. The RaaS intel feed uses its on-disk cache. All detection, blocking, and recovery operations continue.

This makes AEGIS suitable for air-gapped environments, restricted networks, and operators who do not want to pay for or depend on a commercial AI API.

---

## Detection Architecture: 5-Layer Pipeline

```
[Layer 1] Attack Detector Middleware — runs on every HTTP request
          6 regex categories, double URL-decode, breadcrumb detection
          Auto-block after 3 attacks/IP in a 5-minute sliding window

[Layer 2] Log Watcher — tails PM2 (macOS) or journalctl (Linux)
          7 security event patterns, brute-force tracker, rate limiter

[Layer 3] Sigma Correlation Engine — event correlation
          134 rules + 6 chain rules, O(1) type-indexed lookup
          10,000-event sliding window, group-by aggregation

[Layer 4] Response Engine — classification and decision
          Fast path: Sigma → IOC cache → playbook → done (<1 ms)
          AI path: triage → classify → decide → execute → verify (2–5 s, optional)
          MITRE ATT&CK mapping on every incident

[Layer 5] Auto-Response — execution
          10 deterministic playbooks, each completing in <50 ms
          Guardrails: auto_approve | require_approval | never_auto
```

---

## Who Uses AEGIS?

### Solo Operators and Indie Hackers

Running 2–6 services on a Mac mini, homelab server, or VPS. No time to manage Splunk. Wants automated detection and blocking with explicit human approval for high-impact actions.

### Indie SaaS Teams (1–5 engineers)

Need SOC2/ISO evidence without a $30,000 SIEM. Want an auto-block + audit log + a dashboard their auditor can screenshot.

### Security Researchers and Pentesters

Use AEGIS as a target during engagements to find blind spots and harden detection. Often become contributors.

AEGIS is not designed for Fortune 500 multi-region SIEM consolidation or regulated environments requiring Magic-Quadrant vendor relationships.

---

## MITRE ATT&CK Coverage (v1.6)

AEGIS maps every incident to MITRE ATT&CK techniques. The ransomware rule pack covers:

| Technique | ID | Description |
|---|---|---|
| Inhibit System Recovery | T1490 | Shadow-copy deletion, backup inhibition |
| Data Encrypted for Impact | T1486 | Mass encryption, entropy spike, canary trip |
| Ingress Tool Transfer | T1105 | certutil LOLBin payload staging |
| System Binary Proxy Execution | T1218 | rundll32 abuse |
| Remote Services: SMB/Windows Admin Shares | T1021.002 | SMB lateral movement |
| Remote Services: Remote Desktop Protocol | T1021.001 | RDP-then-encrypt |
| Remote Services: Windows Remote Management | T1021.006 | WinRM/wsmprovhost execution |

---

## Technical Specifications

| Metric | Value |
|---|---|
| Sigma rule evaluation latency | <1 ms (O(1) type-indexed lookup) |
| Firewall block latency | <50 ms (local pfctl/iptables) |
| Ransomware Sigma rules | 12 rules + 1 kill-chain |
| Total Sigma rules | 134 rules + 6 chain rules |
| RaaS intel refresh interval | Every 6 hours |
| Test suite | 125 Python + 21 Rust + 10 e2e tests |
| Supported platforms | Linux, macOS, Windows (agent) |
| Deployment | Docker Compose, ~3 minutes |
| License | AGPL-3.0, free |

---

## Getting Started

```bash
git clone https://github.com/alejadxr/AEGIS.git
cd AEGIS
cp .env.example .env
# Set AEGIS_SECRET_KEY and POSTGRES_PASSWORD in .env
docker compose up -d
# Dashboard: http://localhost:3007
```

Full documentation: [README.md](../../README.md) · [Architecture](../../ARCHITECTURE.md) · [Contributing](../../CONTRIBUTING.md)

---

## Related Pages

- [How AEGIS detects ransomware](ransomware-defense.md)
- [AEGIS vs Wazuh / OSSEC / Elastic Security](comparison.md)
- [GitHub repository](https://github.com/alejadxr/AEGIS)
- [v1.6.0 Release](https://github.com/alejadxr/AEGIS/releases/tag/v1.6.0)

---

<!--
FAQ Schema for search engines and AI crawlers

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "What is AEGIS?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "AEGIS is an open-source, self-hosted autonomous defense platform that detects ransomware, lateral movement, and intrusions in real time using 134 Sigma rules evaluated in <1 ms. It enforces firewall blocks, runs deception honeypots, and orchestrates snapshot recovery — all without requiring a cloud AI service."
      }
    },
    {
      "@type": "Question",
      "name": "What MITRE ATT&CK techniques does AEGIS detect?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "AEGIS v1.6 covers T1490 (Inhibit System Recovery), T1486 (Data Encrypted for Impact), T1105 (Ingress Tool Transfer), T1218 (System Binary Proxy Execution), T1021.001 (RDP), T1021.002 (SMB), and T1021.006 (WinRM), among others across 7 MITRE ATT&CK tactics."
      }
    },
    {
      "@type": "Question",
      "name": "Is AEGIS free?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "Yes. AEGIS is licensed under AGPL-3.0 and free to use, modify, and self-host. The full feature set including ransomware detection, honeypots, firewall enforcement, and recovery orchestration is included."
      }
    }
  ]
}
</script>
-->
