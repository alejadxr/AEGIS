<div align="center">

# AEGIS — Open-Source Autonomous Ransomware Defense and EDR Platform

### Self-hosted. Deterministic-first. Offline-capable.

*Detect, block, and recover from ransomware and intrusions in milliseconds — 134 Sigma rules, <1 ms in-memory evaluation, no LLM in the hot path.*

[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Coverage](https://img.shields.io/badge/coverage-65%25-yellow)]()
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
[![Detection](https://img.shields.io/badge/detection-11%2F11-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.12-blue)]()
[![Docker](https://img.shields.io/badge/docker-compose-blue)]()
[![Version](https://img.shields.io/badge/version-1.6.0-cyan)]()

[What is AEGIS?](#what-is-aegis) · [Install](#5-minute-install) · [Ransomware Defense](#ransomware-defense-v16) · [Detection](#detection-1111-verified) · [vs Wazuh / OSSEC / Elastic](#aegis-vs-wazuh--ossec--elastic-security) · [Architecture](#architecture) · [Docs](docs/)

</div>

---

## What is AEGIS?

**AEGIS is an open-source, self-hosted autonomous defense platform that detects ransomware, lateral movement, and intrusions in real time — without depending on a cloud AI service.**

It owns your firewall, watches your logs, runs deception honeypots, and evaluates 134 Sigma rules + 6 chain detections in **<1 ms per event**. When it sees an attack — brute-force, shadow-copy delete, mass file encryption, ransom note drop, SMB lateral movement — it auto-blocks the attacker IP, kills the process tree, restores from snapshot, and writes a structured incident postmortem.

Set `AEGIS_AI_MODE=offline` and the entire stack runs on deterministic rules and Jinja2 templates. AI enrichment is available but never required.

**Three modules:**
- **Surface** — attack-surface management (nmap + nuclei, scheduled scans, CVSS history)
- **Response** — autonomous incident response with guardrailed playbooks (auto_approve / require_approval / never_auto)
- **Phantom** — deception layer (SSH honeypot on :2222, HTTP decoy on :8888, breadcrumb credential traps)

```bash
git clone https://github.com/alejadxr/AEGIS.git && cd AEGIS
docker compose up -d
# Dashboard: http://localhost:3007 · API: http://localhost:8000
```

---

## Frequently Asked Questions

### How does AEGIS detect ransomware?

AEGIS v1.6 ships **12 ransomware-specific Sigma rules + 1 kill-chain** mapped to MITRE ATT&CK techniques T1490, T1486, T1105, T1218, and T1021. The correlation engine evaluates each event in **<1 ms** using an O(1) type-indexed rule lookup.

Specific behaviors detected:
- **Shadow-copy deletion** — `vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit /set {default} recoveryenabled No`, tmutil, btrfs snapshot delete
- **Mass file encryption** — ≥50 write events/second + mean Shannon entropy ≥7.5 bits/byte (sliding window, measured by the Rust endpoint agent)
- **Canary file trips** — 10 hidden sentinel files in Documents/Desktop/Downloads; any modification triggers an immediate critical incident
- **Ransom note drop** — filename pattern detection for `README.txt`, `HOW_TO_DECRYPT`, `RECOVER_FILES`, and 40+ known ransom note variants
- **LOLBin staging** — `certutil -urlcache`, `rundll32` abuse for payload delivery (MITRE T1105/T1218)
- **RDP-then-encrypt lateral movement** — T1021.001 RDP session followed by encryption events on the same host
- **SMB lateral movement** — T1021.002 file-share writes to remote hosts
- **WinRM remote execution** — T1021.006 `wsmprovhost.exe` spawning suspicious child processes

The **RaaS threat intel feed** (refreshed every 6 hours from RansomLook + CISA) supplies current C2 IP ranges, onion addresses, file extensions, and ransom note artifacts for known groups: LockBit, Akira, REvil, BlackCat/ALPHV, Babuk, Conti, WannaCry, and others.

### Is AEGIS really offline-capable?

Yes. Set `AEGIS_AI_MODE=offline` and every AI call site falls back to a deterministic path:

| AI operation | Offline fallback |
|---|---|
| Honeypot decoy content | Jinja2 templates in `app/templates/honeypot/` |
| Incident triage and classification | MITRE rule mapper + chain heuristics |
| Counter-attack selection | Static `THREAT_TO_PLAYBOOK` lookup table |
| IP enrichment | RBL + MaxMind GeoIP-Lite (no model call) |
| Report generation | Per-type Jinja2 templates |
| Playbook selection | 6 in-code playbooks; AI selector replaced by dict |

The RaaS intel feed, Sigma rules, chain detections, and all firewall blocking continue to operate with no external API calls.

### How does AEGIS compare to a traditional SIEM or EDR?

See the [comparison table](#aegis-vs-wazuh--ossec--elastic-security) below. The short answer: AEGIS trades unlimited enterprise scale for deterministic-first detection at machine speed and zero licensing cost.

### Can I run AEGIS on a homelab or Mac mini?

Yes. AEGIS is tested in production on a Mac Pro (FastAPI + Next.js via PM2) with a Raspberry Pi 5 as a Tailscale relay. A Mac mini, a Pi, or any Linux VPS with Docker is sufficient. The Rust endpoint agent builds for macOS arm64, Linux x64, and Windows x64.

### What are the system requirements?

- Docker + Docker Compose (for the full stack)
- 2 GB RAM minimum; 4 GB recommended
- `AEGIS_REAL_FW=1` + root/sudo for real pfctl/iptables enforcement (optional — defaults to in-memory NoopFirewall)
- No external services required in offline mode

---

## Ransomware Defense — v1.6

v1.6 ships full ransomware defense end-to-end. Everything below ships in the open-source free tier.

### Detection (server-side, <1 ms)

12 Sigma rules cover the complete ransomware kill-chain:

| Rule | MITRE Technique | Trigger |
|---|---|---|
| `ransomware_shadow_delete` | T1490 | vssadmin / wbadmin / bcdedit / tmutil shadow-delete commands |
| `ransomware_lolbin_certutil` | T1105 | certutil -urlcache -f payload staging |
| `ransomware_lolbin_rundll32` | T1218 | rundll32 loading from temp or user-writable paths |
| `ransomware_smb_lateral` | T1021.002 | SMB writes to ≥3 remote hosts in 60 s |
| `ransomware_winrm_exec` | T1021.006 | wsmprovhost spawning cmd/powershell/wscript |
| `ransomware_rdp_then_encrypt` | T1021.001 + T1486 | RDP session → encryption events same host, 5 min window |
| `ransomware_mass_extension_change` | T1486 | ≥20 extension-change events in 5 s |
| `ransomware_canary_tripped` | T1486 | Sentinel file modified |
| `ransomware_ransom_note` | T1486 | Known ransom note filename patterns |
| `ransomware_entropy_spike` | T1486 | ≥7.5 bits/byte mean entropy on ≥50 writes/s |
| `ransomware_vss_inhibit` | T1490 | Registry: DisableAutomaticSystemRestorePoint |
| `ransomware_backup_delete` | T1490 | wbadmin delete backup / bcdedit recoveryenabled No |

**Chain rule `ransomware_chain`**: fires a CRITICAL incident when ≥3 of the above rules trigger for the same host within a 10-minute window.

### Threat Intel (RaaS feed)

- Source: RansomLook API + CISA Known Ransomware Advisories
- Refresh interval: every 6 hours (with offline cache)
- Per-group data: aliases, C2 IPs, onion addresses, known file extensions, ransom note artifacts
- Groups tracked: LockBit, Akira, REvil, BlackCat/ALPHV, Babuk, Conti, WannaCry, Locky, and 20+ others
- Cached to `backend/app/data/raas/*.json` — survives restarts

### Recovery Orchestration

```python
# Query recovery options for an incident
GET /api/v1/ransomware/recovery-options/{event_id}

# Trigger restore from snapshot
POST /api/v1/ransomware/restore

# Look up decryptors (NoMoreRansom seed)
GET /api/v1/ransomware/decryptors
```

`SnapshotManager` wraps: tmutil (macOS), btrfs/zfs (Linux), VSS via Rust agent (Windows), Noop (default). Gated by `AEGIS_REAL_RECOVERY=1`.

`DecryptorLibrary` ships a NoMoreRansom seed list for: Akira, Babuk, REvil, LockBit, WannaCry, Conti, Locky, and others.

### Endpoint Agent (Rust)

The hardened Rust agent in `agent-rust/` provides:
- **Canary watcher** — filesystem notify on 10 hidden sentinel files
- **Entropy classifier** — sliding-window: ≥50 writes/s AND mean ≥7.5 bits/byte triggers kill-chain
- **Process killer** — forensic snapshot captured before `SIGKILL` (Linux) / `TerminateProcess` (Windows)
- **Self-protection** — `prctl(PR_SET_DUMPABLE, 0)` on Linux; `SetProcessMitigationPolicy` on Windows
- **Rollback** — calls SnapshotManager via API (gated by `AEGIS_REAL_RECOVERY=1`)

### Dashboard

`/dashboard/ransomware` provides:
- RaaS group activity timeline (recharts)
- Recent ransomware events table with MITRE technique links
- Decryptor lookup widget (NoMoreRansom)
- Recovery options panel per incident

### Test Harness

```bash
AEGIS_LIVEFIRE=1 python -m pytest backend/tests/e2e/test_livefire.py
```

Generates 100 entropy-padded dummy files in a tempdir, drops a ransom note, races the agent. Asserts: kill within 500 ms, incident reaches API, chain rule fires, ≥1 recovery snapshot available, synthetic C2 IP blocked.

---

## AEGIS vs Wazuh / OSSEC / Elastic Security

| Capability | AEGIS v1.6 | Wazuh 4.x | OSSEC 3.x | Elastic Security 8.x |
|---|---|---|---|---|
| **Detection latency** | <1 ms (in-memory Sigma eval) | 5–60 s pipeline | 5–30 s | 10–60 s |
| **Action latency** | <50 ms (local pfctl/iptables) | Active response ~5 s | Active response ~5 s | Manual SOAR / hours |
| **Ransomware Sigma rules** | 12 rules + 1 kill-chain | Community rules, no kill-chain | None built-in | SIEM rules, no offline kill-chain |
| **MITRE ATT&CK mapping** | T1490/T1486/T1105/T1218/T1021 | Yes (agent) | Partial | Yes (SIEM) |
| **Offline / air-gapped** | Full (`AEGIS_AI_MODE=offline`) | Partial | Yes | No (requires cloud) |
| **Honeypot deception** | SSH :2222 + HTTP :8888 + breadcrumbs | No | No | No |
| **Recovery orchestration** | tmutil / btrfs / zfs / VSS | No | No | No |
| **RaaS threat intel** | RansomLook + CISA, every 6 h | No | No | Threat intel subscriptions (paid) |
| **Self-hosted** | Yes, Docker Compose | Yes, complex stack | Yes, C agent | Self-managed or Elastic Cloud |
| **Deployment complexity** | `docker compose up -d` (~3 min) | Multi-node agent rollout | Manual C agent install | Weeks, requires Elasticsearch |
| **AI / LLM dependency** | Optional (AEGIS_AI_MODE=offline) | None | None | Hard requirement for ML features |
| **Cost** | Free, AGPL-3.0 | Free, GPL-2.0 | Free, GPL-2.0 | Free tier limited; Elastic Cloud $$$$ |
| **Rust endpoint agent** | Yes (EDR + entropy + canary) | C agent | C agent | Elastic agent (Go) |
| **Deception / breadcrumb traps** | Yes | No | No | No |

**Where AEGIS wins**: solo operators, indie SaaS teams, and homelabs that need deterministic ransomware kill-chain detection with sub-50 ms automated blocking and zero per-seat licensing. `docker compose up -d` and you have rules + honeypots + firewall enforcement in 3 minutes.

**Where to choose Wazuh/Elastic instead**: large multi-site enterprise deployments, regulated environments requiring Magic-Quadrant vendor relationships, or teams with dedicated SOC staff.

See [docs/seo/comparison.md](docs/seo/comparison.md) for the full side-by-side analysis.

---

## Detection: 11/11 Verified

Every detection capability tested against real attack patterns:

| # | Attack Vector | Detection Layer | Response | Result |
|---|--------------|----------------|----------|--------|
| 1 | SQL Injection (UNION, blind, error-based) | L1: Middleware regex + double URL-decode | Auto-block IP | PASS |
| 2 | XSS (reflected, stored, DOM) | L1: Middleware + L2: Log watcher | Auto-block IP | PASS |
| 3 | Path Traversal (`../`, `%2e%2e`) | L1: Middleware | Auto-block IP | PASS |
| 4 | Command Injection (`;cat`, `$(...)`) | L1: Middleware | Auto-block IP | PASS |
| 5 | SSH Brute Force (5+ failures/5 min) | L3: Sigma rule + honeypot capture | Auto-block + attacker profile | PASS |
| 6 | Port Scan (10+ ports/60 s) | L2: Log watcher + L3: Correlation | Auto-block IP | PASS |
| 7 | Scanner Detection (nmap, sqlmap, nikto) | L1: User-Agent + probe paths | Auto-block IP | PASS |
| 8 | Breadcrumb Trap (stolen honeypot creds) | Phantom → L1: Middleware chain | Critical incident + block | PASS |
| 9 | Lateral Movement (10+ internal hops) | L3: Sigma chain rule + campaign tracker | Isolate host (approval required) | PASS |
| 10 | C2 Beacon (periodic callbacks) | Entropy analysis (Renyi) | Auto-respond | PASS |
| 11 | Credential Stuffing (distributed) | L3: Correlation sliding window | Auto-block + feed report | PASS |

---

## 5-Minute Install

**Prerequisites:** Docker and Docker Compose.

```bash
git clone https://github.com/alejadxr/AEGIS.git
cd AEGIS

# Configure
cp .env.example .env
# Edit .env — set AEGIS_SECRET_KEY and POSTGRES_PASSWORD at minimum
# OPENROUTER_API_KEY is optional; omit it and AEGIS runs fully offline

# Launch
docker compose up -d

# Dashboard at http://localhost:3007
# API at http://localhost:8000
```

No default credentials. The setup wizard at `/setup` walks you through creating your admin account.

### What Gets Deployed

| Container | Port | Purpose |
|---|---|---|
| `aegis-api` | 8000 | FastAPI backend (140+ endpoints, 25 API routers) |
| `aegis-frontend` | 3007 | Next.js 14 dashboard (21 pages, real-time WebSocket) |
| `aegis-db` | 5432 | PostgreSQL 16 |

### Manual Installation

```bash
# Backend
cd backend && pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Frontend
cd frontend && npm install && npm run build && npm start
```

### Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `AEGIS_REAL_FW` | unset | Set to `1` to enable real pfctl/iptables enforcement |
| `AEGIS_AI_MODE` | `full` | `full` / `local` / `offline` — gates every AI call site |
| `AEGIS_REAL_RECOVERY` | unset | Set to `1` to enable real snapshot restore |
| `AEGIS_LIVEFIRE` | unset | Set to `1` to run the ransomware emulation harness |
| `AEGIS_FIREWALL_URL` | unset | Optional remote firewall agent URL |
| `AEGIS_MONITORED_APPS` | all PM2 apps | Comma-separated PM2 app names to tail |

---

## Architecture

### Detection Pipeline

```
Incoming Event
     |
[Layer 1] Attack Detector Middleware ──────────── runs on EVERY request
     |     6 regex categories + double URL-decode + breadcrumb detection
     |     Auto-block after 3 attacks/IP (5 min sliding window, <1 ms detection)
     |
[Layer 2] Log Watcher ────────────────────────── PM2/journalctl log tail
     |     7 security patterns, brute-force tracker, rate limiter
     |
[Layer 3] Sigma Correlation Engine ───────────── event correlation
     |     134 rules + 6 chain rules + campaign tracker
     |     O(1) type-indexed lookup, 10K event sliding window
     |
[Layer 4] Response Engine (dual-mode) ──────────── classification + decision
     |     Fast path: Sigma → IOC cache → Playbook → done (<1 ms)
     |     AI path: triage → classify → incident → actions (2–5 s, optional)
     |     MITRE ATT&CK mapping on every incident
     |
[Layer 5] Auto-Response ──────────────────────── execution
          10 deterministic playbooks (<50 ms each)
          Guardrails: auto_approve | require_approval | never_auto
          Three-layer blocking: external agent → FastAPI 403 → local pfctl/iptables
```

### System Overview

```
+-------------+     +---------------+     +----------------+
|   Desktop   |     |   Dashboard   |     |   Node Agent   |
|   Manager   |     |   (Next.js)   |     |  (Tauri+Rust)  |
|   (Tauri)   |     |   Port 3007   |     |   Per-host     |
+------+------+     +-------+-------+     +-------+--------+
       |                    |                      |
       +---------+----------+----------------------+
                 |
          REST API + WebSocket (real-time push)
                 |
+----------------+------------------+
|       AEGIS Backend (FastAPI)     |
|            Port 8000              |
|  +---------+  +----------+       |
|  | Surface |  | Response |       |
|  |  (ASM)  |  |  (SOAR)  |       |
|  +---------+  +----------+       |
|  +---------+  +----------+       |
|  | Phantom |  | Ransomware|      |
|  | (Decoy) |  | Defense  |       |
|  +---------+  +----------+       |
+----------+-----------+-----------+
           |
+----------+--+
| PostgreSQL  |
|   (data)    |
+-------------+
```

### Data Flow

```
PM2/System Logs  → Log Watcher  → Sigma Engine  → Response Actions  → Audit Log
nmap/nuclei      → Scheduler    → Assets DB     → Risk Score
Honeypots        → Interactions → Attacker Profiler → Threat Intel
RaaS Feed        → Intel Cache  → Correlation Engine → Block/Alert
Rust Agent       → Events       → Chain Detection → Kill-chain response
```

---

## Modules

### Surface — Attack Surface Management

Continuous discovery and vulnerability assessment.

- **Asset Discovery** — nmap service detection with OS fingerprinting (`-sV -O`)
- **Vulnerability Scanning** — Nuclei integration with deterministic risk scoring
- **Hardening Checks** — Configuration audits with actionable remediation
- **Scheduled Scans** — Full scan (2 h), quick scan (30 min), discovery (1 h)

### Response — Autonomous Incident Response (SOAR)

Deterministic-first alert triage with automated action execution.

- **<1 ms Fast Path** — Sigma check → IOC cache → playbook → done, no AI round-trip
- **10 Deterministic Playbooks** — `auto_block_brute_force`, `auto_block_sql_injection`, `auto_respond_c2_beacon`, `ransomware_kill_chain_response`, and 6 more
- **Guardrail System** — Per-action approval: `auto_approve` / `require_approval` / `never_auto`
- **Full Audit Trail** — Every decision logged: reasoning, confidence, timestamp, action taken

### Phantom — Honeypot Deception

Deploy decoy services that attract, profile, and trap attackers.

- **SSH Honeypot** (port 2222) — Paramiko server with fake banner, captures credentials and commands
- **HTTP Honeypot** (port 8888) — Rotating decoy pages: Jenkins, WordPress, phpMyAdmin
- **Breadcrumb Traps** — Fake `.env` files with tracked credentials; attacker reuses them → CRITICAL incident

### Ransomware Defense — New in v1.6

See [Ransomware Defense](#ransomware-defense-v16) above and [docs/seo/ransomware-defense.md](docs/seo/ransomware-defense.md).

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, FastAPI, SQLAlchemy async, APScheduler |
| Frontend | Next.js 14, TypeScript, Tailwind CSS, Recharts |
| Database | PostgreSQL 16 (asyncpg) |
| Threat Intel | RansomLook, CISA, Spamhaus, Tor exit list, MaxMind GeoIP-Lite |
| Desktop | Tauri v2, Rust |
| Endpoint Agent | Rust (tokio, notify, sysinfo) |
| Scanning | nmap, Nuclei |
| Deception | Paramiko (SSH), aiohttp (HTTP), Jinja2 templates |
| Containers | Docker Compose |
| AI (optional) | OpenRouter (claude-opus, sonnet, 5+ free models) |

---

## Project Structure

```
aegis/
├── backend/                    # FastAPI application
│   ├── app/
│   │   ├── api/                # 25 API routers (140+ endpoints)
│   │   ├── core/               # Auth, events, guardrails, attack detector, firewall engine
│   │   ├── models/             # SQLAlchemy models
│   │   ├── modules/
│   │   │   ├── surface/        # ASM: discovery, nuclei, risk scoring
│   │   │   ├── response/       # SOAR: ingestion, analysis, playbooks, responder
│   │   │   └── phantom/        # Deception: SSH/HTTP honeypots, profiler, rotation
│   │   ├── rules/              # 134 Sigma rules + 6 chain rules (YAML)
│   │   │   ├── sigma/          # Categorized by MITRE tactic
│   │   │   └── chains/         # Kill-chain detection rules
│   │   └── services/           # Background services: log_watcher, raas_intel, correlation_engine
│   └── tests/                  # pytest suite (125 Python tests)
├── frontend/                   # Next.js 14 dashboard (21 pages)
│   └── src/app/dashboard/
│       └── ransomware/         # RaaS timeline, events, decryptor lookup
├── agent-rust/                 # Standalone Rust EDR agent
│   └── src/ransomware/         # Canary, entropy, killer, rollback
├── desktop-tauri/              # AEGIS Manager desktop app (Tauri v2)
├── docs/                       # Documentation
│   └── seo/                    # Explainer pages (what-is, ransomware, comparison)
├── .well-known/
│   └── llms.txt                # LLM-discoverable site structure
├── docker-compose.yml
└── .env.example
```

---

## API Reference

All endpoints under `/api/v1/` require `X-API-Key` header or JWT Bearer token.

| Router | Description |
|---|---|
| `auth` | Register, login, JWT, RBAC (admin/analyst/viewer) |
| `surface` | Scans, assets, vulnerabilities, hardening |
| `response` | Incidents, actions, guardrails, analysis |
| `phantom` | Honeypots, interactions, attacker profiles |
| `correlation` | Sigma rules, chain detection, campaigns |
| `ransomware` | Kill-chain events, recovery options, decryptors |
| `nodes` | Endpoint agent enrollment, heartbeat, events |
| `threats` | IOC search, threat feeds, STIX export |
| `ask` | Natural language queries to the rule engine |

WebSocket at `/ws` for real-time event streaming.

Full API reference: [docs/api/](docs/api/)

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

Areas where help is especially valued:
- **Sigma rules** — detection rules for new ransomware families and attack patterns
- **Threat feeds** — integrating additional RaaS intelligence sources
- **Endpoint agents** — Linux and macOS agent builds
- **Documentation** — deployment guides, tutorials, attack scenario walkthroughs
- **Testing** — expanding coverage of the ransomware kill-chain path

---

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md) for our responsible disclosure policy.

---

## License

AEGIS is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).

Free to use, modify, and distribute. If you run a modified version as a network service, you must make the source code available to users.

---

## More Reading

- [What is AEGIS? — Full explainer](docs/seo/what-is-aegis.md)
- [How AEGIS detects ransomware](docs/seo/ransomware-defense.md)
- [AEGIS vs Wazuh / OSSEC / Elastic Security](docs/seo/comparison.md)
- [Architecture deep dive](ARCHITECTURE.md)
- [Contributing](CONTRIBUTING.md)

---

<!--
JSON-LD structured data for schema.org SoftwareApplication + FAQPage
Paste this block into any HTML landing page <head> to enable rich results.

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "SoftwareApplication",
      "name": "AEGIS",
      "alternateName": "AEGIS Autonomous Defense Platform",
      "description": "Open-source, self-hosted autonomous cybersecurity defense platform. Detects ransomware, lateral movement, and intrusions in <1 ms using 134 Sigma rules. Offline-capable. No cloud AI required.",
      "applicationCategory": "SecurityApplication",
      "operatingSystem": "Linux, macOS, Windows",
      "softwareVersion": "1.6.0",
      "datePublished": "2026-05-01",
      "license": "https://www.gnu.org/licenses/agpl-3.0.html",
      "url": "https://github.com/alejadxr/AEGIS",
      "downloadUrl": "https://github.com/alejadxr/AEGIS/releases/tag/v1.6.0",
      "codeRepository": "https://github.com/alejadxr/AEGIS",
      "programmingLanguage": ["Python", "TypeScript", "Rust"],
      "keywords": [
        "open source EDR",
        "self-hosted ransomware defense",
        "deterministic SOAR",
        "open source SIEM alternative",
        "MITRE ATT&CK detection",
        "ransomware kill-chain",
        "offline security platform",
        "open source XDR",
        "Sigma rules",
        "autonomous incident response"
      ],
      "featureList": [
        "134 Sigma correlation rules with <1 ms evaluation",
        "12 ransomware-specific detection rules (MITRE T1490/T1486/T1105/T1218/T1021)",
        "Ransomware kill-chain detection and response",
        "RaaS threat intelligence feed (RansomLook + CISA)",
        "Recovery orchestration (tmutil/btrfs/zfs/VSS)",
        "SSH and HTTP honeypots with breadcrumb traps",
        "Offline-capable (AEGIS_AI_MODE=offline)",
        "Real firewall enforcement (pfctl/iptables)",
        "Rust endpoint agent with entropy classifier",
        "Self-hosted with Docker Compose"
      ],
      "offers": {
        "@type": "Offer",
        "price": "0",
        "priceCurrency": "USD"
      }
    },
    {
      "@type": "FAQPage",
      "mainEntity": [
        {
          "@type": "Question",
          "name": "What is AEGIS cybersecurity?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "AEGIS is an open-source, self-hosted autonomous defense platform that detects ransomware, lateral movement, and intrusions in real time. It evaluates 134 Sigma rules in <1 ms, runs deception honeypots, enforces firewall blocks via pfctl/iptables, and orchestrates snapshot recovery — all without requiring a cloud AI service."
          }
        },
        {
          "@type": "Question",
          "name": "How does AEGIS detect ransomware?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "AEGIS v1.6 ships 12 ransomware-specific Sigma rules + 1 kill-chain detection mapped to MITRE ATT&CK techniques T1490, T1486, T1105, T1218, and T1021. It detects shadow-copy deletion, mass file encryption (entropy ≥7.5 bits/byte at ≥50 writes/s), canary file trips, ransom note drops, LOLBin staging (certutil/rundll32), SMB lateral movement, and WinRM remote execution. Events are evaluated in <1 ms using an O(1) type-indexed correlation engine."
          }
        },
        {
          "@type": "Question",
          "name": "Can AEGIS run without an internet connection or AI API key?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "Yes. Set AEGIS_AI_MODE=offline and the entire stack runs on deterministic Sigma rules, Jinja2 templates, and static playbooks. No LLM call is made. The RaaS intel feed falls back to its on-disk cache. All detection, blocking, and recovery functions continue to operate."
          }
        },
        {
          "@type": "Question",
          "name": "How does AEGIS compare to Wazuh or Elastic Security?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "AEGIS offers <1 ms in-memory Sigma evaluation versus 5–60 s pipeline latency in Wazuh or Elastic. It ships with a ransomware kill-chain out of the box, SSH/HTTP honeypots, RaaS threat intel, and snapshot recovery — none of which are available in Wazuh or OSSEC by default. Deployment is a single `docker compose up -d` versus multi-node agent rollout for Wazuh or weeks of Elasticsearch setup."
          }
        },
        {
          "@type": "Question",
          "name": "Is AEGIS free and open source?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "Yes. AEGIS is licensed under AGPL-3.0 and free to use, modify, and deploy. The full feature set — including ransomware detection, honeypots, Sigma rules, firewall enforcement, and recovery orchestration — is included in the open-source release."
          }
        }
      ]
    }
  ]
}
</script>
-->

<div align="center">

Built by the AEGIS contributors · [GitHub](https://github.com/alejadxr/AEGIS) · [Releases](https://github.com/alejadxr/AEGIS/releases) · AGPL-3.0

</div>
