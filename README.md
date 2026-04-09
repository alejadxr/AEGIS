<div align="center">

# AEGIS

### Autonomous Defense Platform

*Open-source autonomous cybersecurity platform. 11/11 detection score. 18-microsecond pipeline. AI-powered honeypot deception. Autonomous threat response. One command to deploy.*

[![Build](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Coverage](https://img.shields.io/badge/coverage-65%25-yellow)]()
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
[![Detection](https://img.shields.io/badge/detection-11%2F11-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.12-blue)]()
[![Docker](https://img.shields.io/badge/docker-compose-blue)]()

[What is AEGIS?](#what-is-aegis) · [Install](#5-minute-install) · [Detection](#detection-1111-verified) · [Architecture](#architecture) · [Modules](#modules) · [Contributing](#contributing)

</div>

---

## What is AEGIS?

AEGIS is an open-source autonomous cybersecurity defense platform that detects, analyzes, and neutralizes threats without human intervention. It combines:

- **5-layer detection pipeline** with 18-microsecond fast path
- **122 Sigma correlation rules** with chain detection and campaign tracking
- **AI-powered triage** with MITRE ATT&CK mapping and 13 specialized model routes
- **Honeypot deception** with breadcrumb traps and AI-driven smart honeypots
- **Autonomous response** with guardrails, playbooks, and full audit trail
- **Shared threat intelligence** across all AEGIS instances via central hub

All in a single `docker compose up`.

Built for security teams, DevOps engineers, and homelabs that need enterprise-grade detection at zero cost. AEGIS runs in production protecting real services — every AI decision is logged with model used, reasoning, confidence score, and token cost.

**Your servers defend themselves while you sleep.**

### What's New in v1.2

- **Live Dashboard** -- CrowdStrike Falcon-style SOC view with 10 WebSocket-powered widgets, never needs refresh
- **Ransomware Protection** -- Canary files + entropy detection + auto-rollback (VSS/Btrfs/LVM) in <500ms
- **EDR/XDR Core** -- ETW (Windows) + eBPF (Linux) telemetry, process tree reconstruction, 6 MITRE attack chain rules
- **Antivirus Engine** -- YARA + ClamAV + hash reputation cache, on-access + scheduled scans, encrypted quarantine
- **Configurable Firewall** -- YAML rule engine with UI editor, rate limiting, 6 default templates, hot reload
- **Honey-AI Deception** -- Auto-generate 50+ fake services with AI-generated content. 4 industry themes. Breadcrumb UUID tracking

---

## 5-Minute Install

**Prerequisites:** Docker and Docker Compose.

```bash
git clone https://github.com/diego1128256-cmd/AEGIS.git
cd aegis

# Configure
cp .env.example .env
# Edit .env -- at minimum set AEGIS_SECRET_KEY and POSTGRES_PASSWORD
# Optionally set OPENROUTER_API_KEY for AI features (free models available)

# Launch
docker compose up -d

# Open dashboard
open http://localhost:3000
```

The setup wizard at `/setup` walks you through creating your organization, configuring AI, discovering assets, and enabling shared threat intelligence. No default credentials — you create your own admin account.

### What Gets Deployed

| Container | Port | Purpose |
|-----------|------|---------|
| `aegis-api` | 8000 | FastAPI backend (140+ endpoints, 21 API routers) |
| `aegis-frontend` | 3000 | Next.js 14 dashboard (15 pages, real-time WebSocket) |
| `aegis-db` | 5432 | PostgreSQL 16 |
| `aegis-redis` | 6379 | Event bus and caching |

### Manual Installation

```bash
# Backend
cd backend && pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Frontend
cd frontend && npm install && npm run build && npm start
```

---

## Detection: 11/11 Verified

Every detection capability tested against real attack patterns:

| # | Attack Vector | Detection Layer | Response | Result |
|---|--------------|----------------|----------|--------|
| 1 | SQL Injection (UNION, blind, error-based) | L1: Middleware regex + double URL-decode | Auto-block IP | PASS |
| 2 | XSS (reflected, stored, DOM) | L1: Middleware + L2: Log watcher | Auto-block IP | PASS |
| 3 | Path Traversal (`../`, `%2e%2e`) | L1: Middleware | Auto-block IP | PASS |
| 4 | Command Injection (`;cat`, `$(...)`) | L1: Middleware | Auto-block IP | PASS |
| 5 | SSH Brute Force (5+ failures/5min) | L3: Sigma rule + honeypot capture | Auto-block + attacker profile | PASS |
| 6 | Port Scan (10+ ports/60s) | L2: Log watcher + L3: Correlation | Auto-block IP | PASS |
| 7 | Scanner Detection (nmap, sqlmap, nikto) | L1: User-Agent + probe paths | Auto-block IP | PASS |
| 8 | Breadcrumb Trap (stolen honeypot creds) | Phantom -> L1: Middleware chain | Critical incident + block | PASS |
| 9 | Lateral Movement (10+ internal hops) | L3: Sigma chain rule + campaign tracker | Isolate host (approval required) | PASS |
| 10 | C2 Beacon (periodic callbacks) | Quantum: Renyi entropy analysis | Auto-respond | PASS |
| 11 | Credential Stuffing (distributed) | L3: Correlation sliding window | Auto-block + feed report | PASS |

---

## vs Competition

| Capability | AEGIS | Wazuh | CrowdStrike | OSSEC |
|-----------|-------|-------|-------------|-------|
| Detection pipeline <300ms | Yes | No | Yes | No |
| Honeypot deception (SSH + HTTP) | Yes | No | No | No |
| Breadcrumb credential traps | Yes | No | No | No |
| AI triage (13 model routes) | Yes | No | Proprietary | No |
| MITRE ATT&CK auto-mapping | Yes | Yes | Yes | No |
| Sigma correlation (122 rules) | Yes | Yes | Proprietary | No |
| Behavioral ML (Isolation Forest) | Yes | No | Proprietary | No |
| Rust endpoint agent | Yes | C agent | Proprietary | C agent |
| Tauri desktop apps | Yes | Kibana | Proprietary | No |
| Multi-tenant isolation | Yes | Yes | Yes | No |
| Autonomous response + guardrails | Yes | Active Response | Yes | Active Response |
| Open source | AGPL-3.0 | GPL-2.0 | No | GPL-2.0 |
| Cost | Free | Free | $$$$ | Free |

---

## Architecture

### 5-Layer Detection Pipeline

```
    Incoming Event
         |
    [Layer 1] Attack Detector Middleware ──────────── runs on EVERY request
         |     6 regex categories + double URL-decode + breadcrumb detection
         |     Auto-block after 3 attacks/IP (5min sliding window, 18μs detection)
         |
    [Layer 2] Log Watcher ────────────────────────── PM2/system log tail
         |     7 security patterns, brute force tracker, rate limiter
         |
    [Layer 3] Sigma Correlation Engine ───────────── event correlation
         |     122 rules + 5 chain rules + campaign tracker
         |     10K event sliding window, group-by aggregation
         |
    [Layer 4] AI Engine (dual-mode) ──────────────── classification
         |     Fast path: Sigma -> IOC cache -> Playbook -> done (<300ms)
         |     Full path: AI triage -> classify -> incident -> actions (2-5s)
         |     MITRE ATT&CK mapping on every incident
         |
    [Layer 5] Auto-Response ──────────────────────── execution
              10 deterministic playbooks (<50ms each)
              Guardrails: auto_approve | require_approval | never_auto
              Dual-layer: Firewall API (iptables) + local middleware (403)
```

### System Overview

```
    +-------------+     +---------------+     +----------------+
    |   Desktop   |     |   Dashboard   |     |   Node Agent   |
    |   Manager   |     |   (Next.js)   |     |  (Tauri+Rust)  |
    |   (Tauri)   |     |   Port 3000   |     |   Per-host     |
    +------+------+     +-------+-------+     +-------+--------+
           |                    |                      |
           +---------+----------+----------------------+
                     |
              REST API + WebSocket (real-time push)
                     |
    +----------------+------------------+
    |       AEGIS Backend (FastAPI)     |
    |            Port 8000              |
    |                                   |
    |  +---------+  +----------+       |
    |  | Surface |  | Response |       |  140+ API endpoints
    |  |  (ASM)  |  |  (SOAR)  |       |  21 routers
    |  +---------+  +----------+       |  15 background services
    |  +---------+  +----------+       |
    |  | Phantom |  | Threats  |       |
    |  | (Decoy) |  |  (TIP)   |       |
    |  +---------+  +----------+       |
    |  +---------+                     |
    |  | Quantum |  (Premium)          |
    |  +---------+                     |
    +----------+-----------+-----------+
               |           |
    +----------+--+  +-----+----------+
    | PostgreSQL  |  |     Redis      |
    |   (data)    |  |  (event bus)   |
    +-------------+  +----------------+
```

### Data Flow

```
PM2/System Logs --> Log Watcher --> AI Engine --> Response Actions --> Audit Log
nmap/nuclei -----> Scheduled Scanner --> Assets/Vulns DB --> AI Risk Score
Honeypots -------> Interactions --> Attacker Profiler --> Threat Intel
External Feeds --> Threat Feeds --> IOC Database --> Correlation Engine
Node Agents -----> Heartbeat + Events --> Dashboard --> Alerts
```

---

## Modules

### Surface -- Attack Surface Management

Continuous discovery and vulnerability assessment of your infrastructure.

- **Asset Discovery** -- nmap service detection with OS fingerprinting (`-sV -O`)
- **Vulnerability Scanning** -- Nuclei integration with AI-powered risk scoring
- **SBOM Analysis** -- Software bill of materials for dependency tracking
- **Hardening Checks** -- Configuration audits with actionable remediation
- **Scheduled Scans** -- Full scan (2h), quick scan (30min), discovery (1h) on configurable cycles

### Response -- Autonomous Incident Response (SOAR)

AI-powered alert triage with autonomous action execution.

- **Sub-300ms Fast Path** -- Sigma check -> IOC cache -> playbook -> done, no AI round-trip needed
- **Agentic AI Pipeline** -- triage -> classify -> decide -> execute -> verify -> audit (2-5s for complex threats)
- **10 Deterministic Playbooks** -- `auto_block_brute_force`, `auto_block_sql_injection`, `auto_respond_c2_beacon`, and 7 more
- **Guardrail System** -- Fully autonomous by default (all actions `auto_approve`). Users can override any action to `require_approval` or `never_auto` per client in Settings → Guardrails
- **Dual-layer Blocking** -- Firewall API (real iptables on a network device) + local middleware (403)
- **Full Audit Trail** -- Model used, reasoning chain, confidence score, token cost for every AI decision

### Phantom -- Honeypot Deception

Deploy decoy services that attract, profile, and trap attackers.

- **SSH Honeypot** (port 2222) -- Paramiko server with fake Ubuntu banner, captures credentials and commands
- **HTTP Honeypot** (port 8888) -- Rotating decoy pages: Jenkins, WordPress, phpMyAdmin
- **Breadcrumb Traps** -- Fake `.env` files with trap credentials; attacker steals from honeypot -> tries on real API -> critical incident + auto-block
- **Template Rotation** -- Decoy pages rotate every 4 hours to avoid fingerprinting
- **Attacker Profiling** -- TTPs, tools, geolocation, threat scoring per IP with MITRE ATT&CK mapping

#### Smart Honeypots (Enterprise)

AI-driven deception that imitates real applications:

- **Smart HTTP** -- Serves realistic Next.js/WordPress/Laravel apps with login forms, dashboards, admin panels. AI generates dynamic responses. Auto-plants breadcrumb `.env` files with trackable fake API keys
- **Smart API** -- Full REST API mimic (`/api/users`, `/api/config`, `/api/admin`). Returns plausible JSON. Detects 6 injection types (SQLi, XSS, path traversal, command injection, template injection, credential stuffing)
- **Smart Database** -- MySQL wire protocol with fake schemas (production, users, billing). Allows SELECT queries on fake data. Detects 14 SQL injection patterns. Logs every query

### Threats -- Threat Intelligence Platform

Aggregate, correlate, and share threat intelligence.

- **5 Threat Feeds** -- AbuseIPDB, AlienVault OTX, Emerging Threats, Tor Exit Nodes, Feodo Tracker
- **STIX 2.1 Export** -- Standard format for sharing IOCs
- **Intel Cloud** -- Hub/client architecture for sharing IOCs across AEGIS instances
- **Campaign Tracking** -- Detect coordinated attacks spanning recon -> exploit -> persist -> exfil -> lateral phases

### Quantum -- Advanced Analytics

Information-theoretic detection for advanced and evasive threats.

- **Renyi Entropy Analysis** -- Detect C2 beacons (Cobalt Strike, Metasploit, Sliver, Covenant) by entropy profile
- **Grover's Algorithm Calculator** -- Post-quantum cryptographic strength assessment
- **Adversarial ML Detection** -- Identify model poisoning and evasion attempts
- **Steganography Detection** -- Flag files with entropy distributions that deviate from expected file-type norms

### Live Dashboard -- Real-Time SOC View

CrowdStrike Falcon-style dense dashboard. Never needs manual refresh.

- **WebSocket streaming** -- Events push to dashboard in <200ms via topic-based subscriptions
- **Live attack feed** -- Incidents slide in with severity-coded animations
- **Global threat map** -- Pulsing dots for each attacker IP by country
- **Events/sec chart** -- 60-second rolling line chart
- **Top 10 tables** -- Attackers, targets, attack types (refresh every 2s)
- **Raw log stream** -- Terminal-style scrolling log with level color coding
- **Node heartbeat grid** -- Green/red dots for every enrolled agent
- **Counters bar** -- events/sec, blocked/min, AI decisions/min, incidents open

### Ransomware Protection

Detect and stop ransomware in <500ms. Auto-rollback encrypted files.

- **Canary files** -- 10 hidden sentinel files planted in Documents/Desktop/Downloads. Any modification = trip wire
- **Encryption behavior detection** -- Mass file extension changes (>20/5s), Shannon entropy spike (>7.5 bits), VSS deletion attempts
- **Instant kill** -- Process tree terminated via `TerminateProcess` (Windows) / `SIGKILL` (Linux) within milliseconds
- **Auto-rollback** -- Restore encrypted files from VSS shadow copies (Windows), Btrfs/LVM snapshots (Linux), or userspace ring buffer (ext4/xfs fallback)
- **Forensic chain** -- Complete process tree, command lines, affected files uploaded to dashboard as CRITICAL incident

### EDR/XDR Core

Enterprise endpoint detection and response. Process trees, attack chain reconstruction, kernel-level visibility.

- **ETW telemetry** (Windows) -- Kernel-Process, Kernel-Network, Kernel-File, Registry, AMSI providers via `ferrisetw`
- **eBPF telemetry** (Linux) -- `sched_process_exec`, `sys_enter_connect`, `sys_enter_openat`, `security_inode_unlink` via `aya`
- **Process tree reconstruction** -- Full ancestor/descendant tree for any process at any time
- **Attack chain detection** -- 6 Sigma chain rules: macro malware, phishing payload, credential dumping, LOTL download, Office child shell, rundll32 abuse
- **Tiered fallback** -- Tier 1 (no privileges, `sysinfo` polling) → Tier 2 (admin, ETW/eBPF) → Tier 3 (kernel driver, future)
- **Gzip batching** -- 1-second event batches compressed for upload, 16K event ring buffer

### Antivirus Engine

Signature-based detection complementing behavioral analysis.

- **YARA scanning** -- On-access + scheduled full scans using `yara-rs`
- **ClamAV bridge** -- Optional integration via `clamscan` CLI
- **Hash reputation cache** -- `sled` embedded DB for known-good files (>95% cache hit after 1 week)
- **Quarantine** -- Infected files XOR-obfuscated and moved to `~/.aegis/quarantine/` with metadata sidecar
- **Signature updates** -- Daily auto-pull from YARA-Forge community rules + MalwareBazaar SHA256 hashes
- **EICAR detection** -- Built-in for testing, works even without YARA ruleset

### Configurable Firewall

Replace static detection rules with a flexible YAML-based rule engine.

- **YAML DSL** -- Define rules with match conditions (source_ip CIDR, port, protocol, user-agent, rate_limit) and actions (block_ip, allow, alert, quarantine_host)
- **Priority-based evaluation** -- Higher priority rules win. Allow short-circuits.
- **Stateful rate limiting** -- Track per-IP request counts with time windows
- **Hot reload** -- Rules apply in <1s without restart via cache invalidation
- **Rule tester** -- "What-if" testing against synthetic events from the UI
- **6 default templates** -- SSH brute force, port scan, scanner UA block, office IP allowlist, malware quarantine, geo-block

### Honey-AI -- Deception Engineering at Scale (Enterprise)

Auto-generate massive fake infrastructure. The killer differentiator.

- **Deception campaigns** -- Deploy 50+ fake services in <30s with a single click
- **4 industry themes** -- Fintech (banking, payments), Healthcare (patient records), E-commerce (orders, cards), DevOps (API keys, infra configs)
- **AI-generated content** -- LLM creates realistic responses for fake web apps, APIs, databases. Falls back to Faker if no AI key configured
- **Breadcrumb tracking** -- Every fake asset embeds a unique UUID marker. If that UUID appears in real service logs → CRITICAL alert linking the two events
- **Service mix control** -- Sliders for web/db/files/admin ratio per campaign
- **Auto-rotation** -- Decoys mutate every 6 hours to avoid attacker fingerprinting
- **Campaign builder UI** -- Step-by-step wizard: Theme → Service Mix → Decoy Count → Deploy

---

## Desktop Apps

### AEGIS Manager (Tauri v2)

Full dashboard in a native desktop window. Connects to your AEGIS server instance.

- Windows (.msi, .exe) and macOS (.dmg) installers
- Embedded Rust agent: system monitoring, FIM, network discovery
- ~9MB installer size

### AEGIS Node Agent (Tauri v2 + Rust)

Full EDR agent deployed on monitored endpoints. Windows + Linux.

- **~7MB** installer, runs silently in system tray
- **Ransomware protection** -- Canary files, entropy detection, process kill, auto-rollback (VSS/Btrfs/LVM)
- **EDR/XDR telemetry** -- ETW (Windows) / eBPF (Linux) for process, network, file, registry events
- **Antivirus scanning** -- YARA + ClamAV on-access + scheduled full scans with hash cache
- **Process tree tracking** -- Full parent-child chains with command line capture
- **Attack chain detection** -- Sigma rules for LOTL, macro malware, credential dumping
- **Windows Event Log** monitoring (process creation 4688, failed logon 4625, service install 4697, PowerShell 4104)
- **Network monitoring** with per-process connection tracking
- **Registry persistence** detection (Run/RunOnce keys)
- **Living-off-the-Land** detection (certutil, bitsadmin, `powershell -enc`, mshta, regsvr32)
- **File Integrity Monitoring** (.ssh directories, System32)
- **Auto-enrollment** with enrollment codes, 30s heartbeat + exponential backoff
- **Quarantine** -- Infected files isolated in encrypted quarantine directory
- **Tiered architecture** -- Works without admin (polling), better with admin (ETW/eBPF), best with kernel driver (future)

---

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
# Required
AEGIS_SECRET_KEY=your-random-secret       # Change from default
POSTGRES_PASSWORD=your-db-password         # Change from default

# AI (optional -- free models available via OpenRouter)
OPENROUTER_API_KEY=your-key                # https://openrouter.ai

# Or use Ollama for fully local AI (no external calls):
# OPENROUTER_BASE_URL=http://host.docker.internal:11434/v1
# OPENROUTER_API_KEY=ollama

# Threat feeds (optional, free tiers)
ABUSEIPDB_API_KEY=your-key                 # 1000 checks/day free
OTX_API_KEY=your-key                       # AlienVault OTX (free)

# Notifications (optional)
WEBHOOK_URL=https://...                    # Slack/Discord webhook
SMTP_HOST=smtp.example.com                 # Email alerts
```

### AI Provider Support

AEGIS routes AI tasks across 13 specialized model configurations:

| Provider | Setup | Cost |
|----------|-------|------|
| **OpenRouter** | Set `OPENROUTER_API_KEY` | Free models available |
| **Ollama** | Set base URL to `http://host.docker.internal:11434/v1` | Free (local) |
| **OpenAI** | Set base URL to `https://api.openai.com/v1` | Pay-per-token |
| **Anthropic** | Via OpenRouter or direct | Pay-per-token |

AI features degrade gracefully. The platform works without any AI key using deterministic Sigma rules and playbooks only.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.12, FastAPI, SQLAlchemy (async), APScheduler |
| Frontend | Next.js 14, TypeScript, Tailwind CSS, Recharts, react-simple-maps |
| Database | PostgreSQL 16 (asyncpg), Redis 7 (event bus) |
| AI/ML | OpenRouter (13 model routes), scikit-learn (Isolation Forest), sentence-transformers (RAG) |
| Desktop | Tauri v2, Rust |
| Endpoint Agent | Rust (sysinfo, notify, tokio) |
| Scanning | nmap, Nuclei, subfinder, httpx |
| Deception | Paramiko (SSH honeypot), aiohttp (HTTP honeypot) |
| Containers | Docker Compose, multi-stage builds |

---

## API Reference

All endpoints under `/api/v1/` require authentication via `X-API-Key` header or JWT Bearer token.

| Router | Endpoints | Description |
|--------|-----------|-------------|
| `auth` | 10 | Register, login, JWT, RBAC (admin/analyst/viewer) |
| `dashboard` | 5 | Overview stats, timeline, threat map, live metrics |
| `surface` | 12 | Scans, assets, vulnerabilities, hardening, SBOM |
| `response` | 12 | Incidents, actions, guardrails, AI analysis |
| `phantom` | 8 | Honeypots, interactions, attacker profiles |
| `threats` | 5 | IOC search, threat feeds, STIX export |
| `correlation` | 5 | Sigma rules, chain detection, campaigns |
| `behavioral` | 6 | ML baselines, anomaly scores, retraining |
| `network` | 9 | NDR, DNS monitoring, entropy analysis |
| `quantum` | 14 | Entropy analyzer, Grover calc, adversarial ML |
| `nodes` | 10 | Endpoint agent enrollment, heartbeat, events |
| `reports` | 7 | PDF generation, scheduled reports |
| `settings` | 8 | Client config, scan intervals, notifications |
| `payments` | 3 | PayPal checkout, tier upgrades |
| `onboarding` | 1 | Self-serve org creation + admin signup |
| `admin` | 3 | Blocked IPs management, detection stats |
| `counter-attack` | 4 | AI attacker analysis, counter-measures |
| `intel-hub` | 4 | MongoDB shared threat intel |
| `ask` | 1 | Natural language queries to the AI engine |
| `firewall` | 8 | Configurable rule CRUD, testing, templates |
| `ransomware` | 2 | Agent ransomware incident events |
| `edr` | 4 | Process tree, attack chains, event ingestion |
| `antivirus` | 6 | Signatures, quarantine, hash lookup, scan trigger |
| `deception` | 7 | Honey-AI campaigns, breadcrumb hits, themes |
| `updates` | 5 | Auto-update status, check, install, config |

WebSocket endpoint at `/ws` provides real-time event streaming with topic-based subscriptions and auto-reconnect.

---

## Project Structure

```
aegis/
├── backend/                    # FastAPI application
│   ├── app/
│   │   ├── api/                # 27 API routers (170+ endpoints)
│   │   ├── core/               # Auth, events, AI, guardrails, attack detector, firewall engine
│   │   ├── models/             # 18 SQLAlchemy models
│   │   ├── modules/
│   │   │   ├── surface/        # ASM: discovery, nuclei, risk scoring, SBOM
│   │   │   ├── response/       # SOAR: ingestion, analysis, playbooks, responder
│   │   │   ├── phantom/        # Deception: SSH/HTTP/Smart honeypots, profiler, rotation
│   │   │   ├── network/        # NDR: entropy analysis, DNS monitor
│   │   │   └── quantum/        # Renyi entropy, Grover calc, adversarial detection
│   │   └── services/           # 20 background services
│   │       └── honey_ai/       # Deception campaign orchestrator, content generator, breadcrumbs
│   ├── tests/                  # pytest suite
│   └── Dockerfile
├── frontend/                   # Next.js 14 dashboard
│   ├── src/
│   │   ├── app/dashboard/      # 21 pages (live, firewall, edr, antivirus, deception, ...)
│   │   ├── components/
│   │   │   ├── shared/         # Design system components
│   │   │   ├── live/           # Live dashboard widgets (AttackFeed, Top10, RawLogStream, ...)
│   │   │   ├── firewall/       # Rule editor, tester
│   │   │   ├── deception/      # Campaign builder, breadcrumb hits
│   │   │   └── edr/            # Process tree viewer
│   │   └── lib/                # API client, WebSocket client, types
│   └── Dockerfile
├── agent-rust/                 # Standalone Rust EDR agent prototype
├── desktop-tauri/              # AEGIS Manager desktop app (Tauri v2)
├── node-tauri/                 # AEGIS Node Agent (Tauri v2 + Rust)
│   └── src-tauri/src/
│       ├── ransomware/         # Canary, entropy, detector, killer, rollback (Win+Linux)
│       ├── edr/                # ETW (Win), eBPF (Linux), event buffer, uploader
│       └── antivirus/          # YARA, ClamAV, hash cache, quarantine
├── docker-compose.yml          # One-command full stack deployment
├── .env.example                # Configuration template
└── docs/                       # Architecture and planning documentation
```

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on development workflow, code style, and testing.

Areas where help is especially valued:

- **Sigma rules** -- Adding detection rules for new attack patterns
- **Threat feeds** -- Integrating additional intelligence sources
- **Endpoint agents** -- Linux and macOS agent builds
- **Documentation** -- Deployment guides, tutorials, API docs
- **Testing** -- Expanding test coverage

## Security

Found a vulnerability? Please report it responsibly. See [SECURITY.md](SECURITY.md) for our disclosure policy.

---

## Pricing

AEGIS is fully open source under AGPL-3.0. The free tier is production-ready and includes everything needed to defend real infrastructure. Enterprise is a custom-priced tier for companies that need advanced modules, unlimited scale, and dedicated support.

| | Free · Open Source | Enterprise |
|---|---|---|
| **Detection pipeline (5 layers, 18μs)** | ✓ | ✓ |
| **122 Sigma rules + 10 playbooks** | ✓ | ✓ |
| **SSH + HTTP honeypots + breadcrumb traps** | ✓ | ✓ |
| **AI triage with MITRE ATT&CK mapping** | ✓ | ✓ |
| **Counter-attack AI** | ✓ | ✓ |
| **Behavioral ML (Isolation Forest)** | ✓ | ✓ |
| **Shared threat intelligence** | ✓ | ✓ |
| **Dashboard + RBAC + multi-tenant** | ✓ | ✓ |
| **Rust endpoint agent (EDR + AV + ransomware)** | ✓ | ✓ |
| **Live real-time dashboard (WebSocket)** | ✓ | ✓ |
| **Configurable firewall (YAML rule engine)** | ✓ | ✓ |
| **Ransomware protection + auto-rollback** | ✓ | ✓ |
| **Self-hosted with Docker Compose** | ✓ | ✓ |
| **Auto-updates from GitHub** | ✓ | ✓ |
| Nodes | 20 | Unlimited |
| Assets | 100 | Unlimited |
| Users | 3 | Unlimited |
| Smart Honeypots (AI-driven deception) | — | ✓ |
| Quantum entropy analysis | — | ✓ |
| Grover's quantum calculator | — | ✓ |
| Adversarial ML detection | — | ✓ |
| SBOM scanner (NIS2 / DORA) | — | ✓ |
| Compliance dashboard (ISO 27001, NIS2, SOC 2) | — | ✓ |
| Advanced PDF reports + scheduling | — | ✓ |
| SSO (SAML / OIDC) | — | ✓ |
| Custom Sigma rules | — | ✓ |
| SLA + dedicated support | — | ✓ |

Contact [alejandxr@icloud.com](mailto:alejandxr@icloud.com) for Enterprise pricing and deployment.

---

## Counter-Attack (Active Defense)

When a high-severity attack is detected, AEGIS can analyze the attacker and recommend counter-measures using an uncensored AI model:

- **Reconnaissance** — Scan attacker's IP for open ports and services
- **Intelligence** — Geolocation, hosting provider, reputation lookup
- **Deception** — Feed false data, redirect to more honeypots
- **Reporting** — Auto-report to AbuseIPDB with evidence
- **Tarpit** — Throttle attacker connections

All counter-attack actions execute autonomously by default. Override to `require_approval` per action in Settings → Guardrails if manual review is needed.

---

## Shared Threat Intelligence

AEGIS instances can share anonymized threat indicators via a central MongoDB hub:

- **What's shared**: Hashed IPs, attack patterns, IOCs, MITRE techniques
- **What's NOT shared**: Hostnames, internal IPs, user data, configurations
- **Opt-in**: Enabled in setup wizard or Settings → Threat Intelligence
- **Dual collections**: Your detections (`aegis_threats`) never mix with external feeds (`external_feeds`)

---

## Roadmap

- [x] ~~Live real-time dashboard (WebSocket streaming)~~
- [x] ~~Ransomware protection (canary + entropy + auto-rollback)~~
- [x] ~~EDR/XDR core (ETW/eBPF + process tree + attack chains)~~
- [x] ~~Antivirus engine (YARA + ClamAV + hash reputation)~~
- [x] ~~Configurable firewall (YAML rule engine + UI)~~
- [x] ~~Honey-AI deception at scale (campaign builder + breadcrumbs)~~
- [x] ~~Linux endpoint agent support~~
- [x] ~~Auto-updates from GitHub releases~~
- [ ] Voice alerts (Kokoro TTS — AEGIS speaks during critical incidents)
- [ ] Import 100+ rules from SigmaHQ community repository
- [ ] Kubernetes deployment manifests (Helm chart)
- [ ] Mobile app (React Native)
- [ ] Live public demo sandbox
- [ ] Plugin system for custom detection modules
- [ ] macOS endpoint agent
- [ ] SOAR playbook marketplace

---

## License

AEGIS is licensed under the [GNU Affero General Public License v3.0](LICENSE).

You can use, modify, and distribute this software freely. If you run a modified version as a network service, you must make the source code available to users of that service.

---

<div align="center">

Built by the AEGIS contributors

</div>
