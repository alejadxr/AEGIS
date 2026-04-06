# AEGIS Architecture Contract

All agents MUST follow this document as the single source of truth.

## Project Structure

```
AEGIS/
├── backend/                 ← FastAPI (Python 3.11+)
│   ├── app/
│   │   ├── main.py          ← FastAPI entry, CORS, lifespan
│   │   ├── config.py        ← Pydantic Settings from .env
│   │   ├── database.py      ← SQLAlchemy async engine + session
│   │   ├── core/
│   │   │   ├── auth.py      ← API key auth + JWT
│   │   │   ├── openrouter.py ← OpenRouter client with model routing
│   │   │   ├── events.py    ← In-memory event bus (Redis-like)
│   │   │   └── guardrails.py ← Action approval system
│   │   ├── api/
│   │   │   ├── auth.py      ← /api/auth/*
│   │   │   ├── dashboard.py ← /api/dashboard/*
│   │   │   ├── surface.py   ← /api/surface/*
│   │   │   ├── response.py  ← /api/response/*
│   │   │   ├── phantom.py   ← /api/phantom/*
│   │   │   ├── threats.py   ← /api/threats/*
│   │   │   └── settings.py  ← /api/settings/*
│   │   ├── models/
│   │   │   ├── base.py      ← Base model, common mixins
│   │   │   ├── client.py    ← Client/tenant model
│   │   │   ├── asset.py     ← Discovered assets
│   │   │   ├── vulnerability.py ← Found vulns
│   │   │   ├── incident.py  ← Security incidents
│   │   │   ├── action.py    ← Response actions taken
│   │   │   ├── honeypot.py  ← Honeypot configs & interactions
│   │   │   ├── threat_intel.py ← IOCs, TTPs
│   │   │   └── audit_log.py ← AI decision audit trail
│   │   ├── services/
│   │   │   ├── ai_engine.py  ← Agentic AI decision engine
│   │   │   ├── scanner.py    ← Scanning orchestration
│   │   │   ├── reporter.py   ← Report generation
│   │   │   └── notifier.py   ← Notifications (webhook, email)
│   │   └── modules/
│   │       ├── surface/
│   │       │   ├── discovery.py  ← Asset discovery pipeline
│   │       │   ├── nuclei.py     ← Nuclei scanner wrapper
│   │       │   ├── risk_scorer.py ← AI risk scoring
│   │       │   └── hardener.py   ← Auto-hardening scripts
│   │       ├── response/
│   │       │   ├── ingestion.py  ← Alert ingestion (syslog, webhook, file)
│   │       │   ├── analyzer.py   ← AI threat analysis
│   │       │   ├── responder.py  ← Active response executor
│   │       │   └── playbooks.py  ← Dynamic playbook engine
│   │       └── phantom/
│   │           ├── orchestrator.py ← Honeypot deployment/management
│   │           ├── rotation.py    ← Dynamic rotation engine
│   │           ├── profiler.py    ← Attacker profiling
│   │           └── intel.py       ← Threat intel generation
│   ├── requirements.txt
│   ├── Dockerfile
│   └── alembic.ini
├── frontend/                ← Next.js 14 + Tailwind + TypeScript
│   ├── src/
│   │   ├── app/
│   │   │   ├── layout.tsx
│   │   │   ├── page.tsx     ← Login/landing
│   │   │   └── dashboard/
│   │   │       ├── layout.tsx
│   │   │       ├── page.tsx ← Main dashboard overview
│   │   │       ├── surface/page.tsx
│   │   │       ├── response/page.tsx
│   │   │       ├── phantom/page.tsx
│   │   │       ├── threats/page.tsx
│   │   │       └── settings/page.tsx
│   │   ├── components/
│   │   │   ├── dashboard/   ← Overview cards, stats
│   │   │   ├── surface/    ← Asset table, risk scores, scan controls
│   │   │   ├── response/   ← Incident timeline, action log
│   │   │   ├── phantom/    ← Honeypot map, attacker profiles
│   │   │   ├── shared/     ← Sidebar, header, charts, modals
│   │   │   └── ui/         ← Base UI primitives
│   │   └── lib/
│   │       ├── api.ts      ← API client (fetch wrapper)
│   │       ├── types.ts    ← Shared TypeScript types
│   │       ├── utils.ts    ← Utility functions
│   │       └── constants.ts
│   ├── package.json
│   ├── tailwind.config.ts
│   ├── tsconfig.json
│   └── next.config.js
├── docker-compose.yml
├── .env.example
├── scripts/
│   ├── setup.sh           ← One-command local setup
│   ├── seed.py            ← Seed demo data
│   └── test_openrouter.py ← Verify OpenRouter connection
└── ARCHITECTURE.md        ← THIS FILE
```

## Database Schema

Using SQLite for local dev, PostgreSQL for production.
SQLAlchemy with async support (aiosqlite / asyncpg).

### Core Tables

```sql
-- Multi-tenant clients
clients (
  id UUID PK DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  slug VARCHAR(100) UNIQUE NOT NULL,
  api_key VARCHAR(255) UNIQUE NOT NULL,
  settings JSONB DEFAULT '{}',
  guardrails JSONB DEFAULT '{}',  -- action approval config
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
)

-- Discovered assets (Surface)
assets (
  id UUID PK,
  client_id UUID FK -> clients.id,
  hostname VARCHAR(500),
  ip_address VARCHAR(45),
  asset_type VARCHAR(50),  -- 'web', 'server', 'api', 'dns', 'cloud'
  ports JSONB DEFAULT '[]',
  technologies JSONB DEFAULT '[]',
  status VARCHAR(20) DEFAULT 'active',  -- active, inactive, decommissioned
  risk_score FLOAT DEFAULT 0,
  last_scan_at TIMESTAMP,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
)

-- Vulnerabilities found (Surface)
vulnerabilities (
  id UUID PK,
  client_id UUID FK -> clients.id,
  asset_id UUID FK -> assets.id,
  title VARCHAR(500) NOT NULL,
  description TEXT,
  severity VARCHAR(20) NOT NULL,  -- critical, high, medium, low, info
  cvss_score FLOAT,
  cve_id VARCHAR(20),
  template_id VARCHAR(200),  -- nuclei template
  evidence TEXT,
  status VARCHAR(20) DEFAULT 'open',  -- open, remediated, accepted, false_positive
  ai_risk_score FLOAT,  -- contextual risk (CVSS + business context)
  ai_analysis TEXT,  -- AI reasoning
  remediation TEXT,
  found_at TIMESTAMP DEFAULT NOW(),
  remediated_at TIMESTAMP
)

-- Security incidents (Response)
incidents (
  id UUID PK,
  client_id UUID FK -> clients.id,
  title VARCHAR(500) NOT NULL,
  description TEXT,
  severity VARCHAR(20) NOT NULL,  -- critical, high, medium, low
  status VARCHAR(20) DEFAULT 'open',  -- open, investigating, contained, resolved
  source VARCHAR(100),  -- 'wazuh', 'honeypot', 'manual', 'surface_scan'
  mitre_technique VARCHAR(20),
  mitre_tactic VARCHAR(50),
  source_ip VARCHAR(45),
  target_asset_id UUID FK -> assets.id,
  ai_analysis JSONB,  -- full AI reasoning chain
  raw_alert JSONB,
  detected_at TIMESTAMP DEFAULT NOW(),
  contained_at TIMESTAMP,
  resolved_at TIMESTAMP
)

-- Response actions taken (Response)
actions (
  id UUID PK,
  incident_id UUID FK -> incidents.id,
  client_id UUID FK -> clients.id,
  action_type VARCHAR(50) NOT NULL,  -- block_ip, isolate_host, revoke_creds, etc.
  target VARCHAR(500),
  parameters JSONB DEFAULT '{}',
  status VARCHAR(20) DEFAULT 'pending',  -- pending, approved, executed, failed, rolled_back
  requires_approval BOOLEAN DEFAULT false,
  approved_by VARCHAR(100),
  ai_reasoning TEXT,  -- why AI chose this action
  result JSONB,
  executed_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW()
)

-- Honeypot configurations (Phantom)
honeypots (
  id UUID PK,
  client_id UUID FK -> clients.id,
  name VARCHAR(200) NOT NULL,
  honeypot_type VARCHAR(50) NOT NULL,  -- ssh, http, smb, api, database, smtp
  config JSONB DEFAULT '{}',
  status VARCHAR(20) DEFAULT 'stopped',  -- running, stopped, rotating
  ip_address VARCHAR(45),
  port INTEGER,
  last_rotation TIMESTAMP,
  interactions_count INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW()
)

-- Honeypot interactions (Phantom)
honeypot_interactions (
  id UUID PK,
  honeypot_id UUID FK -> honeypots.id,
  client_id UUID FK -> clients.id,
  source_ip VARCHAR(45) NOT NULL,
  source_port INTEGER,
  protocol VARCHAR(20),
  commands JSONB DEFAULT '[]',
  credentials_tried JSONB DEFAULT '[]',
  payloads JSONB DEFAULT '[]',
  session_duration INTEGER,  -- seconds
  attacker_profile_id UUID FK -> attacker_profiles.id,
  raw_log TEXT,
  timestamp TIMESTAMP DEFAULT NOW()
)

-- Attacker profiles (Phantom)
attacker_profiles (
  id UUID PK,
  client_id UUID FK -> clients.id,
  source_ip VARCHAR(45),
  known_ips JSONB DEFAULT '[]',
  tools_used JSONB DEFAULT '[]',
  techniques JSONB DEFAULT '[]',  -- MITRE ATT&CK
  sophistication VARCHAR(20),  -- script_kiddie, intermediate, advanced, apt
  geo_data JSONB,
  first_seen TIMESTAMP,
  last_seen TIMESTAMP,
  total_interactions INTEGER DEFAULT 0,
  ai_assessment TEXT
)

-- Threat intelligence (Shared)
threat_intel (
  id UUID PK,
  ioc_type VARCHAR(50) NOT NULL,  -- ip, domain, hash, url, email
  ioc_value VARCHAR(500) NOT NULL,
  threat_type VARCHAR(100),
  confidence FLOAT,
  source VARCHAR(100),  -- internal, honeypot, community
  tags JSONB DEFAULT '[]',
  first_seen TIMESTAMP DEFAULT NOW(),
  last_seen TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP
)

-- AI Decision Audit Log (Core)
audit_log (
  id UUID PK,
  client_id UUID FK -> clients.id,
  incident_id UUID FK -> incidents.id,
  action VARCHAR(100) NOT NULL,
  model_used VARCHAR(100),
  input_summary TEXT,
  ai_reasoning TEXT,
  decision TEXT,
  confidence FLOAT,
  tokens_used INTEGER,
  cost_usd FLOAT,
  latency_ms INTEGER,
  timestamp TIMESTAMP DEFAULT NOW()
)
```

## API Endpoints

All endpoints prefixed with `/api/v1/`
Auth: API key in `X-API-Key` header or Bearer JWT token.

### Auth
- POST /api/v1/auth/login - Get JWT token
- POST /api/v1/auth/api-key - Generate API key
- GET  /api/v1/auth/me - Current user info

### Dashboard
- GET /api/v1/dashboard/overview - Stats cards (total assets, open vulns, active incidents, honeypot interactions)
- GET /api/v1/dashboard/timeline - Recent activity timeline
- GET /api/v1/dashboard/threat-map - Threat geography data

### Surface
- POST /api/v1/surface/scan - Launch new scan (accepts target domain/IP)
- GET  /api/v1/surface/scans - List scans with status
- GET  /api/v1/surface/scans/:id - Scan details + results
- GET  /api/v1/surface/assets - List discovered assets (filterable)
- GET  /api/v1/surface/assets/:id - Asset details + vulns
- GET  /api/v1/surface/vulnerabilities - List vulns (filterable by severity)
- PATCH /api/v1/surface/vulnerabilities/:id - Update vuln status
- POST /api/v1/surface/harden - Run auto-hardening on target

### Response
- POST /api/v1/response/alerts - Ingest alert (webhook endpoint)
- GET  /api/v1/response/incidents - List incidents
- GET  /api/v1/response/incidents/:id - Incident details + actions
- POST /api/v1/response/incidents/:id/analyze - Trigger AI analysis
- GET  /api/v1/response/actions - List response actions
- POST /api/v1/response/actions/:id/approve - Approve pending action
- POST /api/v1/response/actions/:id/rollback - Rollback action
- GET  /api/v1/response/guardrails - Get guardrail config
- PUT  /api/v1/response/guardrails - Update guardrail config

### Phantom
- GET  /api/v1/phantom/honeypots - List honeypots
- POST /api/v1/phantom/honeypots - Deploy new honeypot
- PATCH /api/v1/phantom/honeypots/:id - Update honeypot config
- DELETE /api/v1/phantom/honeypots/:id - Remove honeypot
- POST /api/v1/phantom/honeypots/:id/rotate - Force rotation
- GET  /api/v1/phantom/interactions - List interactions (filterable)
- GET  /api/v1/phantom/attackers - List attacker profiles
- GET  /api/v1/phantom/attackers/:id - Attacker profile details

### Threats
- GET  /api/v1/threats/intel - List threat intel IOCs
- POST /api/v1/threats/intel - Add IOC manually
- GET  /api/v1/threats/intel/search?q= - Search IOCs
- GET  /api/v1/threats/feed - Export threat feed (JSON/STIX)

### Settings
- GET  /api/v1/settings/client - Client settings
- PUT  /api/v1/settings/client - Update settings
- GET  /api/v1/settings/models - Available AI models + routing config
- PUT  /api/v1/settings/models - Update model routing
- GET  /api/v1/settings/notifications - Notification config
- PUT  /api/v1/settings/notifications - Update notifications

## OpenRouter Integration

Base URL: `https://openrouter.ai/api/v1/chat/completions`
Auth: `Authorization: Bearer $OPENROUTER_API_KEY`

### Model Routing Strategy (Free Models)

```python
MODEL_ROUTING = {
    "triage": "openrouter/quasar-alpha",          # Fast triage
    "classification": "openrouter/hunter-alpha",    # 1M context, deep analysis
    "investigation": "openrouter/hunter-alpha",     # Complex reasoning
    "code_analysis": "openai/gpt-oss-120b:free",   # Code/payload analysis
    "report": "nvidia/nemotron-3-super-120b-a12b:free",  # Report generation
    "decoy_content": "minimax/minimax-m2.5:free",  # Generate fake content
    "quick_decision": "stepfun/step-3.5-flash:free", # Sub-second decisions
    "risk_scoring": "arcee-ai/trinity-large-preview:free", # Risk assessment
    "healing": "openrouter/healer-alpha",          # Remediation suggestions
    "fallback": "openai/gpt-oss-20b:free"          # Lightweight fallback
}
```

### Request Format (OpenAI-compatible)

```python
import httpx

async def query_openrouter(messages: list, task_type: str) -> dict:
    model = MODEL_ROUTING.get(task_type, MODEL_ROUTING["fallback"])
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "HTTP-Referer": "https://github.com/aegis-defense/aegis",
                "X-Title": "AEGIS Defense Platform"
            },
            json={
                "model": model,
                "messages": messages,
                "temperature": 0.3,  # Low temp for security decisions
                "max_tokens": 4096
            }
        )
        return response.json()
```

## Frontend Design System

### Theme: Dark Cyber Security

```
Primary:    #00F0FF (Cyan - AEGIS signature color)
Secondary:  #7B61FF (Purple - alerts, AI actions)
Danger:     #FF3B5C (Red - critical severity)
Warning:    #FFB800 (Amber - high severity)
Success:    #00D68F (Green - resolved, healthy)
Info:       #3B82F6 (Blue - informational)

Background: #0A0E1A (Deep dark navy)
Surface:    #111827 (Card backgrounds)
Border:     #1F2937 (Subtle borders)
Text:       #F9FAFB (Primary text)
Text Muted: #9CA3AF (Secondary text)

Font:       Inter (UI), JetBrains Mono (code/data)
```

### Dashboard Layout

```
┌──────────────────────────────────────────────────────┐
│  AEGIS        [Surface] [Response] [Phantom]  [⚙️] │ ← Top nav
├────────┬─────────────────────────────────────────────┤
│        │                                             │
│  📊    │    Main Content Area                        │
│  🛡️    │                                             │
│  🔄    │    (changes based on selected module)       │
│  👻    │                                             │
│  🔍    │                                             │
│  ⚙️    │                                             │
│        │                                             │
│ Sidebar│                                             │
└────────┴─────────────────────────────────────────────┘
```

### Required Pages

1. **Dashboard Overview** - 4 stat cards (assets, vulns, incidents, honeypot hits) + activity timeline + threat map
2. **Surface** - Asset table with risk scores + vulnerability list + scan controls + trend charts
3. **Response** - Incident timeline + active responses + guardrail config + AI decision log
4. **Phantom** - Honeypot grid/map + interaction feed + attacker profiles + rotation status
5. **Threats** - IOC search + threat feed + shared intelligence
6. **Settings** - Client config + model routing + notification setup + API keys

## Ports (Local Dev)

- Backend API: 8000
- Frontend: 3000
- PostgreSQL: 5432 (or SQLite file)
- Redis: 6379 (or in-memory fallback)

## Environment Variables

```
# Core
AEGIS_ENV=development
AEGIS_SECRET_KEY=your-secret-key-here
AEGIS_API_PORT=8000

# OpenRouter
OPENROUTER_API_KEY=your-openrouter-key
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1

# Database (SQLite for local)
DATABASE_URL=sqlite+aiosqlite:///./aegis.db
# DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/aegis

# Redis (optional for local)
REDIS_URL=redis://localhost:6379
USE_MEMORY_BUS=true  # Use in-memory event bus if no Redis

# Scanning (tools on system)
NUCLEI_PATH=/usr/bin/nuclei
NMAP_PATH=/usr/bin/nmap
SUBFINDER_PATH=/usr/bin/subfinder
HTTPX_PATH=/usr/bin/httpx

# Notifications
WEBHOOK_URL=
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=

# Frontend
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws
```
