# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is AEGIS (v1.6.3.2)

Autonomous cybersecurity defense platform with four modules: Surface (attack surface management), Response (autonomous incident response), Phantom (live honeypot operations), and Deception (Honey-AI campaign decoys, Enterprise tier). Deployed on Mac Pro (YOUR_SERVER_IP) as the **detection + decision brain**, protecting real services. Block enforcement is delegated to the Pi-side `aegis-firewall.service` via `firewall_client` (Rasputin-style remote executor).

v1.5 key additions: AI-offline mode (`AEGIS_AI_MODE=offline`), real firewall execution (`AEGIS_REAL_FW=1`), 122 Sigma rules + 5 chain rules hot-reload, unified design system.

v1.6.x adds: cloud-native CVE Sigma pack, supply-chain worm patterns, expanded FIM, Pi-side firewall executor restored (`AEGIS_FIREWALL_URL=http://100.93.30.20:8765`).

v1.6.3.2 adds: incident dedup hardening (10× table-growth reduction), startup safelist purge, APScheduler retention service (90d default), stuck-incident auto-closer, Tor-exit auto-block, /29 campaign correlation rule, dashboard ?window= parameter, full ISO-3166 country coverage in the threat map.

### Topology (v1.6.3.2+)
- **Raspberry Pi 5 + Hailo-10H** (`100.93.30.20`) = network gateway for Mac Pro AND **remote firewall executor**. Runs `aegis-firewall.service:8765` (FastAPI block agent) + `aegis-iptables-init.service` (oneshot, creates `AEGIS_BLOCK` iptables chain idempotently and links INPUT/FORWARD).
- **Mac Pro** = AEGIS brain (`cayde6-api`, `cayde6-frontend` via PM2). Owns detection, response decision, deception, threat intel. Delegates block enforcement to the Pi via `firewall_client` when `AEGIS_FIREWALL_URL` is set (which it is in prod since 2026-05-10).
- The `firewall-agent/` directory in this repo is the source of `aegis-firewall.service` deployed on the Pi.
- The local `firewall_local.py` (pfctl on Mac / iptables on Linux) remains as a defense-in-depth third blocking layer, gated by `AEGIS_REAL_FW=1`. With the Pi executor enabled it is redundant but harmless.

## Commands

### Local Development
```bash
cd backend && source venv/bin/activate && python -m uvicorn app.main:app --reload --port 8000  # Backend
cd frontend && npm run dev          # Frontend (localhost:3000)
cd frontend && npm run build        # Build check (zero TS errors required)
```

### Production (Mac Pro)
```bash
# SSH
ssh $AEGIS_SSH_USER@$AEGIS_HOST_IP

# PM2 management (actual prod process names -- NOT aegis-api/aegis-frontend)
pm2 restart cayde6-api              # Backend on port 8000, runs from ~/Cayde-6/backend
pm2 restart cayde6-frontend         # Frontend on port 3007 (uses npx next start), runs from ~/Cayde-6/frontend
pm2 logs cayde6-api --lines 30 --nostream

# Deploy frontend
cd frontend && npm run build
rsync -avz --delete --exclude='node_modules' --exclude='.git' --exclude='.env' frontend/ $AEGIS_SSH_USER@$AEGIS_HOST_IP:~/Cayde-6/frontend/
# Then: pm2 restart cayde6-frontend

# Deploy backend
rsync -avz --exclude='__pycache__' --exclude='venv' --exclude='*.db' --exclude='.env' backend/ $AEGIS_SSH_USER@$AEGIS_HOST_IP:~/Cayde-6/backend/
# Then: pm2 restart cayde6-api

# Trigger scan
curl -X POST -H "X-API-Key: YOUR_API_KEY" http://YOUR_SERVER_IP:8000/api/v1/surface/scan/now
```

### Operational notes
```bash
# v1.6.3.2+: AEGIS_FIREWALL_URL=http://100.93.30.20:8765 is ACTIVE in prod.
# AEGIS pushes every block to the Pi firewall executor (aegis-firewall.service:8765);
# firewall_sync runs every 5 min reconciling Mac Pro ↔ Pi blocklists.
# The local pfctl/iptables in firewall_local.py acts as a third defense-in-depth layer.
# (Historical: `rasputin.service` codebase is retired — its role is filled by aegis-firewall.service.)

# NEVER use lsof on Mac Pro — it hangs and creates zombie processes. Use netstat or ps aux instead.
```

## Architecture

### Backend (FastAPI + SQLAlchemy async + PostgreSQL)
- `app/main.py` — FastAPI app with lifespan (starts scanner, honeypots, log watcher, firewall setup, firewall sync)
- `app/core/openrouter.py` — Multi-model routing via OpenRouter (hunter-alpha main, 5+ free models)
- `app/core/ai_mode.py` — `AI_MODE` flag (`full`/`local`/`offline`). Set `AEGIS_AI_MODE=offline` to run without any AI API key.
- `app/core/auth.py` — API key auth middleware, demo client auto-seed
- `app/core/events.py` — In-memory async event bus (pub/sub)
- `app/core/guardrails.py` — Action approval system (auto_approve / require_approval / never_auto)
- `app/core/firewall_client.py` — Optional external firewall client (only used if `AEGIS_FIREWALL_URL` is set; currently unset in prod)
- `app/services/ai_engine.py` — Agentic AI: triage → classify → decide → execute → verify → audit. Falls back to local heuristics when `AI_MODE=offline`.
- `app/services/firewall_local.py` — Local system firewall: `MacOSFirewall` (pfctl), `LinuxFirewall` (iptables), `NoopFirewall` (default). Gated by `AEGIS_REAL_FW=1`. IP injection-safe via `ipaddress` validation.
- `app/services/rules_loader.py` — Loads and indexes 122 Sigma rules + 5 chain rules from `app/rules/`. Hot-reload via `reload()`. O(1) lookup by event type.
- `app/services/correlation_engine.py` — Evaluates rules using the type index. ~6× faster than linear scan on the default rule set.
- `app/services/scheduled_scanner.py` — APScheduler: full scan 2h, quick scan 30min, discovery 1h, adaptive alert mode
- `app/services/log_watcher.py` — Tails PM2 logs (macOS) or journalctl (Linux). Controlled by `AEGIS_MONITORED_APPS`. 11 internal source markers prevent self-detection.
- `app/services/firewall_sync.py` — Optional sync with external firewall agent every 5 min (conditional on `AEGIS_FIREWALL_URL`; **disabled in prod** since AEGIS handles iptables locally)
- `app/modules/surface/` — nmap/nuclei subprocess wrappers, AI risk scoring, hardening checks
- `app/modules/response/` — Alert ingestion, AI analysis, active response (pfctl/iptables + 403 middleware + external firewall)
- `app/modules/phantom/` — SSH honeypot (paramiko, port 2222), HTTP decoy (aiohttp, port 8888), rotation engine. Jinja2 templates in `app/templates/honeypot/` for offline mode.

### Frontend (Next.js 14 + Tailwind + TypeScript)
- Design system: "Refined Dark Command" — Outfit font, Azeret Mono for data, zinc palette, #22D3EE cyan + #F97316 orange accents
- Card pattern: `bg-[#18181B] border border-white/[0.06] rounded-2xl`
- Icons: hugeicons-react primary, lucide-react fallback
- Charts: recharts + react-simple-maps (GlobalThreatMap)
- `src/components/shared/AskAI.tsx` — Floating AI chat panel (POST /api/v1/ask)
- `src/lib/api.ts` — Fetch wrapper reading API key from localStorage
- Light/dark mode via `data-theme` attribute on `<html>`

### Data Flow
```
PM2 Logs   → log_watcher → AI Engine → Actions (local iptables + 403 middleware) → Audit Log
nmap/nuclei → scheduled_scanner → Assets/Vulns DB → AI Risk Score
Honeypots  → Interactions → Attacker Profiler → Threat Intel → local iptables
```

### External Integrations
- **OpenRouter** (AI): Base URL `https://openrouter.ai/api/v1`, key in .env.
- **External firewall agent**: optional, gated by `AEGIS_FIREWALL_URL`. Currently unset — AEGIS manages iptables in-process on Mac Pro.

## Key Patterns

- PostgreSQL only (SQLite removed). Connection pool: pool_size=20, max_overflow=10.
- All scan operations run in background threads via asyncio — never block the API event loop.
- The log_watcher skips internal IPs (YOUR_SERVER_IP, 127.0.0.1) and AEGIS's own scanner output to prevent false positives. 11 internal source markers filter SQLAlchemy tracebacks, PM2 dividers, ExceptionGroup headers.
- IP blocking is three-layer: (1) external firewall agent via `firewall_client` if `AEGIS_FIREWALL_URL` is set; (2) `blocked_ips.txt` + FastAPI middleware returns 403; (3) `firewall_local.get_firewall().block()` for system-level pfctl/iptables when `AEGIS_REAL_FW=1`.
- Firewall execution is injection-safe: all IPs pass through `ipaddress.ip_address()` before any subprocess call. Subprocess always uses argv list, never `shell=True`.
- `AEGIS_AI_MODE=offline` disables all AI API calls. Ten local fallback paths return deterministic rule-based results for every AI operation.
- Frontend uses demo/fallback data patterns: if API fails, show empty state — NEVER hardcoded fake data.
- Mac Pro frontend deployment: `next.config.mjs` must NOT have `output: 'standalone'` — use `npx next start` via PM2.

## Environment Variables (v1.5)

| Variable | Default | Purpose |
|----------|---------|---------|
| `AEGIS_REAL_FW` | unset | Set to `1` to enable pfctl/iptables system firewall |
| `AEGIS_AI_MODE` | `full` | `full` / `local` / `offline` — AI call gating |
| `AEGIS_FIREWALL_URL` | unset | Remote firewall agent URL (e.g. `http://pi:8765`) |
| `AEGIS_MONITORED_APPS` | all PM2 apps | Comma-separated PM2 app names to tail |
| `AEGIS_ATTACKER_IPS` | unset | Comma-separated IPs that bypass internal-IP filter (pentest lab machines that must still generate real incidents despite living in Tailscale CGNAT) |
| `AEGIS_SAFE_IPS` | `127.0.0.1,::1,localhost` | Comma-separated IPs and/or CIDR ranges (e.g. `66.249.0.0/16`) that are never blocked and never turned into an incident, on **every** detection path (log_watcher, ai_engine fast_triage + process_alert, correlation_engine, attack_chain_detector, dos_shield, guardrails, phantom honeypots). Parsed by `app/core/attack_detector.py::_is_safe_ip` — the single shared gate all of the above import. Also folds in RFC1918/CGNAT/Tailscale ranges and published crawler/CDN CIDRs (Googlebot, Bingbot, etc.) unconditionally. |
| `AEGIS_INTERNAL_IPS` | unset | Comma-separated IPs and/or CIDR ranges an operator wants treated as "one of mine" — e.g. a home/office IP that must never spawn an incident even though it isn't a private range. Merged into the exact same gate as `AEGIS_SAFE_IPS` (both are additive, use either name). Example for a residential IP: `AEGIS_INTERNAL_IPS=179.52.12.148` (or widen to a `/24` if the ISP rotates the address within a known block). |
| `BLOCKED_IPS_FILE` | `~/.aegis/blocked_ips.txt` | Path to blocked IPs persistence file |
| `GEMINI_API_KEY` | unset | Google Gemini API key (provider name `gemini`, default model `gemini-flash-lite-latest`) |
| `GEMINI_BASE_URL` | `https://generativelanguage.googleapis.com/v1beta` | Gemini base URL override |

## Ports

| Port | Service |
|------|---------|
| 3007 | AEGIS frontend |
| 5432 | PostgreSQL |
| 8000 | AEGIS API |
| 8888 | AEGIS HTTP honeypot |
| 2222 | AEGIS SSH honeypot |
