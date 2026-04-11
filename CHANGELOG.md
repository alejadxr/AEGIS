# Changelog

All notable changes to AEGIS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.4.0] - 2026-04-11

### Added

#### Threat Sharing Mesh
- **Public hub** at `api-aegis.somoswilab.com` — hub-and-spoke threat intelligence sharing network for all AEGIS nodes.
- **`backend/app/services/hub_sync_client.py`** — Background service that connects a local AEGIS node to the hub. Registers on startup, pulls new IOCs every 60 seconds via `GET /threats/feed?since=`, auto-blocks high-confidence IPs (≥0.8) via `ip_blocker_service`, and exposes `push_ioc()` for local detections. Tracks stats: `iocs_pulled`, `iocs_pushed`, `auto_blocks`, `errors`, `connected`, `last_sync`.
- **`backend/app/services/auto_sharer.py`** — Subscribes to `alert_processed`, `honeypot_interaction`, and `correlation_triggered` events. Validates IOCs via `ioc_validator`, pushes them to the hub through `hub_sync_client.push_ioc()`. 5-minute deduplication per IOC. Severity-to-confidence mapping (`critical=0.95`, `high=0.85`, `medium=0.6`, `low=0.3`).
- **`backend/app/services/ioc_validator.py`** — Central validation layer that prevents poisoning of the sharing network:
  - Rejects private IPs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback, link-local, multicast, reserved.
  - Rejects Tailscale CGNAT range (`100.64.0.0/10`).
  - Rejects safe-listed DNS providers (`8.8.8.8`, `8.8.4.4`, `1.1.1.1`, `1.0.0.1`, `9.9.9.9`, `208.67.222.222`, `208.67.220.220`).
  - Rejects safe-listed domains (`google.com`, `cloudflare.com`, `github.com`, `microsoft.com`, `apple.com`, `amazon.com`, `localhost`).
  - Validates hash lengths (MD5=32, SHA1=40, SHA256=64) and hex content.
  - Normalizes and sanitizes URLs and emails.
- **6 public endpoints** in `backend/app/api/threats.py`:
  - `POST /threats/intel/share` — submit IOC from a remote node (validated before accepting).
  - `GET /threats/feed` — pull shared IOCs, supports `?since=` for incremental sync.
  - `GET /threats/intel/search?q=` — public search.
  - `POST /threats/nodes/register` — node registration (in-memory registry, 15-min TTL).
  - `GET /threats/nodes` — list registered sharing nodes.
  - `GET /threats/hub/info` — hub capability advertisement for auto-discovery.
- **`GET /threats/sharing/stats`** — hub_sync_client stats + auto_sharer stats + registered node list.
- **WebSocket topics** for real-time IOC push: `threats.new`, `threats.ioc`, `threats.blocked_ip`, `threats.pattern_update`.

#### Opt-in UI
- **Threat Sharing section** in `frontend/src/app/dashboard/settings/page.tsx` (top of the sharing tab):
  - One-click toggle (green when active, grey when off).
  - 3 stat tiles: IOCs Shared, IOCs Received, Auto-Blocked.
  - Explanation text about validation and auto-blocking (confidence ≥ 0.8).
- **`api.settings.updateIntelSharing({ enabled })`** — PUT `/settings/intel-sharing`.
- **`api.threats.sharingStats()`** — GET `/threats/sharing/stats`.

#### Infrastructure
- **Cloudflare tunnel route** `api-aegis.somoswilab.com` → `localhost:8000` added via Cloudflare API (remote config).
- **Cloudflared binary** updated from 2025.11.1 → 2026.3.0 on Mac Pro.
- **CHANGELOG.md** — this file.

### Changed

- **Correlation engine** (`backend/app/services/correlation_engine.py`):
  - Now subscribes to `log_line`, `edr.event`, `edr.process_start`, and `honeypot_interaction` events (previously only typed security events nobody published).
  - New `_on_log_line()` translator maps raw PM2 log patterns to typed events (`sql_injection`, `xss`, `auth_failure`, `http_request`, `web_request`, `priv_escalation`) that Sigma rules can evaluate.
  - New `_on_edr_event()` and `_on_honeypot_event()` translators for EDR and honeypot events.
  - New `_is_internal_ip()` helper filters private, loopback, link-local, multicast, and Tailscale (100.64.0.0/10) IPs before running log lines through Sigma rules. This fixes false positives from dashboard WebSocket auth failures being detected as brute-force.
  - `_collect_subscribed_types()` now also reads event types from chain rules.
- **AI routing** (`backend/app/core/openrouter.py`):
  - When internal callers (ai_engine `_triage`, `_classify`, scheduled_scanner `_score_risk_with_ai`) pass no `client_settings`, the router falls back to `ai_manager.active_provider` instead of hitting OpenRouter directly. With `ai_provider=inception` this means all AI calls route through Mercury-2. Fixes 90,000+ OpenRouter 429 errors in the logs.
- **AI engine** (`backend/app/services/ai_engine.py`):
  - `fast_triage()` now always creates an incident in the DB when sigma matches are found (previously only when `actions_taken` was non-empty).
  - `fast_triage()` adds `incident_title`, `incident_severity`, and `source_ip` to the WS payload so the AttackFeed shows real titles instead of "Incident detected".
  - `process_alert()` gracefully handles AI failures — if triage or classification throws, it falls back to sensible defaults and still creates an incident. Before, a single AI 429 would crash the entire alert pipeline.
- **Correlation engine incident creator** (`_create_incident`): wraps `ai_engine.process_alert()` in try/except. If the AI fails, creates the incident directly in the DB with the sigma rule metadata. Before, AI failures meant no incident was ever persisted.
- **IP blocker** (`backend/app/core/ip_blocker.py`):
  - Added `None`/non-string guard at the top of `block_ip()`. Returns `{"success": False, "error": "Invalid IP"}` instead of crashing.
- **Attack detector** (`backend/app/core/attack_detector.py`):
  - Imports `BLOCKED_IPS_FILE` from `ip_blocker.py` instead of defining its own path. Unifies the source of truth. Before, the admin stats API read from `~/Cayde-6/backend/blocked_ips.txt` (empty) while the middleware read from `~/AEGIS/blocked_ips.txt` (actual list).
  - `_block_ip()` has a None guard.
- **Responder** (`backend/app/modules/response/responder.py`):
  - `_block_ip()` validates target is not `None`/empty before calling `ip_blocker_service.block_ip()`.
- **Scheduled scanner** (`backend/app/services/scheduled_scanner.py`):
  - Uptime check publishes `node_status` events instead of `alert_processed`. Service down events now show in Node Heartbeats widget instead of cluttering the Attack Feed.
- **Settings API** (`backend/app/api/settings.py`):
  - `PUT /intel-sharing` now actually starts/stops the `hub_sync_client` when toggled, based on the `AEGIS_HUB_URL` env var.
- **Dashboard live widgets** — all 7 components use semantic shadcn tokens (`bg-card`, `border-border`, `text-foreground`, `text-muted-foreground`, `bg-muted`) instead of hardcoded dark colors. Works correctly in light and dark mode.
  - `AttackFeed.tsx` — also loads recent incidents from `/response/incidents` on mount, makes each feed item clickable to `/dashboard/response?incident=<id>`, and extracts `incident_title`, `incident_severity`, `source_ip`, `mitre_technique`, `status` from WS events.
  - `EventsPerSecChart.tsx` — theme-aware tooltip and grid colors.
  - `Top10Table.tsx`, `RawLogStream.tsx`, `NodeHeartbeatGrid.tsx`, `MetricsSummaryBar.tsx`, `GlobalThreatMap.tsx` — same token migration.
- **`formatRelativeTime()`** (`frontend/src/lib/utils.ts`) — appends `Z` suffix to backend datetimes without timezone before parsing, fixing the "just now" bug where all incidents appeared to be seconds old.
- **Version bumped to 1.4.0** in:
  - `backend/app/main.py` (3 locations — FastAPI app, `/health`, `/api/v1/health`).
  - `frontend/package.json`.
  - `frontend/src/app/page.tsx` login footer.
  - `frontend/src/app/setup/page.tsx` setup wizard footer.
  - `frontend/src/components/shared/Sidebar.tsx` sidebar bottom label.
  - `backend/app/services/auto_updater.py` `CURRENT_VERSION`.
  - `backend/app/services/hub_sync_client.py` node registration payload.

### Fixed

- **Self-blocking loop** — Mac Pro and Windows dev machine IPs were being added to `blocked_ips.txt` repeatedly because:
  1. The dashboard opened WebSocket connections from Tailscale peers.
  2. Failed auth requests generated `auth_failure` log lines.
  3. The correlation engine translated these into `auth_failure` events without filtering internal IPs.
  4. The `brute_force_ssh` sigma rule fired and auto-approved a block.
  5. The admin was locked out of their own server.
  
  Fixed at the root: correlation engine now skips internal/Tailscale IPs in `_on_log_line()`.
- **Dashboard 403 errors** — cleared `blocked_ips.txt` and fixed the feedback loop above.
- **Incident DB empty despite live events** — incidents now persist when AI is rate-limited (AI failure is handled gracefully).
- **AttackFeed showing "Incident detected" everywhere** — fixed by adding `incident_title` to WS payloads and making the feed load from API on mount.
- **Settings silently failing** — save handlers now surface errors via `flashSaveError()` toast instead of swallowing them with `catch {}`.
- **GitHub auto-updater 404** — typo `alejadxr/AEGIS` → `alejandxr/AEGIS` in `auto_updater.py`.

### Security

- **IOC validation is mandatory** on all inbound IOCs to the sharing hub. No poisoning vector via the public `/threats/intel/share` endpoint.
- **Secret scan before every release** — no API keys, passwords, IPs, or credentials in the git tree. `.env` files stay local, `CLAUDE.md` is gitignored.
- **Rasputin firewall optional** — AEGIS defends independently via `ip_blocker_service` + FastAPI middleware. `AEGIS_FIREWALL_URL` can be unset without breaking the defense pipeline.

---

## [1.2.0]

### Added

- **Live Dashboard** — CrowdStrike Falcon-style SOC view with 10 WebSocket-powered widgets.
- **Ransomware Protection** — Canary files + entropy detection + auto-rollback (VSS/Btrfs/LVM) in <500ms.
- **EDR/XDR Core** — ETW (Windows) + eBPF (Linux) telemetry, process tree reconstruction, 6 MITRE attack chain rules.
- **Antivirus Engine** — YARA + ClamAV + hash reputation cache, on-access + scheduled scans, encrypted quarantine.
- **Configurable Firewall** — YAML rule engine with UI editor, rate limiting, 6 default templates, hot reload.
- **Honey-AI Deception** — Auto-generate 50+ fake services with AI-generated content. 4 industry themes. Breadcrumb UUID tracking.

---

[1.4.0]: https://github.com/alejandxr/AEGIS/releases/tag/v1.4.0
[1.2.0]: https://github.com/alejandxr/AEGIS/releases/tag/v1.2.0
