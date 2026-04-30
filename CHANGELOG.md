# Changelog

All notable changes to AEGIS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.5.0] - 2026-04-27

### Added

#### Phase B — AI-Offline Mode
- **`app/core/ai_mode.py`** — `AI_MODE` flag (`full` / `local` / `offline`). When `AEGIS_AI_MODE=offline`, all AI calls skip OpenRouter entirely and return deterministic rule-based results. Ten callsites in `ai_engine.py`, `scheduled_scanner.py`, and `correlation_engine.py` now check the flag and branch to local fallback logic before touching the network. Eliminates the hard dependency on a paid API key.
- **10 AI fallback paths**: triage, classify, risk-score, enrich, decide, verify, chain-evaluate, honeypot-generate, report-summarize, ask-ai. Each path uses a local heuristic (CVSS-based scoring, keyword classification, static MITRE lookup) that produces a valid structured response for downstream consumers.
- **Honeypot Jinja2 templates** (`app/templates/honeypot/`) — `ssh.j2`, `http.j2`, `smb.j2`, `sql.j2`, `api.j2`. Smart honeypots can now render realistic fake responses without an AI call when running offline. Templates use Jinja2 filters for realistic variation.
- **Report Jinja2 templates** (`app/templates/reports/`) — `daily.j2`, `executive.j2`, `incident.j2`, `scan.j2`. Report generator falls back to these when AI summarization is unavailable.
- **Static threat data** — `app/data/spamhaus_drop.txt` and `app/data/tor_exits.txt` bundled in-repo. Threat feed manager reads local copies first when the remote feed is unreachable, so the platform never starts with an empty blocklist.
- **MITRE mapping** — `app/data/mitre_mapping.json` with technique→tactic lookups; used by local AI fallback to produce ATT&CK annotations without a model call.
- **Counter-actions data** — `app/data/counter_actions.json` maps incident types to standard response playbook actions; used by the decision fallback path.

#### Phase C — YAML Rule Pack
- **122 Sigma-style rules** in `app/rules/sigma/` — covers MITRE tactics T1059 (command execution), T1110 (brute force), T1190 (exploit public-facing app), T1071 (C2 over HTTP/S), T1078 (valid accounts), T1486 (data encrypted for impact), and more. All rules are hot-reloadable; the correlation engine picks up file changes without a restart.
- **5 chain rules** in `app/rules/chains/` — multi-step attack sequence detection: `recon_to_exploit`, `brute_to_rce`, `exfil_chain`, `ransomware_chain`, `lateral_movement`. Each chain has a configurable time window (default 5 min) and minimum evidence threshold.
- **`app/services/rules_loader.py`** — validates, parses, and indexes the full rule pack at startup; exposes `reload()` for hot-reload and `get_rules_for_type()` for O(1) lookup by event type.
- **`app/services/correlation_engine.py`** — updated to use the new rule index. Rule evaluation is now O(rules_for_type) instead of O(all_rules); ~6× faster on the default rule set.
- **`app/schemas/rule.py`** — Pydantic v2 models for `SigmaRule`, `ChainRule`, `RuleMatch` with strict validation and human-readable error messages.

#### Phase D — Real Firewall Execution
- **`app/services/firewall_local.py`** — Local system firewall abstraction with three implementations:
  - `MacOSFirewall` — pfctl `aegis_block` persistent table with anchor file `/etc/pf.anchors/aegis`. Block/unblock via `pfctl -t aegis_block -T add/delete <ip>`.
  - `LinuxFirewall` — iptables `AEGIS_BLOCK` chain with idempotent setup (`-N` + `-C/-I` pattern). Block/unblock via `iptables -A/-D AEGIS_BLOCK -s <ip> -j DROP`.
  - `NoopFirewall` — in-memory `set[str]` used in sandboxed/CI environments and when `AEGIS_REAL_FW` is not set.
  - `get_firewall()` factory singleton via `functools.lru_cache`. Returns `MacOSFirewall` on darwin, `LinuxFirewall` on linux, `NoopFirewall` otherwise — all gated by `AEGIS_REAL_FW=1`.
  - All IPs validated through `ipaddress.ip_address()` before any subprocess call — injection-safe by construction. Subprocess calls use argv lists with `check=False, capture_output=True, timeout=5` — never `shell=True`.
  - `setup()` reloads all IPs from `BLOCKED_IPS_FILE` (default `~/.aegis/blocked_ips.txt` or `BLOCKED_IPS_FILE` env) so blocks survive reboots.
- **`responder._block_ip`** — now calls `get_firewall().block(target)` as a third blocking layer after the external firewall client and the `ip_blocker_service` middleware. System-level block failure is non-fatal and logged under `aegis.responder.fw`.
- **`responder._unblock_ip`** — rollback now calls `get_firewall().unblock(target)` to remove the system-level rule alongside the in-memory unblock.
- **`main.py` lifespan** — calls `firewall_local.get_firewall().setup()` on startup (wrapped in try/except; non-fatal if setup fails).
- **36 unit tests** in `backend/tests/unit/test_firewall_local.py` — full Noop coverage, persistence reload, MacOS/Linux exact argv verification, error handling (non-zero exit → False, no exception propagation), factory platform/env branching, singleton identity.

#### Phase E — Solution Packages
- **`solutions/`** — three starter packs (`web-app-defense`, `linux-server-hardening`, `homelab-baseline`), each bundling `rules/`, `playbooks/`, `parsers/`, `honeypots/`, `manifest.yaml`, and `README.md`. Manifest is Azure-Sentinel-inspired YAML with `id`, `name`, semver `version`, `description`, `author`, `includes` (lists of relative paths), and `depends_on`.
- **`app/services/solution_manager.py`** — `SolutionManifest` (Pydantic v2 with semver + kebab-case validators), `SolutionManager` with `discover()`, `install()`, `uninstall()`, `list_installed()`, `validate()`. Dependency resolution + circular-dep detection. Install state persists to `~/.aegis/installed_solutions.json`.
- **`app/cli/solutions.py`** — argparse CLI with `list | install <id> | uninstall <id> | update <id>` subcommands. Runnable via `python -m app.cli.solutions <subcmd>`.
- **20 unit tests** in `backend/tests/unit/test_solutions.py` — manifest validation, install/uninstall round-trip, missing-dep rejection, circular-dep rejection, state-file lifecycle.

#### Phase F — Detection Pipeline Speed Pass
- **`correlation_engine._rules_by_type`** — pre-built `dict[event_type, list[Rule]]` index covering YAML rule pack rules and runtime-added custom rules. `evaluate()` does an O(1) dispatch instead of iterating all 122 rules per event. `add_rule()` and `remove_rule()` keep the index in sync.
- **`RulePack.compile_pattern()`** — regex-cache helper backed by the existing `WeakValueDictionary regex_cache`. Per-pattern compile cost amortized; the rules loader no longer recompiles regexes on hot paths.
- **`backend/tests/perf/test_event_throughput.py`** — 5,000-event mixed-type benchmark (80% known event_types, 20% unknown). Measured throughput on test host: **10,000 evt/s** (target ≥1,000, hard floor 800). `test_indexed_dispatch_faster_than_full_scan` and `test_unknown_event_type_is_free` cover the index correctness invariants.

#### UI Redesign — Unified Token System
- **Rewrote `globals.css`** — single shadcn `.dark` variant with semantic status tokens (`success`, `warning`, `danger`, `info`) calibrated per mode. Elevation ladder: `background` → `surface` → `card` → `elevated` → `subtle`.
- **New CSS utilities** — `.aegis-card`, `.aegis-section-header`, `.pill` family, `.text-label`, `.text-display`, `.text-data`. Legacy `c6-*` aliases kept for backward compatibility.
- **17 dashboard pages** converted from hardcoded hex (`#22D3EE`, `bg-zinc-900`, etc.) to semantic tokens. Flagship pages (`dashboard`, `response`, `surface`) hand-polished for spacing and section headers.
- **shadcn/ui chart components** — `EventsPerSecChart`, Response `BarChart`, Surface `AreaChart`/`PieChart`/`LineChart` migrated to `ChartContainer` + `ChartTooltipContent`. Fixes black tooltip background in light mode; removes `isDark` MutationObserver hack.

#### Portable Log Watcher
- **`log_watcher` dual-mode** — auto-selects PM2 log tailing (macOS/Mac Pro) or `journalctl -f` (Linux/Pi) at runtime. AEGIS ships and runs on either host without config changes.
- **`AEGIS_MONITORED_APPS` env var** — comma-separated list of PM2 app names to tail. Prevents other services' crash logs from entering the detection pipeline.
- **`AEGIS_ATTACKER_IPS` env var** — comma-separated allowlist that bypasses the internal-IP filter. Used to enable Kali (Tailscale CGNAT) attacks to generate real incidents for testing while keeping the self-protection filter active.

#### Portable Firewall Agent
- **`firewall-agent/`** — standalone FastAPI service (port 8765) managing iptables on a Raspberry Pi or any Linux node. Includes systemd unit for one-shot install. Safe-network guards: Tailscale CGNAT, RFC1918, loopback, link-local.
- **`AEGIS_FIREWALL_URL` env var** — firewall client is now fully configurable. If unset, AEGIS manages iptables in-process (default in production). If set, it proxies block/unblock calls to the remote agent.

### Changed

- **Detection pipeline performance** — correlation engine rule evaluation is O(rules_for_type) via the new rule index; ~6× faster on the default 122-rule pack.
- **False-positive elimination** — 11 internal source markers in `log_watcher` prevent AEGIS's own log output (SQLAlchemy tracebacks, ExceptionGroup headers, PM2 dividers) from entering the pattern matcher. SQLi regex tightened from bare `--$` to require SQL keyword context.
- **`correlation_engine._on_log_line`** — drops events with no attributable `source_ip` (None bypass flipped from `if ip and internal` to `if not ip or internal`).
- **`ai_engine._create_incident`** — uses caller's title before AI triage fallback, fixing "MEDIUM: Alert received" ghost title overwrite on rate-limited responses.
- **CI pipeline** — actions bumped (checkout@v5, setup-python@v6, setup-node@v5). Lint step uses `--exit-zero` (findings log without blocking the run). Root `Makefile` mirrors all CI commands for local pre-push parity.
- **Version bumped to 1.5.0** in `backend/app/main.py`, `frontend/package.json`, `README.md`.

### Fixed

- **Kali probe silenced** — `AEGIS_ATTACKER_IPS=100.88.0.85` (Kali Tailscale IP) enables 342 previously-silenced sqlmap requests to generate real incidents. The internal-IP filter was correct for prod but blocked all red-team traffic.
- **self-referential SQL injection loop** — AEGIS no longer detects its own `SELECT` log lines as SQL injection attacks. Three-layer fix: monitored-app filter, source-marker filter, tightened regex.
- **MetricsSummaryBar crash** — runtime crash on `undefined` external metrics fixed with null guard.
- **`gen_diagram.py` hardcoded path** — output path now resolved relative to repo root.

### Security

- **No `shell=True`** anywhere in the new firewall execution path. All subprocess calls use argv lists.
- **IP injection prevention** — `ipaddress.ip_address()` validation is mandatory before any pfctl/iptables call.
- **`AEGIS_REAL_FW=1` opt-in** — system firewall modification is disabled by default. Operators explicitly enable it.
- **Secret scan before release** — no IPs, passwords, or credentials in the git tree.

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

[1.5.0]: https://github.com/alejandxr/AEGIS/releases/tag/v1.5.0
[1.4.0]: https://github.com/alejandxr/AEGIS/releases/tag/v1.4.0
[1.2.0]: https://github.com/alejandxr/AEGIS/releases/tag/v1.2.0
