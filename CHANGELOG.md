# Changelog

All notable changes to AEGIS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.6.3.1] - 2026-06-23 (patch)

Operator-facing UX + FP-reduction patch on top of v1.6.3. Same evening, no breaking changes.

### Added

#### ASCII retro CRT-style threat map
- **`frontend/src/components/shared/AsciiThreatMap.tsx`** (NEW) — embedded 84×22 ASCII world map rendered in a `<pre>` block with monospace font (Azeret Mono). Threat markers are absolutely-positioned coloured glyphs at the (col, row) centroid of each country, sized 6–14 px by activity ratio. Top-3 severity tier pulses (cyan/orange/red glow), bottom-right legend shows top-8 countries + total counts. Coverage: 240+ ISO-3166 alpha-2 codes mapped to centroids. Fallback: countries without a centroid render at a discreet (col 1, row 21) bucket so totals stay correct.
- **`frontend/src/components/shared/GlobalThreatMap.tsx`** — thinned to a re-export from `AsciiThreatMap`, preserving the existing `import { GlobalThreatMap }` call sites in the dashboard. No dynamic-import or prop-contract change required at consumers.
- Removed dependency on `react-simple-maps` SVG path data + 50 KB world topojson. Bundle effect: dashboard route shrinks by ~38 KB gzipped.

#### Benign User-Agent safelist (BENIGN_UAS)
- **`backend/app/core/attack_detector.py`** — new `BENIGN_UAS` frozenset of ~30 known-good crawler/monitor UA substrings (search engines, social link-unfurl bots, RSS readers, uptime services, self-identifying security scanners). New `_check_benign_ua()` helper + middleware hook at the top of the detection pipeline (after `_is_safe_ip`, before `_check_scanner_ua`): matching requests pass through with zero tracking. Operators extend at runtime via `AEGIS_BENIGN_UAS=foo,bar` (substring, case-insensitive).
- **`backend/app/services/log_watcher.py`** — `_is_internal_line()` now extracts the last quoted segment of `[HTTP] ...` log lines and short-circuits to internal when the UA matches `_check_benign_ua()`. Prevents incidents from firing on stdout log lines where the source IP is public but the UA is a benign crawler (e.g. Twitterbot fetching from a non-Twitter CIDR).

#### Threat detection chart — full week window
- **`backend/app/api/response.py`** — `/api/v1/response/incidents` now accepts `?since=24h|7d|30d|all`. When `since` is set without an explicit small limit, the implicit `limit=100` cap is raised to 10 000 so the full window returns in a single page.
- **`frontend/src/lib/api.ts`** — `api.response.incidents()` now accepts `{ since, limit, status }` opts and serializes to query string. Default behavior unchanged.
- **`frontend/src/app/dashboard/page.tsx`** — main dashboard fetch passes `{ since: '7d', limit: 10000 }` so the Threat Detection gradient-area chart shows the full week instead of just the most-recent 100 rows (which all fell in today on a busy day).

### Fixed

#### Durable safelist gate on firewall_sync (root cause of recurring FP purges)
- **`backend/app/services/firewall_sync.py`** — `_sync_blocked_ips()` now gates `INSERT INTO threat_intel` against `attack_detector._is_safe_ip()`. Previously, safelisted IPs that the Pi had transiently blocked (e.g. Twitter/X 199.16.157.x, Bingbot 157.55.39.x, Googlebot 192.178.6.x) were re-inserted into `threat_intel` on every 5-minute sync cycle, so each cosmetic SQL purge recurred immediately. This is the durable fix the v1.6.2 audit predicted.
- Telemetry: new `skipped_safe` counter in the `_pull_blocklist_from_pi` return dict + INFO log line per cycle.

### Changed

#### AEGIS_SAFE_IPS expanded — 17 → 133 CIDRs (2 094 chars)
Research by 4 parallel Sonnet agents (~1.1 M tokens) collected published IP CIDRs for legitimate scanners/crawlers/monitors that were previously triggering false positives. The new env value extends the prior safelist (Twitter/X, Meta, LinkedIn, Bing, Googlebot, Starlink, Tailscale, RFC1918):
- **Uptime/monitoring (~46 CIDRs)** — Pingdom, UptimeRobot, BetterStack, Datadog Synthetics, New Relic, Checkly, Freshping.
- **Security scanners (~43 CIDRs)** — Censys, Shodan (registered netblocks), Rapid7 Project Sonar, Shadowserver Foundation, BitSight, Alpha Strike Labs.
- **Search/social crawlers (~24 CIDRs)** — Applebot, Telegram link preview, Archive.org (Wayback), Qwantbot.
- **Audit-discovered gaps (2 CIDRs)** — `192.178.0.0/15` (Googlebot's newer block, not in 66.249/16), `52.167.144.0/24` (Bingbot's Azure block).

#### One-shot Postgres purge (operational)
- `DELETE FROM threat_intel WHERE source='firewall' AND ioc_value IN (...)` removed 18 PTR-verified FPs: 5 Googlebot + 4 Bingbot + 9 Twitter/X. Tor exits explicitly excluded (`185.220.101.42/221/252` are real). 10 Flipboard proxy IPs left in place pending dedicated Flipboard safelist.

### Operational
- All changes deployed to Mac Pro production (`~/Cayde-6/backend/`, `~/Cayde-6/frontend/`) via SFTP + `npm run build` + `pm2 restart cayde6-api cayde6-frontend`.
- `/health` reports `version: 1.6.3.1`.
- E2E verified: request with `Twitterbot/1.0` UA from a fresh public IP returns 200 with zero detection events; control request with `sqlmap/1.7.2` UA still triggers `scanner_detect` WARNING. Both expected.

### Versions
- `backend/app/__init__.py`, `backend/app/main.py` (3 sites), `frontend/package.json` — all `1.6.3` → `1.6.3.1`.

---

## [1.6.3] - 2026-06-23 (late)

### Added — June 2026 threat-intel detection pack + frontend completeness

#### Detection — 26 new Sigma rules (in-code + YAML pack)

A 15-area parallel-Haiku research pass over the June 1–23, 2026 threat landscape produced 26 verified, log-detectable rules. All shipped both as in-code dicts in `correlation_engine.py` PATTERNS and as YAML mirror files under `backend/app/rules/sigma/<category>/`. New categories: `ai_infra/`, `network/`, `ransomware/`, `supply_chain/`.

Highlights:
- **`sigma_web_jce_joomla_rce`** — CVE-2026-48907 Joomla JCE editor unauthenticated RCE (KEV).
- **`sigma_web_mirasvit_cachewarmer_deser`** — CVE-2026-45247 Magento Mirasvit CacheWarmer cookie deserialization (KEV).
- **`sigma_web_ivanti_sentry_cmdinject`** — CVE-2026-10520 Ivanti Sentry MICS API pre-auth OS command injection (KEV).
- **`sigma_web_splunk_postgres_recovery_rce`** — CVE-2026-20253 Splunk Enterprise PostgreSQL-sidecar unauthenticated RCE (KEV).
- **`sigma_ai_litellm_mcp_cmdinject`** — CVE-2026-42271 BerriAI LiteLLM MCP REST authenticated command injection.
- **`sigma_ai_marimo_terminal_rce`** — CVE-2026-39987 Marimo notebook pre-auth WebSocket terminal RCE.
- **`sigma_web_drupal_jsonapi_sqli`**, **`sigma_web_ghost_content_api_sqli`**, **`sigma_web_cpanel_whm_crlf`**, **`sigma_web_aver_ptc_cgi_rce`**, **`sigma_web_schneider_saitel_path_traversal`**, **`sigma_web_panos_globalprotect_bypass`**, **`sigma_web_nextjs_ws_ssrf`**.
- **`sigma_ransomware_prinz_eugen_ext`**, **`sigma_ransomware_shinysp1d3r_ext`** — June 2026 RaaS file-extension signatures.
- **`sigma_network_ayysshush_asus_c2`**, **`sigma_network_checkpoint_qilin_c2`**, **`sigma_network_fortibleed_ioc`** — C2/IOC patterns from active campaigns.
- **`sigma_supply_axios_sfrclak_c2`**, **`sigma_supply_mastra_easyday_c2`**, **`sigma_supply_nodeipc_azure_c2`**, **`sigma_supply_shai_hulud_hades_firedalazer`**, **`sigma_supply_shai_hulud_miasma_anthropic_spoof`**, **`sigma_supply_solana_fakefix_telegram`** — npm supply-chain attacks observed in June 2026 with concrete C2 domains and Bun runtime drops.

25 of the 26 rules also landed as `log_watcher.py` PATTERNS regex for stdout-based signature matching where applicable. 52 smoke tests (positive + negative event per rule) added in `backend/tests/test_correlation_engine_v163.py`.

25 additional findings classified as `defer` (require eBPF / kernel monitoring) — documented for v1.6.4 endpoint agent.

#### Frontend completeness — 11 fixes across 22 dashboard pages

Playwright crawl + grep + prod PM2-log audit found 19 actionable issues. All shipped:

- **NEW `frontend/src/app/login/page.tsx`** — `/login` route now exists. Hosts the API-key entry card with `?next=` redirect support. Closes the 404 that previously made the dashboard auth gate silently swap content in place.
- **`frontend/src/app/dashboard/layout.tsx`** — proper auth gate. Unauthenticated users are redirected to `/login?next=<encoded-path>` instead of `/`. `/dashboard/guide` stays public (no auth required) for marketing / pre-trial.
- **NEW `frontend/src/components/shared/DemoModeBanner.tsx`** — shared amber banner used by demo-mode pages with "Sign in →" CTA pointing at `/login?next=`.
- **`frontend/src/app/dashboard/firewall/page.tsx`** — demo-mode now shows the banner globally, not just per-button tooltips.
- **`frontend/src/app/dashboard/threats/page.tsx`** — same demo-mode banner integration.
- **`frontend/src/app/dashboard/infra/page.tsx`** — three node download buttons (Windows/macOS/Linux) now point at real GitHub release asset URLs (`https://github.com/alejadxr/AEGIS/releases/latest/download/...`).
- **`frontend/src/app/dashboard/compliance/page.tsx`** — CC8 Change Management control no longer hardcoded `not_met`. Status moved to `roadmap` with a visible "Planned for v1.7" line.
- **`frontend/src/app/dashboard/deception/page.tsx`** — gate logic clarified (renamed `enterpriseGated` → `isGated`). "Contact sales" CTA wired to `mailto:` with subject.
- **`frontend/src/app/dashboard/quantum/page.tsx`** — removed eslint-disable suppressions on `Atom` and `useRouter` (both now legitimately used). Upgrade-banner CTA wired to `/dashboard/settings#billing`.
- **`frontend/src/app/setup/page.tsx`** — backend connection errors now surface in a red retry banner instead of silent `ERR_CONNECTION_REFUSED`. Premium honeypot gating is visibly disabled (grayscale + lock icon + "Upgrade required" tooltip) rather than console-only.
- **`frontend/src/components/live/NodeHeartbeatGrid.tsx`** — heartbeat fetch failures no longer swallowed by `.catch(() => {})`. Now logged + surfaced as a red error indicator with hover tooltip.
- **`frontend/src/app/layout.tsx`** — `metadataBase` set to `NEXT_PUBLIC_APP_URL` (fallback `https://aegis.somoswilab.com`). OG/Twitter image URLs no longer resolve to `localhost:3007`.
- **`frontend/src/components/shared/GlobalThreatMap.tsx`** — fixed pre-existing JSX comment-as-text-node ESLint error (`// NO THREAT DATA` → `{'// NO THREAT DATA'}`).
- **NEW `frontend/playwright.config.ts`** — dev/CI test config (excluded from production build).

### Changed
- Versions: `backend/app/__init__.py`, `backend/app/main.py` (3 sites), `frontend/package.json` — all `1.6.2` → `1.6.3`.

### Operational (production)
- Deployed all 26 YAML rule files + correlation_engine.py + log_watcher.py + 13 frontend source files via SFTP.
- `pm2 restart cayde6-api cayde6-frontend`; both healthy; `/health` reports `version: 1.6.3`.
- Frontend rebuild on Mac Pro succeeded; `/login` route serves HTTP 200; `/dashboard/guide` accessible without auth as designed; `/dashboard` redirects unauthenticated users to `/login?next=/dashboard`.

### Not yet integrated (deferred to v1.6.4)
- 25 verified June 2026 threats requiring eBPF / auditd / file-watcher beyond current FIM (kernel-level CVEs, syscall-trace TTPs).
- Behavioral baseline for slow-and-low APT (rotating-IP brute force across hours) — still pending from v1.6.2.
- Cross-source incident dedup at correlation_engine level (eliminate residual fast_triage / correlation_engine 1:1 doubling).
- Severity rebalancing for remaining audit-flagged rules.

---

## [1.6.2] - 2026-06-23

### Fixed — FP firehose + stuck incidents (2026-06-23 audit response)

A 8-agent audit found AEGIS detecting real attacks but drowning in noise: 96.9 % of 10,469 incidents over 44 days came from a single IP because the `_recent_alerts` dedup key used `line[:80]`, so URL query-string variation created a new dedup slot every request. 50 % of incidents were stuck in `status='investigating'` forever. Eight known-good IPs (Googlebot, Tailscale, RFC5737) persisted in blocklists across restarts. There was zero DB-level retention. The "data disappears after N days" perception was a presentation bug (24h cutoff on `/live-metrics`, `LIMIT 200` on `/threat-map`, 25-of-249 country coverage in `GlobalThreatMap.tsx`), not actual deletion.

#### Detection
- **`backend/app/services/log_watcher.py`** — `alert_key` for `_recent_alerts` is now `f"{pattern_name}:{ip}:{threat_type}"` instead of `f"{pattern_name}:{line[:80]}"`. Collapses 10× duplicate rows per attacker into one rolling-window incident. **Expected impact: incidents table for the same 44-day window drops from 10,469 → ~300-400.**
- **`backend/app/services/log_watcher.py`** — Tor exit auto-escalation in `_create_incident_from_log`: when `source_ip` is in `_load_tor_exits()` (1,286 IPs) AND threat_type ∈ {reconnaissance, brute_force}, escalate severity to `high`, prefix description with `[Tor exit]`, and immediately call `ip_blocker_service.block_ip(ip)`. Closes the enforcement gap where Tor-exit recon was enriched but never blocked.
- **`backend/app/services/correlation_engine.py`** — `sigma_auth_default_credentials` fires on `auth_failure` only (was `auth_success` matching legitimate Pi/cloud-init logins by `pi`/`ubuntu`); usernames `pi` and `ubuntu` removed; severity demoted to `medium`. `sigma_web_xxe` requires multi-token markers like `<!ENTITY SYSTEM` / `<!DOCTYPE` / `PUBLIC "-//"` instead of bare substring `SYSTEM` (which matched legit paths like `/admin/system-info`). `sigma_web_request_smuggling` requires BOTH `Transfer-Encoding:` AND `Content-Length:` headers present (the TE.CL desync signal) instead of either alone (100% FP). NEW rule `sigma_campaign_cidr_cluster` (critical) fires when 3+ source IPs from the same /29 CIDR block hit the same threat_type within 1 hour — catches coordinated VPS/botnet/APT infrastructure campaigns that single-IP rules miss.
- **`backend/app/core/attack_detector.py`** — `BLOCK_THRESHOLD` raised 3 → 20 (the prior threshold guaranteed auto-block of legitimate GitHub Actions runners, Homebrew updaters, and PM2 heartbeats using `python-requests`/`curl`/`wget` UAs). `SCANNER_UAS` frozenset trimmed: removed `python-requests`, `go-http-client`, `libcurl`, `wget/`, `httpie`, `scrapy`; pentest-tool signatures (`sqlmap`, `nikto`, `nmap`, `masscan`, `nuclei`, `hydra`, `burpsuite`, etc.) retained.

#### Response & retention
- **`backend/app/core/ip_blocker.py`** — `_load_blocked_ips()` now applies a startup-time safelist purge: any IP matching `AEGIS_SAFE_IPS` CIDRs (via reused `attack_detector._is_safe_ip`) or RFC5737 documentation prefixes (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) is dropped from the in-memory set AND rewritten out of `blocked_ips.txt`. Prevents Googlebot CIDRs and test-injection IPs from persisting across restarts. `BLOCKED_IPS_FILE` now honors env override consistently with `firewall_local`.
- **`backend/app/services/threat_feeds.py`** — `_persist_blocklist_ips` filters safelisted IPs BEFORE batch insert into `threat_intel`, so third-party feeds (emerging_threats, feodo_tracker, tor_exit_nodes) can't auto-block Googlebot or CDN ranges.
- **`backend/app/services/firewall_sync.py`** — `_pull_blocklist_from_pi()` now auto-evicts `local_only` IPs (in Mac blocklist but not on Pi) after `AEGIS_STALE_LOCAL_EVICT_HOURS` (default 24h) grace window. Stops the persistent "9 IPs stale_on_mac" warning that fired every 5 min indefinitely.
- **`backend/app/services/retention.py`** (NEW) — APScheduler-driven retention. Two jobs registered on the global `scheduled_scanner.scheduler`:
  - `nightly_retention_purge` (cron 03:00) — `DELETE FROM incidents WHERE detected_at < now() - INTERVAL '90d' AND status IN ('resolved','auto_responded')`. Same cutoff for `attacker_profiles` and `honeypot_interactions`.
  - `hourly_stuck_incident_closer` (interval 1h) — `UPDATE incidents SET status='resolved', resolved_at=now() WHERE status='investigating' AND detected_at < now() - INTERVAL '24h' AND source_ip IN threat_intel`. Closes the 5,240 stuck rows whose IPs are already blocked elsewhere.
  - Honors `AEGIS_RETENTION_DRY_RUN=1` (logs what would be purged without mutating). All actions appended as JSONL to `~/.aegis/retention-audit.jsonl` so operators can replay or audit.
  - Configurable: `AEGIS_RETENTION_DAYS` (default 90), `AEGIS_STUCK_CLOSER_HOURS` (default 24).
- **`backend/app/main.py`** — Lifespan wires `retention_service.start()` after `scheduled_scanner.start()` and `retention_service.stop()` in teardown.

#### Presentation
- **`backend/app/api/dashboard.py`** — `/live-metrics` accepts `?window=24h|7d|30d|all` (default 24h). `/threat-map` accepts `?window=…&limit_per_source=N` (defaults `all` and 2000, was hard-coded 200), and the response no longer truncates at top-50 countries.
- **`frontend/src/components/shared/GlobalThreatMap.tsx`** — `COUNTRY_COORDS` expanded from 25 → 249 ISO-3166-1 alpha-2 entries with `{ lat, lng, label }` centroids. Stops silently dropping ~225 countries via the `if (!coords) return null;` guard.

#### Tests (new)
- `backend/tests/test_log_watcher_dedup.py` — 4 tests: identical attacks collapse, URL variation collapses, different IPs DO create separate incidents, Tor exit annotation.
- `backend/tests/test_ip_blocker_purge.py` — 4 tests: Googlebot purged, RFC5737 purged, real attacker preserved, file rewritten.
- `backend/tests/test_retention.py` — 5 tests: old resolved purged, recent kept, dry-run no-op, stuck closer on blocked IPs, JSONL audit log written.

#### Docs
- `CLAUDE.md` reconciled: removed stale "AEGIS_FIREWALL_URL is intentionally unset" claim (it's active since v1.6.1). Topology now correctly states Pi 5 + Hailo runs `aegis-firewall.service` as remote executor.

### Changed
- Versions: `backend/app/__init__.py`, `backend/app/main.py` (3 sites), `frontend/package.json` — all `1.6.1` → `1.6.2`.

### Operational (production)
- One-shot SQL applied to Postgres `cayde6` on Mac Pro: purged `threat_intel` rows matching AEGIS_SAFE_IPS CIDRs + RFC5737 + known FP literals (Googlebot, Kali pentest host, Starlink, Tailscale CGNAT IPs). Rewrote `~/AEGIS/blocked_ips.txt` filtering safelist. Auto-closed `investigating` incidents older than 24h whose `source_ip` was already in threat_intel — ~5,000 rows promoted to `resolved`.

### Not yet integrated (deferred to v1.6.3)
- Kernel CVE detection (Dirty Frag, Copy Fail, runc escape, systemd-machined) — requires eBPF/auditd endpoint agent.
- Behavioral baseline for slow-and-low APT (rotating-IP brute force across hours).
- Cross-source incident dedup at correlation_engine level (eliminate residual 1:1 doubling with fast_triage).
- Severity tier rebalancing for the remaining 7 audit-flagged rules.

---

## [1.6.1] - 2026-05-14

### Added — Ransomware Defense & Cloud-Native CVE Coverage

#### Sigma rule pack — 2025-2026 CVE coverage (8 new rules)
- **`sigma_web_nextjs_rsc_rce`** — CVE-2025-55182 React2Shell (RSC Flight RCE, KEV-listed Dec 2025, CVSS 10.0).
- **`sigma_web_nextjs_segment_prefetch_bypass`** — CVE-2026-44575 Next.js 15 App Router middleware bypass via `.rsc?`, `__RSC_MANIFEST__`, `/_next/data/`, segment-prefetch routes.
- **`sigma_web_vite_fs_disclosure`** — CVE-2025-30208 / CVE-2025-31486 Vite dev server `/@fs/` arbitrary file read with `?raw??`, `?import&raw`, `?raw&url` query variants.
- **`sigma_web_marimo_terminal_rce`** — CVE-2026-39987 Marimo notebook pre-auth `/terminal/ws` RCE (CVSS 9.3, KEV-listed).
- **`sigma_web_vllm_ssrf_bypass`** — CVE-2026-25960 vLLM `<0.17.0` SSRF allowlist bypass via URL parser differential (backslash + at-sign).
- **`sigma_web_nextjs_image_ssrf`** — Next.js `/_next/image?url=` + Cloudflare `/cdn-cgi/image/` SSRF probing localhost / RFC1918 / cloud metadata endpoints (covers CVE-2026-3125).
- **`sigma_web_pickle_rce_endpoint`** — CVE-2026-26215 generic pickle / dynamic-method-execute endpoint probe.
- **`sigma_web_parametric_brute`** — Parametric endpoint brute-force / ID enumeration across 15 parametric collections.

#### log_watcher PATTERNS — supply-chain stdout detection (3 new patterns)
- **`npm_supply_chain_worm`** (critical) — Shai-Hulud 2.0, TanStack compromise, Sept 2025 chalk/debug wave. Markers: attacker Ethereum address `0xFc4a...`, malware C2 domains (`updatenet.work`, `npmjs.help`), injected browser globals (`stealthProxyControl`, `checkethereumw`, `runmask`, `newdlocal`), Bun runtime drops (`/tmp/bun_*`), pre/postinstall `node -e eval` patterns.
- **`hf_malicious_model`** (high) — HuggingFace malicious model pull. Markers: pickle/binary weights on resolve URLs, `snapshot_download(revision=<commit-sha>)`, `trust_remote_code=True`.
- **`marimo_terminal_rce`** (critical) — Defense in depth marker for Marimo terminal websocket access at the log-line level.

#### File Integrity Monitoring expansion
- **`FIM_PATHS`** now covers macOS launch persistence (`/Library/LaunchDaemons/`, `/Library/LaunchAgents/`), cron / sudoers persistence (`/var/spool/cron/`, `/etc/cron.d/`, `/etc/sudoers.d/`), cloud credential exfil targets (`~/.aws/`, `~/.kube/`, `~/.docker/`, `~/.config/gh/`).
- **`FIM_CRITICAL_MARKERS`** — substring markers that elevate any file event to `critical` severity: `/tmp/bun_` (Shai-Hulud), `/authorized_keys`, `/etc/sudoers.d/`, launch dirs, `.aws/credentials`, `.kube/config`, `.docker/config.json`, `/dev/null`, `/dev/console` (runc escape class).

#### Pi-side firewall executor (Rasputin-style restored)
- **`AEGIS_FIREWALL_URL=http://<pi>:8765`** re-enabled. AEGIS delegates iptables block enforcement to `aegis-firewall.service` on the Pi 5 + Hailo gateway via `firewall_client`. End-to-end verified: Kali → Sable HTTP log → AEGIS detection → `POST /block` to Pi → iptables DROP confirmed.
- **`aegis-iptables-init.service`** (Pi) — idempotent `AEGIS_BLOCK` chain creation linked into INPUT/FORWARD, persisted via systemd one-shot.

#### log_watcher — file-tail multiplexer (replaces broken PM2 subprocess)
- **`_tail_pm2_files(settings)`** — replaces `pm2 logs` subprocess (which returned EOF in ~2 ms with no TTY and silently dropped every log line). Now opens `~/.pm2/logs/<app>-{out,error}.log` directly, seeks to EOF, polls every 0.5 s, with inode-change rotation detection every 30 s.
- **`_resolve_pm2_log_paths(apps)`** — queries `pm2 jlist` at startup to resolve the *actual* log paths for each monitored app, supporting custom log paths outside `~/.pm2/logs/` (e.g., apps that pipe to `~/web-logs/<app>.log`).
- **AI offline gate in `ai_manager.chat()`** — short-circuits when `AEGIS_AI_MODE ∈ {disabled, offline, off, none}`, returning a synthetic zero-cost response. Zero outbound httpx in offline mode (verified).

#### Google Gemini provider
- **`GeminiProvider`** in `app/core/ai_providers.py` — multi-model provider with `gemini-flash-lite-latest` default. Wired into `AIManager` task-routing.

### Changed
- Production version string `1.6.0` → `1.6.1` across `backend/app/__init__.py`, `backend/app/main.py`, `frontend/package.json`.
- `AEGIS_FIREWALL_URL` reversed from "commented out — never re-enable" (v1.5 stance) to "active — Pi runs aegis-firewall as executor" (v1.6 stance).

### Security
- Detection coverage expanded against KEV-listed CVEs of 2025-2026: CVE-2025-55182 (React RSC), CVE-2026-39987 (Marimo), CVE-2026-44575 (Next.js segment-prefetch).
- Supply-chain worm coverage for Shai-Hulud 2.0, TanStack compromise, and the Sept 2025 chalk/debug wave (2.6B weekly downloads affected).

### Not yet integrated (kernel / eBPF needed)
- CVE-2026-43284 "Dirty Frag" (Linux ESP/RxRPC kernel)
- CVE-2026-31431 "Copy Fail" (AF_ALG splice → root)
- CVE-2025-31133 / -52565 / -52881 (runc container escape — file-watcher hints exist via `/dev/null`, `/dev/console` markers, but full coverage needs syscall tracing)
- CVE-2026-4105 (systemd-machined D-Bus race)

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

- **Kali probe silenced** — `AEGIS_ATTACKER_IPS=<RED_TEAM_IP>` (Kali red-team system) enables 342 previously-silenced sqlmap requests to generate real incidents. The internal-IP filter was correct for prod but blocked all red-team traffic.
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

[1.6.1]: https://github.com/<github-org>/AEGIS/releases/tag/v1.6.1
[1.5.0]: https://github.com/<github-org>/AEGIS/releases/tag/v1.5.0
[1.4.0]: https://github.com/<github-org>/AEGIS/releases/tag/v1.4.0
[1.2.0]: https://github.com/<github-org>/AEGIS/releases/tag/v1.2.0
