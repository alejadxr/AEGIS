# Changelog

All notable changes to AEGIS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.6.4.7] - 2026-07-18 (memory hardening — bound the four remaining unbounded caches)

### Security note (unbounded-memory DoS vector)
- The structures below grew without bound per unique attacker IP / incident / scan. Besides the slow leak (~60 MB/day observed at ~270k events/day), an attacker generating traffic from many spoofed/rotating source IPs could accelerate worker memory growth toward the PM2 2 GB restart ceiling — a low-severity, self-inflicted DoS vector. All four are now bounded; upgrading is recommended for internet-exposed deployments.

### Fixed - residual slow leak after 1.6.4.5/1.6.4.6 (~2.5 MB/h at steady state)
- Live introspection (vmmap) localized the growth to pymalloc arenas (small Python objects), i.e. the same "per-IP dict entries never evicted" class 1.6.4.5 fixed elsewhere. Four unbounded structures remained:
  - `services/ip_intel.py` — `_CACHE`/`_DEEP_CACHE` only expired an entry when the **same IP** was looked up again after TTL; entries fed by every incident (via the `after_insert` enrichment listener) accumulated forever. Added a periodic `sweep()` (TTL expiry + `cap_lru` 50k), wired as a 300 s task in `main.py`.
  - `services/counter_attack.py` — `_analyses` kept one ~1-4 KB analysis dict per incident forever. Capped at 5,000 entries (LRU).
  - `services/host_monitor.py` — `_conn_tracker` pruned each PID's timestamp list but never removed dead-PID keys. Added a 60 s sweep loop (`prune_stale_list_map` + `cap_lru`), wired into start()/stop().
  - `services/scanner.py` — `_active_scans` retained the full discovery+nuclei payload of completed scans indefinitely. Now popped once the terminal state is persisted (the `scans` table is the source of truth; reads already fall back to DB).
- All bounding uses the existing `core/mem_bounds.py` helpers, off the hot path.

### Docs
- README: rule count corrected to the actual repo contents (168 Sigma + 6 chain rules — badge and JSON-LD previously said 134), version badge/JSON-LD bumped, `downloadUrl` now points to `releases/latest`.

---

## [1.6.4.6] - 2026-07-17 (memory — GeoIP compact storage, the real leak)

### Fixed - GeoIP memory (dominant term of the 3.2 GB worker footprint)
- `offline_geoip.py` parsed the 8.07-million-row db-ip **city** CSV into Python `list[int]` (starts/ends) + `list[tuple[str,str,str]]` (country/region/city), costing **~2 GB RSS** — the single largest contributor to the leaked worker (v1.6.4.5 bounded the per-IP dicts, but the GeoIP baseline remained). Rewritten to:
  - store range bounds in `array.array('Q')` (8 bytes/entry vs ~36 for Python ints),
  - keep only `country` as a compact `array.array('I')` index into a deduplicated ~250-entry country table (region/city dropped — nothing depends on them from the offline source; `ip_intel` uses live HTTP providers for those and offline country/asn only as a fallback),
  - skip IPv6 rows (128-bit ints overflow uint64 arrays; IPv6 geo rarely needed).
- Result verified in production: worker RSS **3.2 GB → ~570 MB (−82%)**, stable.
- Side benefit: offline GeoIP lookups now resolve correctly (previously returned `None` for all IPs), so the dashboard threat map now shows real attacker countries instead of "Unknown".

### Note
- The PM2 memory-restart backstop (ecosystem.config.js, added in 1.6.4.5) can now be applied safely: the ~570 MB baseline sits well under the 2000 MB ceiling, whereas the previous 3.2 GB baseline would have caused a restart loop.

---

## [1.6.4.5] - 2026-07-17 (memory hardening — bound per-IP tracker growth)

### Fixed - Memory Bounding

Six in-memory structures accumulated one entry per unique attacker IP seen since process start, causing the observed 3.2 GB RSS leak under sustained honeypot traffic. All bounding is idle/stale-key eviction only — active-attacker detection windows and thresholds are unchanged.

- **core/mem_bounds.py** (NEW): Shared helpers `prune_stale_deque_map`, `prune_stale_list_map`, `prune_stale_ts_map`, `prune_stale_keyed_maps`, `cap_lru` (DEFAULT_MAX_KEYS=50k). Called from periodic background sweeps, never on the hot path.
- **services/correlation_engine.py** (Rank-1): `_sigma_fire_log` value type changed from unbounded list to `deque(maxlen=200)`. Added `_prune_loop()` (300s) evicting stale `_sigma_fire_log` keys (>7200s idle), `_fired`/`_chain_fired` past 2x/10x cooldown, and campaign tracker per-IP phase state idle >3600s. New `stop()` wired into main.py shutdown.
- **core/attack_detector.py** (Rank-2): `sweep_attack_log()` evicts `_attack_log` keys whose deque is empty or newest hit is older than BLOCK_WINDOW (300s). Background `attack_log_sweeper()` coroutine (60s) started/cancelled in main.py lifespan.
- **services/dos_shield.py** (Rank-3): Added absolute idle TTL in `_prune()` that force-evicts `_ip_state` entries idle past `max(max_window, block_duration, 900)s` regardless of active concurrency counter — fixes stuck TCP half-open/slow-loris preventing eviction. Added `cap_lru(50k)` backstops on `_ip_state` and `_subnet_hits`. Added `prune_stale_ts_map` on `_event_cooldown` (which previously had NO eviction).
- **services/log_watcher.py** (Rank-5): Added `.prune()` to `RateTracker` and `PortScanTracker`. New `_sweep_loop()` (60s) in `LogWatcher` sweeps all trackers and proactively evicts `_incident_cooldown` entries older than 2x cooldown (previously only evicted when len>1024).
- **core/ws_push.py**: Added `MAX_CLIENTS=512` cap with FIFO eviction of oldest zombie socket in `connect()`; added `total_evicted_over_cap` stat.
- **core/events.py**: `unsubscribe()` now deletes the event_type key when its handler list becomes empty (prevents empty-list key retention).
- **services/incident_enrichment.py**: Added `_ENRICH_TIMEOUT_S=15.0` + `_enrich_guarded()` wrapper using `asyncio.wait_for()` so every enrichment task terminates and is discarded from `_pending_tasks`.
- **ecosystem.config.js** (NEW): PM2 ecosystem file launching venv python directly (interpreter:none) so `max_memory_restart` monitors the real uvicorn worker (2000M for API, 1000M for frontend) rather than a ~1MB bash wrapper. Not yet applied — operator must run: `pm2 delete cayde6-api && pm2 start ecosystem.config.js --only cayde6-api`.

### Result
Fresh worker RSS baseline after restart: 543 MB (was 3.2 GB before fix).

---

## [1.6.4.4] - 2026-07-14 (dashboard visibility — widen campaign/history windows)

### Fixed - Dashboard Visibility

Historical attack data was invisible on first load because default query windows were too narrow.

- **api/threats.py**: campaigns default window 24h -> 168h, cap 14d -> 30d; added 7d/14d/30d historical fallback + effective_window_hours field; feed endpoint gained `?limit` param (1..10000).
- **services/ttp_clustering.py**: detect_campaigns and get_campaign_detail now exclude [FP-*] incidents so crawler noise cannot form fake campaigns.
- **api/dashboard.py**: live-metrics default window changed from '24h' to '30d' so weeks-old attacker/target top-lists render by default.
- **modules/phantom/intel.py**: generate_threat_feed gained bounded limit param (default 1000, max 10000), replacing hard-coded .limit(1000).
- **api/intel_cloud.py**: community/stats endpoint now awaits intel_cloud.get_stats_live() for DB-backed real-time counts.
- **services/intel_cloud.py**: added async get_stats_live() reconciling iocs_submitted/unique_contributors against non-expired shared_iocs, with in-memory fallback.
- **models/scan.py**: NEW Scan ORM model persisting scan history (composite index on client_id, created_at).
- **models/__init__.py**: registered Scan model so its table is created by Base.metadata.create_all.
- **services/scanner.py**: persist scans to DB on start/complete/fail; get_scan/list_scans now async and DB-backed with in-memory merge for in-flight scans.
- **api/surface.py**: scans list/detail endpoints inject db and await the now-async orchestrator methods.
- **frontend/threats/campaigns/page.tsx**: Changed default campaign window from 168h to 720h (30d) so historical campaigns render on first load.
- **frontend/threats/CampaignFilters.tsx**: Replaced WINDOWS selector with honest 24h/7d/14d/30d progression; removed misleading duplicate 'All' option.

---

## [1.6.4.3] - 2026-07-14 (auth session-check FP fix + block gating)

### Fixed - Auth Session-Check False Positive

Root cause: GET /api/v1/auth/me returning 401 (normal session expiry / unauthenticated browser poll) was classified identically to brute-force credential attacks, creating spurious incidents and blocks for residential ISPs and cloud crawlers.

- **event_normalizer.py**: Added _SESSION_CHECK_PATHS frozenset and _is_session_check() helper. Non-POST requests to session-check paths returning 401 are now classified as session_check_401 at low severity instead of generic auth_failure.
- **log_watcher.py**: Added is_session_check_401 guard in _run_behavioural_detectors(). Brute-force gate skips 401s on session-check paths.
- **correlation_engine.py**: Added /api/v1/auth/me, /api/v1/auth/refresh, /api/v1/auth/logout, /api/v1/auth/session to path_excludes for http_auth_brute_force and generic_credential_attack rules.

### Added - Auto-Block Confirmation Gate

Single-event or low-confidence detections no longer auto-block IPs without meeting explicit confirmation thresholds.

- **playbook_engine.py**: New is_confirmed_attack() helper. Block-ip actions are withheld (status=withheld_requires_approval) unless the alert matches confirmed exploit rules OR meets brute-force thresholds (5+ events at high+ severity). Non-block actions execute immediately.
- **ai_engine.py**: New _alert_block_confirmed() check in process_alert(). Unconfirmed blocks route to _create_pending_block() creating a PENDING Action. Confirmed blocks continue through guardrail_engine unchanged.

### Operational - FP Cleanup

- 17 false-positive IPs unblocked from Pi firewall and removed from threat_intel: social media crawlers, residential ISP single-401 events, cloud single /api/og Open Graph crawler hits.
- Corresponding incidents tagged with FP-SESSION-CHECK, FP-OG-CRAWLER, and FP-CRAWLER-TWITTER prefixes.

---

## [1.6.4.1] - 2026-07-14 (dashboard FP filter)

### Fixed
- Dashboard aggregation endpoints (live-metrics top attackers + attack types, threat-map, featured-incident, auth-attempts monthly, incidents daily-counts) now exclude `[FP-*]`-prefixed incidents, matching the incidents list. Previously benign crawlers and operator/internal IPs appeared as "top attackers" and dominated the threat map; the dashboard now reflects only real threats.

### Known limitation
- The offline GeoIP dataset lacks country coverage for some attacker ranges (e.g. Starlink CGNAT, certain cloud ranges), which render as "Unknown" on the threat map until the dataset is upgraded.

---

## [1.6.4.0] - 2026-07-14 (DoS/DDoS Shield)

Application-layer DoS and DDoS detection module added as an always-on
monitor with network-tier blocking gated behind a feature flag.

### Added
- **`dos_shield`** service (`backend/app/services/dos_shield.py`) — per-IP,
  per-subnet, and global request-rate counters with configurable thresholds
  for HTTP flood, distributed flood, expensive-endpoint abuse, Slowloris
  connection exhaustion, and coordinated under-attack mode. Runs in monitor
  mode by default (detect-only, no blocks) so operators can tune thresholds
  before enabling enforcement.
- **`DoSShieldMiddleware`** (`backend/app/core/dos_middleware.py`) — ASGI
  middleware that feeds every inbound request into the shield counters and
  emits structured `dos.*` events onto the internal event bus.
- **`/api/v1/dos` router** (`backend/app/api/dos.py`) — status endpoint,
  per-IP counter inspection, threshold configuration, and manual override
  to switch between monitor-only and enforcement modes at runtime.
- **DoS correlation rules** — five new Sigma-style chain rules covering
  HTTP flood, distributed flood, expensive-endpoint abuse, Slowloris, and
  global under-attack patterns. Integrated with the existing rules loader
  and hot-reload path.
- **Network-tier blocking** (`firewall-agent/dos_netshield.py`) — optional
  iptables/nftables rate-limit enforcement on the Pi network segment, off
  by default. Activated only when the `DOS_NETWORK_TIER` feature flag is
  set, keeping production impact zero until explicitly opted in.
- **`firewall-agent/rate_limit_rules.example.json`** — reference config
  documenting per-route and global rate-limit parameters.
- **`scripts/dos_hardening.md`** — operational runbook: threshold tuning
  guide, escalation from monitor to enforce mode, rollback procedure.
- **`backend/tests/test_dos_shield.py`** — unit tests for counter logic,
  threshold evaluation, and event emission.

### Operational
- Monitor mode is the default; no traffic is dropped until the operator
  sets `DOS_ENFORCE=1` in the environment.
- Network-tier blocking (Pi segment) is disabled by default; set
  `DOS_NETWORK_TIER=1` to enable iptables rate-limit rules on the
  remote firewall executor.
- `/health` reports `version=1.6.4.0`.

---

## [1.6.3.11] - 2026-06-30 (cold-cache perf)

Eliminates the cold-cache tax on the first dashboard request after every
restart by pre-warming the DB pool, SQLAlchemy compile cache, and the
`/dashboard/overview` result cache during startup — off the event loop.

### Measured (Mac Pro production, 2 consecutive curls, after warmup)

| Endpoint | v1.6.3.10 cold | v1.6.3.11 1st | v1.6.3.11 2nd |
|---|---:|---:|---:|
| `/dashboard/overview` | 1.253 s | **415 ms** (3× faster cold) | 899 ms (cache miss between) |
| `/dashboard/monitored-apps` | 1.044 s | **192 ms** (5× faster cold) | 327 ms |
| `/dashboard/featured-incident` | 866 ms | **180 ms** (5× faster cold) | 291 ms |
| `/dashboard/threat-map` | 513 ms | 1076 ms (full query path) | **171 ms** |
| `/dashboard/live-metrics?window=24h` | 526 ms | **375 ms** | 541 ms |

### Added
- **`warmup_dashboard_cache()`** in `backend/app/api/dashboard.py` — runs after `warmup_pm2_cache()` in the FastAPI lifespan. Sequence: 5 parallel DB pool ping → resolve bootstrap client → serial pre-runs of /overview, /monitored-apps, /featured-incident, /threat-map, /live-metrics → populate `_OVERVIEW_CACHE` so the first request finds the result cached.
- **`logger = logging.getLogger("aegis.dashboard")`** module-level logger so warmup paths can log progress + warnings without sprinkling print statements.
- New startup log line: `[aegis.dashboard] INFO: dashboard warmup: pool + compile cache + result cache primed`.

### Operational
- `/health` reports `version=1.6.3.11`.
- Zero errors in `pm2 logs cayde6-api --err`. The intermediate v1 of the warmup used `asyncio.gather()` on a single AsyncSession which raises an `InvalidRequestError` (sessions can't do concurrent queries); fix was to make the warmup serial (only the live endpoint uses gather, where FastAPI injects a fresh session per request).
- Net effect: operator hits the dashboard URL the first time after a restart and the KPI tiles render in 415 ms instead of 1253 ms — the difference between "feels instant" and "feels stale".

---

## [1.6.3.10] - 2026-06-30 (perf)

Targeted attack on the two endpoints flagged in v1.6.3.9 as >1.5s. No new
features — just stop scanning growing tables on every dashboard load and
stop paying the cold PM2-jlist tax on every restart.

### Measured (Mac Pro production, X-API-Key, 3 consecutive curls)

| Endpoint | v1.6.3.9 | cold | warm | Speedup (warm) |
|---|---:|---:|---:|---:|
| `/dashboard/overview` | 1.748 s | 1.253 s | **175 ms** | **10×** |
| `/dashboard/monitored-apps` | 3.697 s | 1.044 s | **131 ms** | **28×** |

### Added
- **30-second in-process result cache** on `/dashboard/overview` (per client) — KPI tiles redraw 10× per minute on an active dashboard; the TTL collapses 10 DB round-trips into 1.
- **`warmup_pm2_cache()` startup task** in `main.py` lifespan — fires `pm2 jlist` off the event loop after `scheduled_scanner.start()` so the first `/monitored-apps` request after restart doesn't pay the 1-5 s cold-cache penalty.
- **PM2 cache TTL extended** 15 s → 60 s — PM2 process status changes rarely; 60 s removes ~75 % of subprocess calls.

### Changed
- `/dashboard/overview` COUNT queries on `HoneypotInteraction` and `Action` now bounded to `>= NOW() - 30 days`. Unbounded scan was the slowest leg of the `asyncio.gather()`.
- `/dashboard/monitored-apps` per-app `GROUP BY` query bounded to `Incident.detected_at >= NOW() - 90 days`.

### Operational
- `/health` reports `version=1.6.3.10`.
- Zero errors in `pm2 logs cayde6-api --err` after restart.
- Cold-call regression remaining (`/dashboard/overview` 1.25 s cold) is bounded by DB pool warmup — next perf pass if needed (DB pool pre-warm).

---

## [1.6.3.9] - 2026-06-30 (architectural completion)

Closes every deferred item from the v1.6.3.7 / v1.6.3.8 sequence. The
detection-logic rebuild is now FULLY functional in production. 13-agent audit
+ 5-Opus parallel rewrite + Sonnet cross-file integration verification.

### Headline
- **172 rules now loaded** in `correlation_engine._rules` (was 166): the merge of `BUILT_IN_RULES` on top of the YAML pack actually runs, and the 3 v1.6.3.7 in-code rules (`http_auth_brute_force`, `ssh_honeypot_attempt`, `generic_credential_attack`) are present and routable from event #1.
- **0 active operator-IP incidents** in the visible dashboard, **0 SSH-titled HTTP 401 events**, **0 visible `[FP-*]` rows** in the operator queue.
- **5063 historical `auto_responded` incidents** older than 24h auto-resolved (collapsed the 5000+ open-counter the dashboard was inheriting).

### Added
- **Backend `?include_fp=false` default** on `/api/v1/response/incidents` — hides any incident whose title starts with `[FP-…`. Pass `include_fp=true` for forensic / compliance access to the full audit trail.
- **Frontend filter** in `dashboard/page.tsx` + `dashboard/response/page.tsx` — `[FP-*]` prefixed and `auto_responded` status hidden from the active threat queue.
- **Port-aware inline brute-force tracker** in `log_watcher.py` — per-port threshold + severity:
  - port 2222 (SSH honeypot): every hit = CRITICAL, threshold 1
  - port 22 (real sshd): 5 in 60s = CRITICAL
  - other / HTTP API: 20 in 60s = HIGH
  - dashboard paths: skipped entirely
- **`backend/scripts/v1639_smoke.py`** — pure-stdlib smoke test that hits `/health`, asserts new rule IDs are loaded via `/api/v1/threats/rules`, and verifies zero unresolved `[FP-*]` rows. Runs against AEGIS_API_KEY env var.

### Fixed
- **`event_normalizer.py`** confirmed to emit protocol-discriminated event types (`http_auth_failure`, `ssh_honeypot_failure`, `ssh_real_failure`, generic `auth_failure` fallback). The v1.6.3.8 audit incorrectly flagged this as missing — it was present and working; this release adds smoke-test coverage so the question doesn't reopen.
- **`correlation_engine.__init__` merge step** — the v1.6.3.7 spec said BUILT_IN_RULES merge on top of YAML pack with YAML winning on id collision, but the actual deploy had only the fallback path (BUILT_IN used only on YAML load exception). Merge logic now runs unconditionally with a startup `logger.info("rules loaded: N sigma + M chain (yaml=Y, builtin=B, dedup=D)")` audit line so the operator can verify on every restart.
- **`ai_engine.SIGMA_TO_THREAT_TYPE`** — added `http_auth_brute_force → brute_force`, `ssh_honeypot_attempt → honeypot_recon`, `generic_credential_attack → brute_force`. Added `honeypot_recon` entry to `RESPONSE_ACTIONS` with `["block_ip", "collect_evidence"]`.
- **`brute_force_401` description string** in the inline detector now reports the actual port from the typed event instead of hardcoded text, so an operator reading the incident can immediately tell whether the brute force was on port 2222 / 22 / 8000.

### Operational
- `/health` reports `version=1.6.3.9`.
- 5063 stale `auto_responded` incidents older than 24h have been resolved in bulk to clear the dashboard counter inheritance (5061 of these were the same real-attacker `148.0.72.76` dedup-artifact incidents — the block is preserved, only the duplicate incident rows are closed).
- Backend `/api/v1/response/incidents?since=24h` returns `count: 0` after the cleanup — confirming the filter + bulk-resolve both landed.
- `dashboard/monitored-apps` at 3.7s and `dashboard/overview` at 2.2s remain over the 500ms SLA — deferred to next perf pass (PM2 jlist cache warmup tuning + COUNT query time-window scoping).

---

## [1.6.3.8] - 2026-06-30 (regression hotfix)

Honest follow-up to v1.6.3.7. A 12-agent status audit found the v1.6.3.7
"detection-logic rebuild" was **incomplete in production**: new modules
shipped clean, but the YAML rules-loader shadowed the new Python BUILT_IN_RULES
so the protocol-aware rules were dead code, and log_watcher kept publishing on
both `log_line` AND `log_event` while correlation_engine subscribed to both,
causing exact 1:1 double-counting. FP rate rose to 99.8% (452/453 in 24h)
instead of dropping.

### Root causes (caught by 12-agent post-deploy audit)

1. **YAML pack shadows `BUILT_IN_RULES`** — `correlation_engine.__init__` loads rules via `rules_loader.load_rules()` (YAML pack) and only falls back to in-code rules on exception. The v1.6.3.7 `http_auth_brute_force` / `ssh_honeypot_attempt` / `generic_credential_attack` rules never entered `self._rules`.
2. **`event_normalizer` still emits `event_type='auth_failure'`** — not the protocol-discriminated `'http_auth_failure'`/`'ssh_honeypot_failure'` values the new rules required. Even if the new rules HAD loaded, they would never have matched.
3. **Double-publish in `log_watcher`** — line 530 publishes raw `log_line` (for the Live Log UI widget) and line 575 publishes typed `log_event`. `correlation_engine` subscribed to BOTH, calling `evaluate()` twice per source event. Source distribution confirmed the symptom: `correlation_engine: 226 + fast_triage: 226` exact-equal counts for the same 24h.
4. **Rule sync gap** — `sigma_auth_account_lockout.yaml` was disabled in the local checkout (commit 7ce5757, 2026-05-31) but the stale `enabled: true` version was still on Mac Pro, doubling SSH-class incidents alongside `brute_force_ssh`.
5. **`brute_force_ssh.yaml`** was never touched — it had `count_threshold: 5, time_window_seconds: 300` and produced all 225 "SSH Brute Force Detected" titled incidents from the operator's IP this 24h window.

### Fixed
- `backend/app/rules/sigma/authentication/brute_force_ssh.yaml`: title corrected to "Auth Brute Force (HTTP 401) Detected"; threshold raised 5 → 20 in 300s; `cooldown_seconds: 3600` added; `path_excludes` filter listing operator paths (`/api/v1/auth/`, `/api/v1/dashboard/`, `/dashboard/`, `/login`, `/ws`, `/api/v1/health`, `/api/v1/me`, `/api/v1/version`); MITRE technique corrected to `T1110` (was `T1110.001` sshd-specific despite matching HTTP).
- `correlation_engine.py` no longer subscribes to legacy `log_line` — only to `log_event` (the typed-event topic). `_on_log_line` remains as a manually callable function for tests. This kills the exact 1:1 double-counting between `correlation_engine` and `fast_triage` sources.
- Synced 4 stale YAML rules to Mac Pro: `brute_force_ssh.yaml`, `sigma_auth_account_lockout.yaml`, `sigma_auth_default_credentials.yaml`, `sigma_auth_impossible_travel.yaml`. The deploy pipeline never picked up local YAML edits.

### Operational
- `/health` reports `version=1.6.3.8`.
- Operator IP `179.52.12.148` and CIDR `179.52.0.0/15` confirmed clear across Mac, Pi, and `threat_intel.firewall` — the whitelist is still preventing the BLOCK; this release stops the FP INCIDENT being created in the first place.
- Expected FP volume drop on next 24h sample: from ~452/day to single digits (the inline `brute_force_401` tracker is the only remaining surface and it already has `threshold=15` + path skip from v1.6.3.5).
- Three v1.6.3.7-introduced deferred-work items remain (low priority): make `event_normalizer` emit protocol-discriminated event_types, merge `BUILT_IN_RULES` into `self._rules` (instead of fallback-only), add the new rules to `SIGMA_TO_THREAT_TYPE` in `ai_engine.py`. None are required for FP suppression — they unlock additional precision but the high-priority FP loop is closed in this release.

---

## [1.6.3.7] - 2026-06-29 (architectural)

Detection-logic rebuild driven by a 19-agent forensic audit (10 Haiku discover
+ 6 Sonnet verify + 3 Opus high-effort synthesis, 1.4M output tokens, 16 min
wall-clock). Replaces the duplicate regex tables and the hardcoded one-rule-
per-event-type model with a single normalized event pipeline + context-aware,
protocol-discriminating rules. The whitelist remains in place as a safety
net, but detection no longer DEPENDS on it for correctness — it now passes
benign traffic on its own merits.

### Root causes addressed

1. **Duplicate regex tables** — `log_watcher.PATTERNS` (~30 regexes) and `correlation_engine._LOG_PATTERNS` were defined independently and drifted: a pattern present only in one would create incidents but never advance the correlation window, or vice-versa.
2. **Event-type conflation** — `event_type=auth_failure` carried events from 4 distinct surfaces (HTTP API 401, dashboard 401, honeypot SSH on port 2222, real sshd) without distinction. Any rule listening to `auth_failure` fired on operator dashboard logins, then the title said "SSH Brute Force Detected" regardless.
3. **Missing context** — events carried only `source_ip` + `path`. No `target_port`, no `protocol`, no `request_method`, no `response_status`, no `user_agent`. Rules had no way to discriminate `sqlmap on port 8000` from `git clone on port 22`.
4. **Arbitrary severity** — severity was hardcoded per rule with no relationship to attacker tooling, repetition count, or known-attacker history. A single HTTP 401 typo got the same HIGH severity as a 100-event sqlmap burst.
5. **No post-detection dedup** — one attack burst that matched 5 rules created 5 separate incidents. The user saw "SSH Brute Force Detected" + "Auth Failure detected" + "High Request Rate" + "Path Traversal" + "Scanner Activity" as 5 rows for the same actor in the same minute.

### Added
- **`backend/app/services/event_normalizer.py`** (NEW, 860 lines) — the single source of truth for log-line → typed-event translation. Pure function `normalize(log_line, source) -> NormalizedEvent | None`. Extracts source_ip, request_path, request_method, response_status, user_agent, target_port. Tags protocol (`http_api` / `http_dashboard` / `ssh_honeypot` / `ssh_real` / `unknown`) so the same HTTP 401 line is classified differently depending on which surface produced it. Returns `None` on structural log noise (PM2 dividers, ExceptionGroup headers, AEGIS-internal source markers) so AEGIS's own diagnostic output no longer advances any counter.
- **`path_excludes` filter key** in `correlation_engine._matches_filter()` (was added in v1.6.3.6; documented here for context).
- **Severity scoring layer** in `correlation_engine` — every rule may declare a `confidence_factors` list. Calling code multiplies the rule's base severity by the matched factors before deciding final severity. Default catalog: `scanner_ua` × 1.3, `tor_exit` × 1.5, `known_attacker_history` × 2.0, `geo_high_risk` × 1.2, `burst_rate` × 1.4, `safelisted` × 0 (drop), `internal_ip` × 0 (drop).
- **Per-attack-class cooldown constants** (`COOLDOWN_AUTH=3600`, `COOLDOWN_RECON=600`, `COOLDOWN_EXPLOIT=300`, `COOLDOWN_EXFIL=600`, `COOLDOWN_CHAIN=0`, `COOLDOWN_HONEYPOT=0`, `COOLDOWN_SUPPLY=60`) — replaces the implicit 60s default that was inflating one attack into hundreds of incidents.
- **Protocol-aware Sigma rules** — split `brute_force_ssh` (which listened to `auth_failure` and mislabeled HTTP 401 as SSH) into 3 separate rules:
  - `http_auth_brute_force` — `event_type=http_auth_failure`, 15 events / 60 s, cooldown 3600 s, severity high, path_excludes for dashboard/login/auth/ws/health
  - `ssh_honeypot_attempt` — `event_type=ssh_honeypot_failure`, threshold 1 (every hit fires), severity critical, no cooldown
  - `generic_credential_attack` — `event_type=auth_failure` (fallback), 25 / 300 s, severity medium
- **New event-bus topic `log_event`** carrying NormalizedEvent payloads, subscribed by `correlation_engine._on_normalized_event` with safelist gating + direct evaluation (no regex re-matching).

### Changed
- **`log_watcher.py`** (refactored, ~899 lines): removed the entire on-disk PATTERNS list (~30 regexes) — pattern → event-type classification now lives in `event_normalizer`. `_process_line()` calls `event_normalizer.normalize()` once at the top, gates safelist once, publishes typed `NormalizedEvent` on `log_event`. Inline behavioural detectors (`brute_force_401`, `rate_tracker`, `port_scan`) are preserved because they operate ACROSS multiple events and are not expressible as a single Sigma rule.
- **`correlation_engine.py`**: BUILT_IN_RULES rewritten to be protocol-aware. Subscribes to new `log_event` topic via `_on_normalized_event` (defence-in-depth safelist re-check). Old `_on_log_line` subscription preserved for backwards compatibility during migration.
- **MITRE tag corrections** — `brute_force_ssh` was tagged `T1110.001` (sshd-specific) despite matching HTTP 401. Now correctly tagged `T1110` (generic credential brute force) with the protocol-specific variants carrying their own correct sub-techniques.

### Fixed
- A single attack burst no longer inflates into hundreds of incidents — per-class cooldowns + post-detection dedup work together so one IP attacking the API for 5 minutes generates 1-2 incidents instead of 150.
- Operator dashboard login typos no longer count as brute force — `path_excludes` filter on `http_auth_brute_force` skips `/api/v1/auth/`, `/dashboard/`, `/login`, `/ws`, `/api/v1/health`, `/api/v1/me`, `/api/v1/version`.
- HTTP 401 events no longer get titled "SSH Brute Force Detected" — they go through `http_auth_brute_force` which carries the correct title.

### Operational
- `/health` reports `version=1.6.3.7`.
- No incidents bulk-purged in this release — the operator already cleared the FP backlog in v1.6.3.5 and v1.6.3.6. This release prevents future FPs structurally.
- The Opus #1 module (`event_normalizer.py`) is the only new file. Opus #2 patched `correlation_engine.py` in place. Opus #3 rewrote `log_watcher.py` in place.

---

## [1.6.3.6] - 2026-06-29 (hotfix)

Hotfix on top of v1.6.3.5. Two root-cause defects identified by operator review.

### Root cause #1 — Operator's ISP was missing from safelist
- WHOIS verified that `179.52.12.148` belongs to `Compañía Dominicana de Teléfonos S.A.` (Codetel/Claro DR) with CIDR allocation `179.52.0.0/15`. Same ISP as the previously-safelisted `152.166.0.0/16` and `190.166.0.0/16`. The v1.6.3.5 audit conservatively classified this IP as "real attacker, keep blocked" based purely on the 1428-incident volume, without WHOIS verification.
- `179.52.0.0/15` (entire Codetel residential allocation) appended to `AEGIS_SAFE_IPS`.
- `179.52.12.148` removed from Mac Pro `blocked_ips.txt` and Pi `/blocked`. `threat_intel.firewall` entry purged.
- 1437 incidents re-prefixed `[FP-USER-DEVICE-179]` (was `[FP-DEDUP-SSH]`).

### Root cause #2 — `brute_force_ssh` rule was mislabeled
- The correlation engine `brute_force_ssh` rule listened on `event_type=auth_failure` which is emitted by `correlation_engine._on_log_line()` whenever a PM2 log line matches the HTTP-401 regex (line 109). NOT on actual sshd protocol failures. Result: every HTTP 401 from a user mistyping a password produced an incident titled "SSH Brute Force Detected".
- Title corrected to "Auth Brute Force (HTTP 401) Detected".
- Threshold raised 5 → 15 events in 300s, cooldown 60s → 3600s. One alert per IP per hour during a sustained campaign instead of dozens of duplicates.
- `path_excludes` filter added to the rule: `/api/v1/auth/`, `/api/v1/dashboard/`, `/dashboard/`, `/login`, `/ws`, `/api/v1/health`, `/api/v1/me`, `/api/v1/version`. Dashboard login typos no longer count.
- MITRE tag changed from T1110.001 (sshd-specific) to T1110 (generic credential brute force).

### Added
- `path_excludes` filter key in `correlation_engine._matches_filter()` — fails the rule when the event path contains any listed fragment. Symmetric to the v1.6.3.2 `path_contains_all`.

### Fixed
- `correlation_engine._on_log_line` now calls `_is_safe_ip()` before feeding events into the rule window. Previously safelisted IPs created `auth_failure` / `sql_injection` / `scanner` events that triggered rule firings + safelist drops at incident creation — wasteful and noisy. Now those events never enter the window.
- `log_watcher.PATTERNS` loop now also short-circuits on `is_dashboard_request` for `brute_force` and `reconnaissance` threat types — same protection as the inline `brute_force_401` detector.

### Operational
- `/health` reports `version=1.6.3.6`.
- `AEGIS_SAFE_IPS` extended by 1 CIDR (`179.52.0.0/15`).
- 0 active blocks now belong to the operator. 38 remaining blocks all confirmed real attackers.

---

## [1.6.3.5] - 2026-06-29 (patch)

Deep FP audit + safelist coverage expansion. 12-agent forensic workflow
(6 Haiku discover + 5 Sonnet verify + 1 Opus high-effort synthesis, 565 k
output tokens) traced every recurring brute-force / auth-failure / login
incident back to its root cause. Closes 1431+ false-positive incidents and
adds 4 code-level safelist gates that were leaking events to the database.

### Headline numbers
- **0 IPs unblocked** — all 39 currently-enforced blocks are confirmed real attackers (Claro DR botnet `179.52.12.148`, Tor exits, SSH brute farms, exploit-scanning VPS).
- **1431 FP incidents resolved** with audit-trail prefixes (`[FP-DEDUP-SSH]` for 1428 dedup artifacts from `179.52.12.148`, `[FP-CRAWLER-TWITTER]` for 3 Twitter/X crawler events).
- **11 new CIDR ranges** added to `AEGIS_SAFE_IPS` covering Bingbot /16, Meta CDN /16, Cloudflare edge, Twitter API, Google secondary ranges, LinkedIn Australia.
- **15 new crawler User-Agent substrings** added to `BENIGN_UAS` (Threadsbot, meta-externalagent, GoogleOther, Google-Extended, GPTBot, ClaudeBot, PerplexityBot, anthropic-ai, CCBot, ImagesiftBot, BingPreview, WhatsApp, FacebookBot, Slack-ImgProxy, Applebot-Extended).

### Added
- `_SAFE_PATHS` (log_watcher.py) extended with `/api/v1/auth/logout`, `/api/v1/auth/refresh`, `/api/v1/me`, `/api/v1/version`, `/api/v1/threats/feed`, `/favicon.ico`, `/_next/`. Operator browser polling no longer advances the brute_force_401 counter.

### Fixed
- **Inline `brute_force_401` threshold** raised from **5 → 15** failed 401s in 60s (NIST SP 800-63B baseline tolerates 5+ legitimate retries from password managers / typos). Deque now clears after firing so sustained campaigns re-alert each window instead of silently looping.
- **`firewall_sync._sync_auto_response_events`** now calls `_is_safe_ip()` before creating incidents from external Pi firewall events. Previously only hardcoded `127.0.0.1`/`::1`/`localhost` was checked — Bingbot, Googlebot, Cloudflare, Tailscale events from the Pi were creating AEGIS incidents.
- **`attack_chain_detector`** EDR chain rules now honor `AEGIS_SAFE_IPS` in addition to RFC1918+Tailscale. Previously CDN / partner crawler / monitoring infrastructure could trigger chain incidents.
- **`correlation_engine._create_incident`** silent `except Exception: pass` replaced with `logger.warning` so a broken import doesn't silently degrade safelist coverage.
- **`sigma_auth_default_credentials.yaml`** synced with the v1.6.2 in-code BUILT_IN_RULES fix: `event_type: auth_success` → `auth_failure`, removed `pi` and `ubuntu` from the username filter (cloud-init / Raspberry Pi hosts use them legitimately), added `count_threshold: 3` + `time_window_seconds: 300` + `cooldown_seconds: 600`. Was firing high-severity incident on EVERY successful admin/pi/ubuntu login.
- **`sigma_auth_impossible_travel.yaml`** thresholds relaxed: `count_threshold` 2 → 3, `time_window_seconds` 300 → 900, added `cooldown_seconds: 1800` to absorb legitimate VPN-then-native reconnects.
- **`high_request_rate` description string** now reads the actual threshold from `self._rate_tracker.threshold` (was hardcoded `>100 req/min` while the rate tracker uses 500).

### Operational
- 0 active blocks revoked. The 39 currently-enforced blocks were independently verified as real attackers across Mac Pro / Pi / threat_intel — they remain in place.
- Backend `/health` reports `version=1.6.3.5`.
- 11 safelist CIDRs added to `AEGIS_SAFE_IPS` env via `pm2 restart cayde6-api --update-env`.

---

## [1.6.3.4] - 2026-06-27 (patch)

Stability + completeness patch. Closes the last visible bugs from the
operator-driven UI review: duplicate hero panels, recharts width(-1)
errors, missing ransomware endpoints, recurring Twitter/X false positives,
and a stale light-mode default that masked the v1.6.3.2 warm-charcoal theme.

### Added
- `GET /api/v1/ransomware/stats` — aggregate `{rules_active, raas_groups_tracked, triggers_24h}` for the ransomware dashboard header tiles.
- `GET /api/v1/ransomware/raas-groups` — RaaS group activity timeline + per-group metadata `{name, activity_score, color}` for the threat-actor chart.
- `GET /api/v1/threats/events?type=ransomware&limit=N` — polymorphic ransomware event feed for the recent-events table. Filters by `T1486*` MITRE / `node-agent-ransomware` source / `ransom|encrypt` title keywords.

### Fixed
- **97 Twitter/X false-positive incidents** marked `[FP-AUDIT2]` and 4 IPs (`199.16.157.180-183`) unblocked from Mac + Pi. Root cause was a leak in the safelist-ingestion path that re-blocked the same `199.16.156.0/22` IPs even though the CIDR was already in `AEGIS_SAFE_IPS`.
- `recharts` `ResponsiveContainer` `width(-1) height(-1)` console errors on `/dashboard` — `ThreatDetectionChart` now has `h-[200px] min-h-[200px]` parent + `minHeight=180` on the `ResponsiveContainer`.
- Duplicate dashboard hero — the v1.6.3.3 dashboard rewrite left both the new `FeaturedIncidentHero` and the legacy inline hero+KPI tiles rendered. Removed the 100 lines of legacy hero markup; the new featured-incident block now stands alone.
- Asset table avatar bug: `r.asset.slice(0, 2)` produced concatenated text like `cacayde6-api` when copied to clipboard. Switched to `r.asset.charAt(0)` with a brand-orange circle background.
- Reports page returns 401 when `aegis_api_key` localStorage entry is missing → redirects to `/login?next=/dashboard/reports` instead of throwing a generic error.
- Dashboard light-mode default — the v1.6.3.2 warm-charcoal theme was masked because `<html data-theme="light">` was hard-coded. Default flipped to `data-theme="dark"` so the theme tokens take effect on a clean session.

### Changed
- `LoginAttemptsMatrix` v2: dot radius 2.5px → 5px, peak month renders in `#F97316` orange with all visible dots, total count promoted to `text-3xl` mono in the section header, per-column count label above each column. Replaces the previous near-invisible sparse-dot rendering.
- `IncidentTimeline` v2: auto-zoom when events cluster in a small time window so the timeline isn't 90% empty whitespace; range-selector pills now show count badges (`24H (12)`); event dots have hover halos and tooltips; explicit `h-[200px]` so charts below don't inherit `height: 0`.
- `AEGIS_SAFE_IPS` env var extended with Meta `31.13.64.0/18` and Apple/Threads `17.0.0.0/8` — caught two new crawler ranges (Threads-bot, FB-scraper) that were generating low-severity FPs.
- `AsciiThreatMap` replaced with a 25-continent hand-traced SVG map (vector paths, top-5 country labels with leader lines, tier-colored attack dots with halo glow). The v1.6.3.3 Braille rendering was illegible at the small `lg:col-span-4` width in production — the new vector map scales cleanly to any size. Component name and export surface preserved so callers don't break.
- `offline_geoip.refresh_async()` no longer invalidates the in-memory cache on weekly refresh; new CSV is picked up on next process restart instead. Prevents the 3-minute synchronous CSV reparse on the event loop that froze every endpoint when the refresh fired.
- PM2 `jlist` subprocess (used by `/dashboard/monitored-apps`) now cached for 15s — first call 5s cold, subsequent <50ms.

### Removed
- Inline hero + KPI grid markup in `frontend/src/app/dashboard/page.tsx` (≈108 lines) — superseded by the standalone `FeaturedIncidentHero` component.

### Operational
- `/health` reports `version=1.6.3.4`.
- `/dashboard` verified via Playwright against the production deployment at `http://100.87.222.58:3007` (single hero, single set of stat labels, cartographic map renders, login attempts dots visible, no console `width(-1)` errors).
- `/dashboard/ransomware` no longer 404s on the three previously-missing endpoints.

---

## [1.6.3.3] - 2026-06-26 (patch)

Operator-facing dashboard redesign. New incident-centric hero replaces the bare
overview at `/dashboard` — surfaces the highest-priority open incident with its
MITRE technique, source IP, affected asset and AI confidence as a 4-card hero,
plus a monthly login-attempts dot-density chart and an inline Reject/Approve
queue for pending AI-suggested actions.

### Added
- `GET /api/v1/dashboard/featured-incident` — returns the most-recent OPEN/INVESTIGATING incident with severity in [critical, high] (falls back to any open). Computed fields: `incident_number` (INC-XXXX from first 4 hex of UUID), `affected_asset` (joins to `Asset.hostname`/`ip_address`), `confidence` (parsed from `ai_analysis.confidence|ai_confidence`, falls back to severity-tier heuristic). Returns 200 with all-null payload when no open incidents exist — never 404.
- `GET /api/v1/dashboard/auth-attempts/monthly?months=6` — pre-aggregated monthly counts of authentication-failure incidents (MITRE T1110.x + title keyword fallback), gap-filled to always return N entries oldest-to-newest. Returns `{months: [{month, count}], total, peak_month}`.
- `PATCH /api/v1/response/actions/{id}` with `{status: 'approved'|'rejected'}` — wired from new dashboard Approve/Reject buttons.
- `frontend/src/components/dashboard/FeaturedIncidentHero.tsx` — "Hello, #INC-XXXX" greeting + 4 stat cards (Affected Asset / MITRE Technique / Source IP / Confidence) matching the operator-supplied mockup. Outfit headlines, Azeret Mono for IPs and confidence percentages. Severity color rail by `var(--danger)|var(--brand-accent)|var(--warning)`.
- `frontend/src/components/dashboard/LoginAttemptsMatrix.tsx` — SVG dot-density chart, 6 monthly columns × up to 25 dots each, peak month highlighted `#F97316` orange, all others `text-muted-foreground/25`. Deterministic horizontal jitter (no `Math.random`) for organic feel without breaking hydration.
- `frontend/src/components/dashboard/AISuggestedActionsList.tsx` — pending-actions list with Reject (red border) and Approve (orange brand) buttons. Optimistic UI: row fades to 0.5 opacity and buttons disable during await.

### Fixed
- `dashboard/auth-attempts/monthly` Postgres `GroupingError` — `func.date_trunc('month', col)` was emitted twice (once in SELECT, once in GROUP BY) producing distinct parameterized expressions, which Postgres rejected. Extracted to a single `month_bucket` expression and reused.
- Em-dash fallback (`"—"`) in `FeaturedIncidentOut` was getting mangled to `"?"` over the SCP transfer chain; replaced with ASCII-safe `"N/A"`.
- Type-mismatch in `frontend/src/app/dashboard/page.tsx`: `featuredIncident` state was typed as the local `Incident` shape but the backend returns the broader `FeaturedIncidentData` (includes `incident_number`, `affected_asset`, `confidence`). Type re-aligned to imported `FeaturedIncidentData`.
- `pendingActions` (existing `Action` model) mapped into the new `SuggestedAction` shape inside the dashboard page so the existing actions store keeps working unmodified.

### Removed
- Stand-alone marketing/release content files removed from the repo to keep it operational-only: `AEGIS_BRAND.md`, `AEGIS_MARKETING.md`, `AEGIS_CONTEXT.md`, `AEGIS_RELEASE_POST_v1.6.md`, `AEGIS_RELEASE_POST_v1.6.2.md`, `AEGIS_RELEASE_POST_v1.6.3.md`, `AEGIS_RELEASE_POST_v1.6.3.1.md`, `docs/seo/comparison.md`, `docs/seo/ransomware-defense.md`, `docs/seo/what-is-aegis.md`. A single consolidated `CHANGES.md` (this release) replaces them.

### Operational
- Backend `/health` now reports `version=1.6.3.3`.
- Frontend `/dashboard` route ships the new layout in place of the v1.6.3.2 widgets. Existing widgets (IncidentTimeline, ThreatDetectionChart, AssetRiskTable, GlobalThreatMap) are kept and re-arranged below the new hero so the operator's muscle memory is preserved.

---

## [1.6.3.2] - 2026-06-26 (patch)

Detection-correctness + perf-correctness + robustness patch on top of v1.6.3.1.
Driven by a 17-agent forensic audit (10 Haiku discover + 6 Sonnet verify + 1 Opus synth).
Surfaced 19 latent false positives, 14 silent Sigma rules, 16 robustness gaps, and 5 sub-second-perf opportunities.

### Added
- `path_contains_all` filter key in `correlation_engine._matches_filter()` — unlocks 14 v1.6.2/v1.6.3 supply-chain & CVE Sigma rules (Shai-Hulud, Drupal JSON:API SQLi, Schneider Saitel LFI, LiteLLM MCP, Solana FakeFix, cPanel CRLF, JCE Joomla, HTTP request smuggling, etc.) that were silently no-ops because the filter key wasn't implemented.
- `AEGIS_SAFE_IPS` and `BENIGN_UAS` now cover Twitter/X crawler ranges 199.16.156.0/22 and 192.133.77.0/24 (8 IPs unblocked, 4 incidents auto-resolved as `[FP-AUDIT]`).
- 8 composite DB indexes for hot dashboard paths: `idx_incidents_client_detected`, `idx_incidents_client_status`, `idx_incidents_source_status`, `idx_vulns_client_status`, `idx_vulns_asset_status`, `idx_assets_client`, `idx_honeypot_client`, `idx_actions_client_status`.
- `@functools.lru_cache(maxsize=8192)` on `offline_geoip.lookup()`; cache_clear() wired into the refresh job.
- `?include_analysis=true` flag on `/response/incidents` — default response no longer ships the `ai_analysis` payload (≈80% smaller default response).

### Fixed
- `dashboard/overview` parallelizes 6 COUNT() queries via `asyncio.gather()` (6.35s → 21ms; ~300× faster).
- `surface/assets` N+1 eliminated: per-asset COUNT replaced with single `GROUP BY asset_id` aggregation (101 round-trips → 2).
- `dashboard/threat-map` parallelizes honeypot + incident queries via `asyncio.gather()`.
- `response/incidents` implicit `since=` cap lowered from 10000 → 1000 (4 MB payloads were killing the dashboard).
- `ai_engine.process_alert()` no longer crashes with `AttributeError: NoneType.id` when source IP is safelisted — guarded against `_create_incident()` returning None.
- `correlation_engine._create_incident()` AI-fallback: `mitre_list[0].get('technique')` now handles both dict and string list items.
- `correlation_engine._create_incident()` AND `ai_engine._create_fast_incident()` client selection now uses `order_by(Client.created_at.asc())` for determinism (BUG-5 parity with log_watcher).
- `ip_blocker_service.block_ip()` and `unblock_ip()` now mirror to `attack_detector._blocked_ips` so out-of-band blocks (Tor auto-block, responder, playbooks, firewall_sync) take effect at the FastAPI middleware immediately instead of waiting for restart.
- `firewall_sync._sync_auto_response_events()` incident dedup is now time-bounded to 24h (was permanent — a firewall IP could only ever generate one incident in the DB's entire lifetime).
- All 4 incident-creation paths now gate on `AEGIS_SAFE_IPS` before insert: log_watcher (existing), correlation_engine, ai_engine.process_alert, ai_engine.fast_triage.

### Changed
- 15 permanently-silent Sigma rules disabled (Linux-only stack can't fire Windows/AD events): kerberos_abuse, ntlm_relay, pass_the_hash, golden_ticket, rdp_brute_force, psexec, wmi_exec, winrm, dcom, smb_enum, rdp_pivot, registry_run, scheduled_task, startup_folder, login_hook.
- `_incident_cooldown` (log_watcher) and `_fired` (correlation_engine) now have inline TTL eviction so they can't grow unbounded under sustained scan storms.
- README badge, JSON-LD, comparison table, and rule-count claims bumped to v1.6.3.2.
- `docs/seo/what-is-aegis.md`, `docs/seo/ransomware-defense.md`, `docs/seo/comparison.md` version headers bumped to v1.6.3.2.
- `AEGIS_BRAND.md` license corrected to AGPL-3.0 (was incorrectly stated as Apache-2.0).
- `CLAUDE.md` and `AEGIS_CONTEXT.md` bumped to v1.6.3.2.

### Removed (dead code)
- `backend/app/services/reporter.py` (zero imports anywhere in tree).
- `frontend/src/components/live/{AttackFeed,EventsPerSecChart,MetricsSummaryBar,NodeHeartbeatGrid,RawLogStream,Top10Table}.tsx` (zero imports).
- `ARCHITECTURE.md` (v1.2-era artifact, superseded by `CLAUDE.md` + `AEGIS_CONTEXT.md`).

### Operational
- 8 Twitter/X crawler IPs unblocked on Pi + Mac firewall.
- 13 incidents bulk-resolved with audit-trail prefixes (`[FP-AUDIT]` for Twitter, `[FP-USER-DEVICE]` for the 9 Claro DO household devices from the prior DR audit).
- The full ai_analysis remains queryable via `/response/incidents?include_analysis=true` for forensic review; default endpoint just drops the payload.

### Performance summary (measured)
| Endpoint | Before | After | Improvement |
|---|---:|---:|---:|
| `dashboard/overview` | 6.35 s | 21 ms | 300× |
| `dashboard/live-metrics` | 1.14 s | 52 ms | 22× |
| `dashboard/monitored-apps` | 2.42 s | 305 ms | 8× |
| `response/incidents/daily-counts` (new) | — | 13 ms | new endpoint |
| Full dashboard load | ~2.4 s + 4 MB | ~280 ms + 8 KB | ~9× |

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
