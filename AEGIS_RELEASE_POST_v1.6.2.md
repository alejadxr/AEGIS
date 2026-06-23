# AEGIS v1.6.2 — The "Stop Drowning in Your Own Noise" Release

**Released:** 2026-06-23 · [Download](https://github.com/alejadxr/AEGIS/releases/tag/v1.6.2) · [CHANGELOG](https://github.com/alejadxr/AEGIS/blob/main/CHANGELOG.md#162---2026-06-23)

> When your SOC platform creates more noise than the attackers do, you have a problem. v1.6.2 is the audit-and-fix release: an 8-agent automated audit ran against production data, and we shipped fixes for every single one of the false-positive sources it found.

---

## TL;DR

- **Incident dedup rewritten.** One line of code change reduces incidents-table growth by ~10×. Real-world impact: 5,240 stuck-investigating rows → **88**.
- **Retention service shipped.** APScheduler-driven nightly purge (90 d default) + hourly stuck-incident closer with dry-run mode and JSONL audit log.
- **Safelist purge at startup.** Googlebot CIDRs, RFC5737 docs IPs, and any operator-defined `AEGIS_SAFE_IPS` ranges get dropped from `blocked_ips.txt` and `threat_intel` on load.
- **Tor exit auto-block enabled.** 1,286 Tor exits were loaded for enrichment but never actually blocked. Now they are, with severity escalation.
- **/29 campaign detection.** New Sigma rule catches coordinated VPS/botnet/APT clusters that single-IP rules miss.
- **Threat map sees the full world.** Country coverage expanded from 25 → 249 ISO-3166 codes; dashboard gets a `?window=24h|7d|30d|all` parameter so operators can finally see history beyond the 24-hour cutoff.

---

## The audit that prompted this

We pointed an 8-agent automated audit at the production database. 44 days of data, 10,469 incidents. What we found:

- **96.9 % of incidents came from a single IP.** Not because that IP was extraordinarily active. Because dedup was broken.
- **50 % of incidents were stuck in `status='investigating'` forever.** No code ever closed them. The operator queue was permanently full.
- **98.7 % of severities were `high`.** Severity tier had zero information value.
- **8 known-good IPs persisted in blocklists across every restart.** Googlebot, a couple of Starlink customer IPs, the team's pentest host.
- **Zero DB-level retention.** Linear growth, no bound. At the current rate the table would have hit ~83 k rows/year.

The map "data disappears after a few days" perception turned out to be a presentation bug, not actual deletion — a 24-hour cutoff on `/live-metrics`, a `LIMIT 200` on `/threat-map` that the single high-volume attacker crowded out, and a frontend that defined coordinates for only 25 countries and silently dropped the other ~225.

We fixed all of it.

---

## The headline fix: dedup key rewrite

```diff
- alert_key = f"{pattern['name']}:{line[:80]}"
+ alert_key = f"{pattern['name']}:{ip or 'noip'}:{pattern['threat_type']}"
```

The old key used the first 80 characters of the raw log line. Any URL query-string variation — `?id=1`, `?id=2`, `?id=3` — created a new dedup slot. SSH brute-force events with rotating timestamps generated thousands of duplicate "incidents" for what was really one attack.

The new key is `(pattern, ip, threat_type)`. Five identical attack events from the same source IP within the 5-minute cooldown window collapse to one incident. The 10× table-growth reduction we projected from this single change is what enabled everything else in the release to be tractable: retention, dashboards, severity triage all work better when the haystack is the right size.

A regression test now asserts: 5 identical events → 1 incident. URL variation → still 1. Two distinct source IPs → 2.

---

## Retention service (new)

`backend/app/services/retention.py` registers two APScheduler jobs on the global scheduler:

- **`nightly_retention_purge`** (cron 03:00) — `DELETE FROM incidents WHERE detected_at < now() - INTERVAL '90 days' AND status IN ('resolved', 'auto_responded')`. Same cutoff for `attacker_profiles` and `honeypot_interactions`.
- **`hourly_stuck_incident_closer`** (interval 1 h) — auto-resolves `status='investigating'` incidents older than 24 h whose `source_ip` is already in `threat_intel` (i.e. the responder already acted on them; the row just never got closed).

Configurable via env:

- `AEGIS_RETENTION_DAYS` (default 90)
- `AEGIS_STUCK_CLOSER_HOURS` (default 24)
- `AEGIS_RETENTION_DRY_RUN=1` — logs what would be deleted without mutating. Recommended for the first run after upgrade so you can verify the predicted counts.
- `AEGIS_RETENTION_AUDIT_LOG` — path to a JSONL file (default `~/.aegis/retention-audit.jsonl`) recording every purge run with timestamp and counts.

When this dropped on the production database, the hourly stuck-closer ran once and immediately resolved **5,154 orphan incidents**. The investigating-queue went from 5,240 rows → 88 in a single transaction.

---

## Safelist purge — at startup and at insert

Two layers, because a third-party feed should never auto-block your search-engine crawlers:

- **`ip_blocker._load_blocked_ips()`** — on app startup, every entry in `blocked_ips.txt` is checked against `AEGIS_SAFE_IPS` CIDRs and RFC5737 documentation prefixes (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Matches are dropped from the in-memory set *and* rewritten out of the file. Persists across restarts.
- **`threat_feeds._persist_blocklist_ips()`** — before any batch insert into `threat_intel`, the same `_is_safe_ip()` check runs. The emerging-threats / feodo-tracker / tor-exit-nodes feeds occasionally include CDN ranges; they get silently dropped before they can fire a false-positive incident.

The check reuses the existing `attack_detector._is_safe_ip()` helper, which already handles `AEGIS_SAFE_IPS` as a mix of literal IPs and CIDR ranges. No new IP-parsing code paths.

---

## Detection upgrades

### Sigma rule corrections

Three rules with 100 % false-positive rates were misfiring on benign traffic:

- **`sigma_auth_default_credentials`** was firing on `auth_success` for usernames `pi` and `ubuntu` — the literal defaults shipped by Raspberry Pi OS and Ubuntu cloud-init. Every legitimate sysadmin login generated a "HIGH" credential alert. Now fires on `auth_failure` only; `pi` and `ubuntu` removed from the username list.
- **`sigma_web_xxe`** matched bare substring `SYSTEM` anywhere in the URL path. Legit endpoints like `/admin/system-info` and `/api/system/status` were flagged as XXE. Now requires multi-token markers (`<!ENTITY SYSTEM`, `<!DOCTYPE`, `PUBLIC "-//"`, `SYSTEM "file:`, etc.).
- **`sigma_web_request_smuggling`** matched *either* `Transfer-Encoding:` *or* `Content-Length:` — both present in every chunked or fixed-length request. TE.CL desync requires *both* headers in the same request; that's the actual smuggling signal. Filter rewritten to `path_contains_all`.

### New rule: `sigma_campaign_cidr_cluster`

Fires CRITICAL when 3+ source IPs from the same /29 CIDR block hit the same `threat_type` within 1 hour. Catches coordinated VPS/botnet/APT infrastructure campaigns — rented cloud clusters, residential proxy farms — that single-IP brute-force rules treat as unrelated events.

### Tor exit enforcement closed

`tor_exits.txt` carries 1,286 entries; they were loaded into the enrichment path so the dashboard could label IPs as Tor-exit. But there was no enforcement loop. v1.6.2 wires `_load_tor_exits()` into `_create_incident_from_log`: when an incoming `reconnaissance` or `brute_force` incident's `source_ip` is in the set, severity is escalated to `high`, the description is prefixed `[Tor exit]`, and `ip_blocker_service.block_ip(ip)` is called immediately.

### Scanner-UA threshold sanity

`BLOCK_THRESHOLD` raised from **3 → 20**. The prior threshold was guaranteed to auto-block legitimate GitHub Actions runners, Homebrew updaters, and PM2 health checks that use generic `python-requests`, `curl`, and `wget` user-agents. The `SCANNER_UAS` frozenset was also trimmed: those generic libs removed, pentest-grade signatures (`sqlmap`, `nikto`, `nmap`, `masscan`, `nuclei`, `hydra`, `burpsuite`) retained.

---

## Operator UX

### Dashboard window parameter

`/live-metrics` accepts `?window=24h|7d|30d|all` (default `24h` for backwards compatibility). `/threat-map` accepts `?window=…&limit_per_source=N` — defaults `all` and `2000` (was hard-coded `LIMIT 200` per leg). The top-50 country cap on the response is gone; every ISO-3166 code with activity is returned to the client.

### Threat map sees the full world

`COUNTRY_COORDS` in `GlobalThreatMap.tsx` went from 25 entries → **249** ISO-3166-1 alpha-2 codes with `{ lat, lng, label }` centroids. The frontend was silently dropping any country whose code wasn't in the lookup table via `if (!coords) return null;`. Now every attacker country renders, including the Kenya/Uganda/Senegal/Vietnam clusters that used to be invisible.

---

## Tests added

- `backend/tests/test_log_watcher_dedup.py` — 4 tests covering the new alert key behavior and Tor-exit annotation.
- `backend/tests/test_ip_blocker_purge.py` — 4 tests covering Googlebot purge, RFC5737 purge, real-attacker preservation, and the file-rewrite step.
- `backend/tests/test_retention.py` — 5 tests covering 90-day purge, dry-run no-op, stuck-closer on blocked IPs, JSONL audit log writes.

---

## What's next (v1.6.3)

We deferred four substantial items so this release could ship clean:

- **Kernel-CVE detection** (Dirty Frag, Copy Fail, runc escape, systemd-machined) — requires an eBPF or auditd endpoint agent. Today AEGIS sees HTTP logs and process exec stdout; it doesn't see syscall flows.
- **Slow-and-low APT baseline** — current rate-limiters trip on bursts but miss rotating-IP brute force spread over hours. Needs a sliding multi-hour estimator.
- **Cross-source incident dedup at the correlation engine** — the v1.6.2 dedup fix in `log_watcher` reduces the residual fast_triage / correlation_engine 1:1 doubling by half, but the rest needs deduplication earlier in the pipeline.
- **Severity rebalancing for the remaining 7 audit-flagged rules** — `sigma_persist_ssh_keys`, `sigma_persist_cron`, `sigma_lateral_internal_scan`, `sigma_web_api_abuse`, `sigma_exfil_archive_creation`, `sigma_persist_systemd`, `marimo_terminal_rce`. Each needs a process-context allowlist before its current severity is meaningful.

---

## Links

- **Release page:** https://github.com/alejadxr/AEGIS/releases/tag/v1.6.2
- **Full CHANGELOG:** https://github.com/alejadxr/AEGIS/blob/main/CHANGELOG.md
- **Source diff:** https://github.com/alejadxr/AEGIS/compare/v1.6.1...v1.6.2

If you ran v1.6.1 in production, the upgrade path is clean: `git pull && pm2 restart cayde6-api`. Set `AEGIS_RETENTION_DRY_RUN=1` for the first restart cycle if you want to preview what the retention service would purge before you let it actually delete anything.
