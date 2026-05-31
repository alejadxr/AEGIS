# AEGIS Threats Audit — 2026-05-31 (last 72h)

**Auditor:** Automated investigation agent  
**Period:** 2026-05-29 00:00 UTC — 2026-05-31 18:00 UTC  
**Database:** cayde6 (PostgreSQL, Mac Pro localhost:5432)

---

## Numbers

- **Incidents (72h window):** 1,399 total rows; 25 unique source IPs
- **Pi blocklist (before cleanup):** 26 IPs
- **Pi blocklist (after cleanup):** 11 IPs
- **Unique IPs in 72h incident table:** 25
- **False positives removed from Pi:** 15 IPs

---

## Classification Breakdown

### REAL_ATTACKER — 9 IPs (retained on Pi/blocked)

| IP | ASN | Country | Notes |
|----|-----|---------|-------|
| `148.0.72.76` | AS6400 Claro Dominican Republic | DO | 1,359 incidents in 72h, brute-force + SQL injection |
| `185.220.101.252` | AS60729 Stiftung Erneuerbare Freiheit | DE | Tor exit node `berlin01.tor-exit.artikel10.org` |
| `142.204.171.108` | AS393238 ImOn Communications | US | Iowa residential ISP, SQLi attempts |
| `152.166.147.81` | AS28118 Altice Dominicana | DO | Auth brute-force attempts |
| `31.4.148.79` | AS12430 Vodafone Spain | ES | Vodafone Spain, SQLi (older than 72h but retained) |
| `185.124.0.195` | AS48294 Spectrum Internet Ltd | GB | British ISP, historical incident |
| `45.155.205.233` | AS208677 Cloud Technologies (Cloud.ru) | RU | Russian cloud provider (oldest block: 2026-05-11) |
| `2.5.10.4` | AS3215 Orange France | FR | Public routable IP, SQLi targeting /api/og |
| `2.5.10.10` | AS3215 Orange France | FR | Public routable IP, SQLi targeting /api/og |

> Note: `2.5.10.x` superficially resembles RFC5737 documentation IPs (192.0.2.x, 198.51.100.x, 203.0.113.x) but they are NOT documentation ranges. These are live Orange France AS3215 public IPs with no reverse DNS. Treated as REAL_ATTACKER; retaining block.

### SYNTHETIC_TEST — 0 IPs

No RFC5737 or known synthetic-test ranges found in 72h data.

### CRAWLER_LEGIT — 14 IPs (unblocked from Pi, incidents resolved)

All triggered false positives via the `/api/og` endpoint SQL injection pattern (see Root Cause below).

| IP | Identity | ASN | MITRE |
|----|----------|-----|-------|
| `66.249.69.66` | Googlebot | AS15169 Google | T1190 (false positive) |
| `66.249.69.67` | Googlebot | AS15169 Google | T1190, T1036 (false positive) |
| `66.249.69.68` | Googlebot | AS15169 Google | T1190 (false positive) |
| `66.249.69.69` | Googlebot | AS15169 Google | T1083, T1190 (false positive) |
| `3.211.213.154` | Flipboard (AWS) | AS14618 Amazon | T1190 (false positive) |
| `100.29.31.150` | Flipboard proxy | AS14618 Amazon (proxy.flipboard.com) | T1190 (false positive) |
| `98.83.73.112` | Flipboard proxy | AS14618 Amazon (proxy.flipboard.com) | T1059.001, T1190 (false positive) |
| `98.83.92.111` | Flipboard proxy | AS14618 Amazon (proxy.flipboard.com) | T1190 (false positive) |
| `100.55.135.214` | Flipboard proxy | AS14618 Amazon | T1190 (false positive) |
| `54.234.74.14` | AWS crawler | AS14618 Amazon | T1059.001, T1190 (false positive) |
| `44.245.236.161` | AWS scanner/bot | AS16509 Amazon | T1190 (false positive) |
| `52.1.208.2` | AWS crawler | AS14618 Amazon | T1190 (false positive) |
| `52.72.61.119` | AWS crawler | AS14618 Amazon | T1190 (false positive) |
| `44.198.88.55` | AWS crawler | AS14618 Amazon | T1190 (false positive) |

> Note: `199.16.157.182` (Twitter AS13414) appears in the 72h incident table (source: `T1059`) but was NOT on the Pi blocklist. Left as-is — only 1 incident, status checked separately.

### USER_OWN_IP — 1 IP (unblocked from Pi, incident resolved)

| IP | Identity | Range |
|----|----------|-------|
| `74.244.193.220` | User's Starlink (Sable testing) | `74.244.193.0/24` in `AEGIS_SAFE_IPS` |

### UNKNOWN — 1 IP (flagged for human review)

| IP | ASN | Notes |
|----|-----|-------|
| `3.82.72.4` | AS14618 Amazon | Single SQLi incident 2026-05-29; not a known Flipboard reverse-DNS hostname. May be AWS scanner. Still on Pi blocklist — keep until further review. |

---

## Safe-List Bypass Root Cause

### Three-Layer Bug

The safe-list bypass that allowed Googlebot (`66.249.0.0/16`) and Starlink (`74.244.193.0/24`) to be blocked despite being in `AEGIS_SAFE_IPS` is caused by a gap between **where AEGIS_SAFE_IPS is enforced** and **where the block action originates**.

**Layer 1 — Where safe IPs ARE checked correctly:**
- `attack_detector._is_safe_ip()` — middleware blocks immediate 403 and refuses to call `_block_ip()` for safe IPs. CIDR parsing works correctly.
- `guardrails.evaluate_action()` — safe-IP guard runs before policy evaluation.
- `responder._block_ip()` — defense-in-depth check also calls `_is_safe_ip()`.

**Layer 2 — Where the bypass occurs (root cause):**
The `log_watcher._process_line()` method (line 591-604) runs the PATTERNS regex loop and calls `_create_incident_from_log()` **without first checking `attack_detector._is_safe_ip()`**. It uses its own `_is_private_ip()` which only checks RFC1918 + Tailscale CGNAT — it does NOT read `AEGIS_SAFE_IPS` env var or the `_SAFE_NETWORKS` list that includes `66.249.0.0/16` and `74.244.193.0/24`.

The Sable `/api/og?title=<url-encoded-article-title>` endpoint logs article titles from social media crawlers. Article titles from security blogs (e.g., "CVE-2026-42945 — Heap Overflow via SQL…") contain words like `SQL` followed by `--` separators in URL-encoded form (`%27`), which trigger the `sql_injection` regex pattern. Googlebot and Flipboard crawl these Sable research pages routinely, causing incidents to be created.

**Layer 3 — How incidents become blocks on Pi (the propagation path):**
Once an incident is created in the DB from log_watcher, the `ai_engine` triage loop picks it up, scores it HIGH/CRITICAL, and proposes a `block_ip` action. The guardrails engine calls `_is_safe_ip()` — and this correctly catches literal IPs in `SAFE_IPS` — BUT the CIDR check uses `attack_detector._is_safe_ip()` which IS correctly configured. However, the playbook engine (`playbook_engine.py`) contains a separate auto-block path for brute-force playbooks that calls `firewall_client.block_ip()` **directly** without going through `guardrails.evaluate_action()`. This path does call `ip_blocker_service.block_ip()` but the `AEGIS_FIREWALL_URL` forward to the Pi bypasses the safe-IP check in `attack_detector._block_ip()`.

**Additionally:** The Pi firewall agent's own `_is_safe_ip()` only has RFC1918 + Tailscale CGNAT hardcoded in `_SAFE_NETWORKS`. It does NOT read `AEGIS_SAFE_IPS` from environment or accept dynamic safe-list configuration. The Pi's safe-list has no knowledge of `66.249.0.0/16` or `74.244.193.0/24`, so it accepts and enforces any block request AEGIS sends for those IPs.

**Summary — bypass path:**
```
Googlebot hits /api/og?title=...SQL...CVE...
  → Sable logs the request
  → log_watcher tails Sable PM2 log
  → log_watcher._process_line() matches sql_injection pattern
  → _is_private_ip(66.249.69.x) returns False (public IP, correct)
  → _create_incident_from_log() called — NO AEGIS_SAFE_IPS check here
  → playbook_engine auto-blocks via AEGIS_FIREWALL_URL
  → Pi accepts block (Pi has no CIDR safe-list for 66.249.0.0/16)
  → IP blocked on Pi iptables despite being in AEGIS_SAFE_IPS
```

---

## Cleanup Actions Taken

- **Unblocked 15 IPs from Pi** via `DELETE http://100.93.30.20:8765/block/<ip>`
  - 4x Googlebot (66.249.69.66–69)
  - 10x Flipboard/Amazon proxies
  - 1x User Starlink (74.244.193.220)
- **Resolved 33 open/investigating incidents** in DB for false-positive IPs
  - 10 Googlebot incidents resolved
  - 1 Starlink incident resolved
  - 22 Flipboard/Amazon incidents resolved

---

## Real Attackers Retained (table)

| IP | ASN | Country | MITRE | First | Last | Action |
|----|-----|---------|-------|-------|------|--------|
| `148.0.72.76` | AS6400 Claro | DO | T1110, T1110.001 | 2026-05-30 19:15 | 2026-05-31 16:33 | Keep blocked (1,359 incidents, active) |
| `185.220.101.252` | AS60729 | DE | — | 2026-05-28 14:35 | 2026-05-28 14:35 | Keep blocked (Tor exit node) |
| `142.204.171.108` | AS393238 | US | T1190 | 2026-05-29 00:37 | 2026-05-29 00:50 | Keep blocked |
| `152.166.147.81` | AS28118 Altice DO | DO | T1110 | 2026-05-30 15:49 | 2026-05-30 15:49 | Keep blocked |
| `2.5.10.4` | AS3215 Orange FR | FR | T1190 | 2026-05-30 13:27 | 2026-05-30 13:27 | Keep blocked (public IP) |
| `2.5.10.10` | AS3215 Orange FR | FR | T1190 | 2026-05-28 14:04 | 2026-05-28 14:04 | Keep blocked (public IP) |
| `3.82.72.4` | AS14618 Amazon | US | T1190 | 2026-05-29 12:47 | 2026-05-29 12:47 | Keep on Pi, flag for review (UNKNOWN) |

> Note: `31.4.148.79`, `185.124.0.195`, `45.155.205.233` are on Pi from earlier sessions (before 72h window). Not touched per constraint (DO NOT cleanup IPs not conclusively classified in this window).

---

## Risks / Next Steps

### Bug Fix Required (Priority: HIGH)

**BUG-1: `log_watcher._process_line()` does not check `AEGIS_SAFE_IPS` CIDRs**

File: `backend/app/services/log_watcher.py`  
Line ~525 has: `if ip and (ip in INTERNAL_IPS or _is_private_ip(ip)): return`  
But `_is_private_ip()` only knows RFC1918 + Tailscale. Fix: also call `attack_detector._is_safe_ip(ip)` here, or extend `_is_private_ip()` to read `AEGIS_SAFE_IPS` CIDR ranges.

**BUG-2: Pi firewall agent `_SAFE_NETWORKS` does not include `AEGIS_SAFE_IPS` CIDRs**

File: `pi-deploy/aegis-firewall/main.py` (on Pi at `~/aegis-firewall/main.py`)  
The Pi has no mechanism to learn the Mac Pro's `AEGIS_SAFE_IPS`. An AEGIS block request to the Pi for any public IP (even one in AEGIS_SAFE_IPS) will be accepted and enforced. Fix: either pass `AEGIS_SAFE_IPS` to the Pi agent via env var and use it in `_is_safe_ip()`, OR have the Mac Pro AEGIS validate all block requests against `_is_safe_ip()` before forwarding to the Pi via `firewall_client`.

**BUG-3: Sable `/api/og` generates false-positive SQLi signals**

The `/api/og?title=` endpoint URL-decodes article titles containing terms like "SQL injection", "CVE", "heap overflow" — these legitimately trigger the `sql_injection` regex pattern. Consider:
- Excluding the `/api/og` path from log_watcher pattern matching (it's a known safe OG-image endpoint)
- Or whitelisting the Googlebot/Flipboard user-agent strings in log_watcher

**BUG-4: `playbook_engine` auto-block path bypasses guardrails safe-IP check**

The brute-force playbook auto-blocks directly via `ip_blocker_service` + `AEGIS_FIREWALL_URL` forward without going through `guardrails.evaluate_action()`. This means the safe-IP CIDR check in `guardrails.py` line 64 is never reached for playbook-originated blocks. Trace: `playbook_engine → ip_blocker_service.block_ip() + firewall_client.block_ip()` — neither path calls `attack_detector._is_safe_ip()` for CIDR ranges when AEGIS_FIREWALL_URL is set.
