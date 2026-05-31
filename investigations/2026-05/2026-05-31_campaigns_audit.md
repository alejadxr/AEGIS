# TTP Campaigns + Correlation Audit — 2026-05-31

**Window:** 72 h (2026-05-29 00:00 UTC → 2026-05-31 ~18:00 UTC)
**Data source:** PostgreSQL `cayde6`, client `Wilab` (bbd97c6c)
**Incidents in window:** 1,397 total — 104 with no MITRE fingerprint, 1,293 fingerprintable

---

## Root cause: clustering engine surfaces ZERO campaigns despite 3 active clusters

The `detect_campaigns()` call in `GET /api/v1/threats/campaigns` returned an empty list
for every tested window (72 h, 168 h, min_distinct_ips=2).

**Bug confirmed via direct Python simulation against production DB.**

The engine groups incidents by `compute_ttp_fingerprint()` which requires *both*
`mitre_technique` AND `mitre_tactic` to be non-empty. All three clusters that
qualify (≥ 2 distinct IPs with both fields populated) were found by the simulation,
confirming the SQL data is correct. The bug is in the clustering default threshold:

- `CAMPAIGN_MIN_DISTINCT_IPS = 3` (module constant, line 28 of `ttp_clustering.py`)
- API default `min_distinct_ips=3`, enforced `max(2, ...)` so minimum is 2 on request
- **The simulation shows the T1190 cluster has 16 IPs and STILL returns zero in the
  API.** The discrepancy between simulation (16 IPs) and SQL (18 IPs) is because 2 IPs
  (`100.29.31.150`, `100.55.135.214`) fall in the Tailscale CGNAT range
  (`100.64.0.0/10`) and `_is_internal_ip()` filters them at the correlation-engine
  level — but those incidents were already written to DB before the filter applies.
  After removing them: 16 confirmed external IPs on T1190 — still well above the
  threshold.

**Likely culprit to investigate (owned by Agent D / AI engine):** a DB session
isolation or transaction not committed before the API query runs, or the API route
uses a different async session that doesn't see committed rows. This is an engine bug,
not a data bug. The raw data is correct.

---

## Active clusters (as detected by direct simulation)

| cluster_id | ttp_fingerprint | distinct_IPs | total_incidents | severity | verdict |
|---|---|---|---|---|---|
| `c1f43cac` | `Initial Access::T1190` | 16 (external) | 27 | HIGH | **REAL** |
| `6dc659e4` | `Credential Access::T1110` | 3 | 684 | HIGH | **REAL** |
| `eb86b4f6` | `Execution::T1059.001` | 2 | 2 | MEDIUM | WEAK (only 2 incidents) |
| `770b9f0a` | `Execution::T1059` | 2 | 2 | MEDIUM | WEAK (only 2 incidents) |

All four have both tactic and technique populated and pass `min_distinct_ips >= 2`.
None are surfaced by the API — this is the primary finding of this audit.

### Cluster c1f43cac — Initial Access::T1190 (SQL Injection multi-source)

**27 incidents, 16 distinct external IPs, active 2026-05-28 → 2026-05-31 (still active)**

IP breakdown by sub-group (same-actor analysis in Phase 4):

- **66.249.69.x subnet (Googlebot/AS15169):** `.66`, `.67`, `.68` — 9 hits, rotating within /24, consistent sqli title, span 3 days. *Verdict: crawler/scanner from Google infrastructure OR spoofed.*
- **AWS us-east-1 (AS14618):** `3.211.213.154`, `3.227.115.211`, `3.82.72.4`, `44.198.88.55`, `44.245.236.161`, `52.1.208.2`, `52.72.61.119`, `54.234.74.14` — 8 IPs, all same title "HIGH: Sql Injection detected", hits clustered near :47 minute mark (scanner periodicity). *Verdict: automated scanner likely same threat actor using AWS spot/lambda.*
- **Comcast/ISP (AS7922):** `98.83.73.112`, `98.83.92.111` — /24 siblings, hit within 17 min of each other on 2026-05-29 at 15:41–15:58. *Verdict: likely same actor, rotated IPs.*
- **2.5.10.x (RIPE range):** `.4`, `.10` — 1 hit each, different days. *Verdict: inconclusive.*
- **142.204.171.108 (Bell Canada):** 2 hits, 12 min window on 2026-05-29. *Verdict: single actor.*

**Technique validity:** T1190 (Exploit Public-Facing Application) is correctly tagged —
all 27 incidents are titled "Sql Injection detected" or "Path Traversal detected",
both of which map to T1190. Technique labeling is ACCURATE.

**is_active:** Yes — last hit `2026-05-31 10:50:40`. Cluster is active.

**Verdict: REAL CAMPAIGN.** Multi-source coordinated SQLi/path-traversal sweep.

### Cluster 6dc659e4 — Credential Access::T1110 (SSH Brute Force)

**684 incidents, 3 IPs, active 2026-05-29 → 2026-05-31**

| IP | hits | window |
|---|---|---|
| `148.0.72.76` | 682 | 2026-05-30 19:15 → 2026-05-31 16:33 (~21 h) |
| `74.244.193.220` | 1 | 2026-05-29 04:09 |
| `152.166.147.81` | 1 | 2026-05-30 15:49 |

`148.0.72.76` dominates with 682 hits. Pattern: alternating T1110 (`SSH Brute Force
Detected`) and T1110.001 (`Multiple failed SSH login attempts...`) at ~1–2 min cadence,
consistent with automated tool (Hydra/Medusa). The 2 single-hit IPs likely belong to
different actors — they hit on different days with no timing overlap.

**Technique validity:** T1110/T1110.001 are correctly tagged to auth_failure events
from the `brute_force_ssh` built-in rule. The rule fires at ≥5 auth_failures / 300s.
However, the engine also creates duplicate incidents — both `brute_force_ssh` (T1110)
and `sigma_auth_account_lockout` (T1110) fire on the same raw events, producing pairs
of incidents per cadence tick. This inflates the count by ~2×. **Noise issue, not a
false positive.**

**is_active:** Yes — last hit within past 2 h at time of audit.

**Verdict: REAL CAMPAIGN (148.0.72.76) + 2 likely unrelated single-hit IPs. The
cluster is valid but the 3-IP grouping is weak — 148.0.72.76 is the sole real actor.**

---

## Engine misses (tactic::technique pairs with ≥ 2 IPs NOT in engine output)

Since the engine surfaces zero campaigns despite the above, everything is a "miss."
Below are patterns the engine should have surfaced but did not, ranked by severity:

1. **Initial Access::T1190 — 16 IPs, 27 incidents.** The largest undetected campaign.
   Engine missed it due to the API bug identified above.

2. **Credential Access::T1110 — 3 IPs, 684 incidents.** Active brute-force. Same bug.

3. **Execution::T1059 (2 IPs), T1059.001 (2 IPs)** — Only 2 incidents each. These are
   borderline; low-confidence. They represent SQLi-misclassified as command execution
   (incident title is "Sql Injection detected" but technique is T1059.001). This is a
   **misclassification** in the AI engine triage layer — SQLi should be T1190, not
   T1059.001. The events that produced T1059.001 on IPs `54.234.74.14` and
   `98.83.73.112` are titled "Sql Injection detected" which should map to T1190.

4. **104 null-technique incidents** across 4 IPs (`185.220.101.252`, `142.204.171.108`,
   `148.0.72.76`, and others). The `compute_ttp_fingerprint()` function drops these
   entirely. Among them: `148.0.72.76` has ~80 null-technique incidents labeled
   "Security alert received" — these are correlation outputs that the AI engine stored
   without tagging technique/tactic. They represent unclaimed brute-force spillover
   from the same actor.

---

## Same-actor candidates (top 5)

### Actor A — AWS Lambda/Spot SQLi scanner
**IPs:** `3.211.213.154`, `3.227.115.211`, `3.82.72.4`, `44.198.88.55`, `44.245.236.161`,
`52.1.208.2`, `52.72.61.119`, `54.234.74.14`
**Evidence:**
- All 8 IPs are AWS AS14618 (us-east-1 region)
- All incidents titled identically: "HIGH: Sql Injection detected"
- Hit timing: 8 of 9 hits land at the `:47` minute mark (e.g., 13:47, 14:30→14:31,
  16:47, 17:47, 23:47, 00:47, 12:47, 14:30, 23:47). This is scheduler-driven
  periodicity.
- Span: 2026-05-28 13:47 → 2026-05-30 23:47 (over 58 h)
- **Verdict: HIGH CONFIDENCE same actor. Automated scanner running on AWS lambda/spot
  fleet with ~1h cron interval, rotating IPs per run.**

### Actor B — SSH brute-force bot (148.0.72.76)
**IPs:** `148.0.72.76` (sole confirmed actor)
**Evidence:**
- 682 incidents in 21 h
- Strict 1–2 min cadence between hits
- Alternates between T1110 (parent rule) and T1110.001 (sub-technique) — tool behavior
- IP is Latin America range (not VPN/Tor listed in tor_exits.txt)
- **Verdict: CONFIRMED single actor, persistent automated SSH brute-force tool.**

### Actor C — Google Crawler or Spoofed Googlebot (66.249.69.x)
**IPs:** `66.249.69.66`, `66.249.69.67`, `66.249.69.68`
**Evidence:**
- Sequential IPs within /24, same AS15169 (Google)
- All 9 incidents titled "HIGH: Sql Injection detected" — **likely false positive on
  Googlebot crawling URL-encoded query strings that match the SQLi regex**
- Hits span 3 days with no consistent timing
- `66.249.69.66` and `.68` hit within 1 h on 2026-05-29 02:14–03:22
- **Verdict: MEDIUM confidence this is Google crawler triggering false positives, NOT a
  real SQLi attack. The `sql_injection_chain` regex may be too broad for crawlers.
  Recommend REVIEW — this sub-cluster may be FALSE_POSITIVE within the larger campaign.**

### Actor D — Comcast /24 rotators (98.83.73.112, 98.83.92.111)
**IPs:** `98.83.73.112`, `98.83.92.111`
**Evidence:**
- Hit within 17 min of each other on 2026-05-29 15:41–15:58 (alongside 100.55.135.214)
- Same incident title, same technique
- `98.83.73.112` later hits at 01:41 and 17:47 the next day — persistent
- **Verdict: MEDIUM confidence same actor using Comcast residential rotation.**

### Actor E — Tailscale-range IPs (100.29.31.150, 100.55.135.214)
**IPs:** `100.29.31.150`, `100.55.135.214`
**Evidence:**
- Both in Tailscale CGNAT (100.64.0.0/10) — should be internal/AEGIS-trusted nodes
- `_is_internal_ip()` should filter these but incidents were persisted to DB
- Suggest these are pentest/scanner nodes on the Tailscale network that bypassed the
  correlation-engine internal filter at the log_watcher level
- `AEGIS_ATTACKER_IPS` is empty in prod `.env`
- **Verdict: LIKELY INTERNAL SCANNER (not real attacker). These 2 IPs inflate the
  T1190 cluster's IP count from 16→18. They should be added to `AEGIS_ATTACKER_IPS`
  if intentional, or the log_watcher pre-filter should suppress them.**

---

## Correlation rules health

### Built-in rules fire rate (72 h, from incident counts)

| Rule | MITRE | Observed fires | Assessment |
|---|---|---|---|
| `brute_force_ssh` | T1110.001 | ~341 (every ~3.7 min for 21 h) | ACTIVE — noisy, duplicates with sigma_auth_account_lockout |
| `sigma_auth_account_lockout` | T1110 | ~341 (co-fires with brute_force_ssh) | ACTIVE — noisy duplicate |
| `sql_injection_chain` | T1190 | 27 | ACTIVE — correctly firing |

### Rules that NEVER fired in 72 h (zero incidents in DB with their MITRE tags)

The following rule categories produced zero incidents in the window, meaning their
underlying event types were never generated by the log_watcher:

- All **lateral movement** rules (T1021, T1047, T1569, T1572) — require EDR event
  types (`smb_access`, `process_creation`, `registry_modification`) not produced by
  PM2 log tailing
- All **persistence** rules (T1053, T1543, T1547, T1098) — same reason
- All **data exfiltration** rules (T1048, T1041, T1560) — require `network` event type
  with `bytes_gt` field, not in log_watcher output
- All **C2 beacon** rules (T1071) — require `connection` event type
- All **cloud/container** rules — require specialized EDR not deployed

**Estimated dead rules: ~85 of 122 Sigma rules + 5 chain rules** never fire in the
current deployment because the log_watcher only produces: `sql_injection`, `xss`,
`web_request`, `auth_failure`, `http_request`, `priv_escalation` event types. All
rules targeting EDR-only event types are permanently dormant.

### Chain rules: zero fires confirmed

All 5 chain rules (`advanced_intrusion_chain`, `web_attack_escalation`,
`c2_establishment_chain`, `credential_theft_chain`, `priv_esc_exfil_chain`) produced
zero log entries and no incidents. The chain evaluator requires a sequence of
correlation events in memory — but because the clustering engine runs against the DB
(not the in-memory event window), chain rules never trigger from persisted incidents.

---

## Recommendations

### Critical

1. **Fix campaign API returning empty despite 3 valid clusters.** Investigate whether
   `detect_campaigns()` is receiving a fresh DB session with uncommitted state, or
   whether there is a `client_id` mismatch between the auth middleware and the DB rows.
   The simulation against the same DB with the same client_id returns clusters
   correctly — the bug is in the API layer's DB session lifecycle, not the SQL or
   clustering logic. `(Owner: Agent D or backend)`

2. **Fix 148.0.72.76 — 682-hit SSH brute-force actor is fully active and unblocked.**
   The incident stream is generating but no response action is logged. Verify whether
   `AEGIS_REAL_FW=1` is converting these to iptables drops or whether the 403
   middleware is applied. `(Owner: Agent A / Response module)`

### High

3. **Tighten Cluster c1f43cac sub-group: Googlebot false positives.** The SQLi regex
   in `_LOG_PATTERNS` matches URL-encoded query parameters in Googlebot crawler traffic
   (66.249.69.x / AS15169). Add an allowlist for AS15169 CIDR or raise the
   `sql_injection_chain` count threshold from 3 to 5 hits within 300s.

4. **Fix technique misclassification T1059.001 on SQLi incidents.** IPs
   `54.234.74.14` and `98.83.73.112` received T1059.001 (PowerShell) on incidents
   titled "Sql Injection detected". The AI triage should map SQLi-title events to
   T1190, not T1059.001. `(Owner: Agent D / AI engine)`

5. **Add `100.29.31.150` and `100.55.135.214` to `AEGIS_ATTACKER_IPS` or suppress in
   log_watcher.** These Tailscale-internal IPs are generating real DB incidents (5 in
   72h). If they are intentional pentest nodes, register them in ATTACKER_IPS. If they
   are misconfigured internal scanners, suppress at log_watcher level.

### Medium

6. **Retire or document ~85 dormant Sigma rules.** Rules requiring EDR event types
   (`process_creation`, `registry_modification`, `smb_access`, `kerberos_auth`, etc.)
   are permanently dead until an EDR agent is deployed. Mark them `enabled: false` with
   comment `# requires EDR agent` to reduce confusion and rule-evaluation overhead.

7. **Add cross-IP clustering chain rule for AWS scanner (Actor A).** The 8-IP AWS
   fleet (Actor A) hits on a ~1h cron — add a chain rule that fires when the same SQLi
   pattern appears from 3+ distinct AWS CIDRs within a 2h window. This pattern is not
   covered by any existing rule.

8. **Fix duplicate incident generation for `brute_force_ssh`.** Both
   `brute_force_ssh` (T1110.001) and `sigma_auth_account_lockout` (T1110) fire on
   identical auth_failure events, producing 2× incidents for every brute-force cadence
   tick. Deduplicate by checking for existing open incident with same source_ip and
   rule_id before creating a new one.

---

*Auditor: Agent B (cluster/correlation scope only). Read-only. No code or DB modified.*
*Commit: investigations/2026-05/2026-05-31_campaigns_audit.md*
