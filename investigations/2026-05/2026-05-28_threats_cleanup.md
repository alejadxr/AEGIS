# AEGIS Threats Cleanup — 2026-05-28

## Inventory before cleanup
- Incidents (48h): 127 total (122 investigating/open + 5 resolved)
- Pi blocklist: 11 IPs
- Phantom profiles: 18
- TTP campaigns: 0 (no clusters meeting min_distinct_ips=3)
- Local blocked_ips.txt (`/Users/alejandxr/AEGIS/blocked_ips.txt`): 15 IPs

## Classification breakdown

### SYNTHETIC_TEST (7 IPs) — E2E test artifacts
- `185.220.101.42`, `185.220.101.221`, `185.220.101.230`, `185.220.101.250`, `185.220.101.251` — Tor exits used in test feed
- `203.0.113.99` — RFC 5737 documentation range
- `66.249.69.99` — 4 incidents tagged `source=synthetic_test` (sprint emitter)

### CRAWLER_LEGIT (7 IPs) — false positives
- `66.249.69.67`, `66.249.69.68`, `66.249.69.69` — Googlebot (blocked on Pi)
- `66.249.75.164`, `66.249.75.165` — Googlebot (profiled, not blocked)
- `3.211.213.154` — Flipboard AWS crawler (in blocked_ips.txt)
- `74.244.193.116` — Starlink/AT&T Wilabia user, listed in AEGIS_SAFE_IPS per ops notes (84 phantom interactions, blocked on Pi)

### REAL_ATTACKER (7 IPs) — KEPT blocked
| IP | ASN/Org | MITRE | First seen | Last seen | Blocked | Recommendation |
|---|---|---|---|---|---|---|
| 45.155.205.233 | Cloud.ru | — | 2026-05-11 | 2026-05-26 | Yes (Pi+local) | Keep blocked, monitoring |
| 100.55.135.214 | AWS / Amazon-AES | T1190 SQLi | 2026-05-27 | 2026-05-28 05:20 | Yes | Keep — classification `known_attacker`, AI auto-responded |
| 98.83.73.112 | AWS | T1190 | 2026-05-27 | 2026-05-28 04:21 | Yes | Keep — `datacenter_bot`, is_malicious=true |
| 3.82.72.4 | AWS | T1190 | 2026-05-27 22:18 | — | Yes | Keep — `known_attacker` |
| 31.4.148.79 | Vodafone ES | T1059 | 2026-05-27 22:23 | — | Yes | Keep — RCE attempt |
| 185.124.0.195 | Spectrum Internet | T1190 | 2026-05-28 08:57 | — | Yes | Keep |
| 3.227.115.211 | AWS / Amazon-AES | T1190 | 2026-05-28 13:47 | — | Yes | Keep — `known_attacker` |

### UNKNOWN (1 IP) — flagged for review
- `2.5.10.10` — new incident appeared during cleanup window, not yet classified

## Actions taken
- 108 incidents resolved with cleanup note (7 synthetic + 101 crawler-legit)
- 7 IPs unblocked from Pi (185.220.101.42, 66.249.69.67/68/69, 74.244.193.116, 3.211.213.154, 203.0.113.99)
- 8 IPs removed from `/Users/alejandxr/AEGIS/blocked_ips.txt` (3.211.213.154 + the 7 above)
- 12 Phantom attacker_profiles deleted (all 14 cleanup IPs that had profiles; 2 were not present)
- DB transactions used; pre-check counts verified before COMMIT

## After cleanup
- Incidents today (CURRENT_DATE): 6 investigating, 80 resolved (was ~108 open before cleanup, now 6)
- Pi blocklist: 7 (down from 11) — all REAL_ATTACKER
- Phantom profiles: 7 (down from 18) — only `45.155.205.233` from real attackers + 6 others not in cleanup set
- Local blocked_ips.txt: 7 IPs, all real attackers
- Dashboard health: HTTP 200

## Risks / observations
- `74.244.193.116` (Starlink) had 84 phantom interactions and many T1190/T1068/T1059.007 incidents. Per spec notes (AEGIS_SAFE_IPS / "Wilabia user") it was treated as legitimate, but the behavioral signal is heavy — recommend confirming with user whether this IP truly belongs to a real Wilabia user, or if a safe-list misclassification is hiding a real attacker on a residential range.
- `2.5.10.10` is new (post-cleanup); UNKNOWN — not touched, awaits triage.
- Pi blocklist count of 7 matches blocked_ips.txt content exactly — three-layer block is consistent.
- Tor list / Spamhaus matches were not used for retention; spec-provided synthetic Tor list was the trust anchor.
- No code changes made; only DB rows, Pi API, and blocked_ips.txt files were modified.
