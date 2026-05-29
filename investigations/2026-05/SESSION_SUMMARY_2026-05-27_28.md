# AEGIS — Session Summary (2026-05-27 → 2026-05-28)

Two intensive engineering days. 24 commits pushed to `main`. Production
healthy on Mac Pro: `api=200`, `frontend=200`, all 18 dashboard routes
serving, new endpoints live.

---

## What shipped

### IP Intelligence subsystem (v1 → v2 → v2.5)

| Layer | Capability |
|---|---|
| **Providers (10)** | ipinfo · ip.guide · ipquery · ipapi.is · proxycheck.io · ip-api · GeoJS · GreyNoise · Shodan InternetDB · IPInfo Lite (opt) · OTX (opt) · VirusTotal (opt) · AbuseIPDB (opt) |
| **Ground truth** | Tor exit list (local cache) · Spamhaus DROP (1,613 CIDRs) · Emerging Threats (538 IOCs) · db-ip ASN (469k ranges, 28 MB binary-search) |
| **Inference** | Multi-source consensus risk (0-100) · classification (tor_exit / vpn_user / known_crawler / datacenter_bot / known_service / known_attacker) · confidence scoring (tor/vpn/proxy/datacenter/attacker 0-1) · behavioral fingerprint (session hash across exits) |
| **Internal context** | Incident history per IP · honeypot interactions · attacker profile · action timeline · related infrastructure (same /24, same ASN) · external threat feed cross-ref |
| **AI threat brief** | `ai_manager.chat(task_type=ip_threat_brief)` with multi-model fallback (`openrouter/openai/gpt-oss-20b:free` working) |
| **UI** | `/dashboard/ip-intel` manual lookup · deep mode checkbox · recent searches · classification pill · confidence pills · abuse score · proxy type · OTX pulses · VT verdict · Shodan ports · JA4 fingerprints · honeypot canaries · timeline · related chips · threat brief · `[algorithm:X]` / `[agent:X]` provenance tags · Report-abuse mailto CTA |
| **Incident pipeline** | Auto-enrichment via SQLAlchemy `after_insert` listener — every incident gets `ai_analysis.ip_intel` populated within ~6s of detection |

### Active deception

- **WebRTC + canvas + audio + headless** canary JS embedded in HTTP honeypot decoy pages (Mac Pro :8888 + Pi :8081). POSTs to `/__c`, persisted to `honeypot_canaries` table.
- **AWS credential canaries** planted in `/wp-config.php{,.bak,.txt}`, `/.env.{bak,example,production,local}`, `/api/v1/internal/config` (re-uses existing BREADCRUMB_INDICATORS so re-played creds trip the detector across all monitored apps).
- **JA4 TLS fingerprinting** on honeypot port 8889 (pure-Python ClientHello parser, no PyPI dep, self-signed cert).

### MITRE TTP Campaign clustering

- `services/ttp_clustering.py` groups recent incidents by `(tactic::technique)` fingerprint.
- `GET /api/v1/threats/campaigns` (list) and `GET /api/v1/threats/campaigns/{cluster_id}` (drill-down with IP intel per attacker).
- `/dashboard/threats/campaigns` premium redesign:
  - 4 KPI tiles
  - URL-synced filter bar (window / min-IPs / tactic / severity)
  - **Lazy-loaded MITRE ATT&CK matrix** — 14 tactics × techniques heat-shaded
  - Expandable campaign cards with 4 tabs (Overview · Attacker IPs · Incidents · Timeline)
  - Plain-language summary per campaign
  - Mark-investigated + Export CSV actions

### Dashboard redesign (incident-first, image-1 / image-2 inspired)

- Hero greeting `Hello, #INC-xxxx` (or "All quiet")
- 4 KPI tiles
- **Incident Timeline** horizontal scrubber with severity-colored chips
- AI Suggested Actions panel with Approve / Reject (live wired to backend)
- Login Attempts dot-grid heatmap (10×8, honeypot interactions last 6h)
- Threat Detection gradient area chart (7d)
- Asset Risk Table (per-app incidents + resolved + risk score)
- Lazy-loaded Global Threat Map

### Sidebar → TopNav consolidation

20+ sidebar items collapsed to 5 top-level sections:

- **Dashboard** | **Threats** (Response · Campaigns · IoCs · IP Intel) | **Defense** (Firewall · Phantom · Deception · Antivirus · Ransomware · EDR) | **Assets** (Surface · Infra · Attack Path) | **Reports** (Reports · Compliance · Quantum)
- User menu: Settings · Sign out
- Section sub-tab strip below TopNav per section
- Mobile hamburger drawer
- A11y: `aria-current="page"`, `aria-haspopup`, `motion-safe:` transitions

### Premium component library (`components/aegis/`)

Seven canonical primitives, all on-brand tokens, all touch ≥44px:

`<Panel>` (5 variants × 4 padding × 3 border × interactive) ·
`<SectionHeader>` · `<KPI>` (5 tone variants) · `<DataRow>` ·
`<StatusBadge>` (7 variants) · `<EmptyState>` · `<ProvenanceBadge>`
(algorithm / agent / honeypot / legacy / rule / manual)

Refactored consumers: main dashboard, all 6 dashboard components,
`response`, `ip-intel`, `firewall` pages.

### MITRE plain-language

`frontend/src/lib/mitre.ts` — 20-technique lookup with `id, name, tactic, plain, url`. Helpers `mitreLabel(id)` → `T1190 (Exploiting a public website or API)` and `mitreInfo(id)`. Applied across 7 rendering sites.

### Backend P0 bug fixes

- `notify_critical_event` AttributeError (webhook delivery broken) → implemented
- Reject endpoint missing (`POST /response/actions/{id}/reject` + audit log + idempotency)
- Threat-map shape mismatch (`{ip, count}` → `{country, country_code, count}`) via offline GeoIP grouping

### Threats cleanup

- 108 incidents resolved (7 synthetic E2E + 101 false-positive crawlers/users)
- 7 IPs unblocked from Pi (Googlebot ranges, Flipboard, your Starlink IP)
- 12 phantom profiles deleted
- 7 real attackers retained:
  `45.155.205.233 · 100.55.135.214 · 98.83.73.112 · 3.82.72.4 · 31.4.148.79 · 185.124.0.195 · 3.227.115.211`
- AEGIS_SAFE_IPS extended with `66.249.0.0/16` (Googlebot) and `74.244.193.0/24` (your Starlink)
- Phantom safety filter prevents recreation of RFC5737 / safe-net profiles

### New endpoints

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/intel/ip/{ip}?deep=true&history=true` | IP intel deep mode |
| `POST /api/v1/response/actions/{id}/reject` | Reject pending action |
| `GET /api/v1/firewall/blocked` / `stats` / `DELETE /blocked/{ip}` | Live firewall surface |
| `GET /api/v1/threats/campaigns` / `/{cluster_id}` / `POST /investigated` | TTP campaigns |
| `GET /api/v1/phantom/canaries?ip&hours&limit` | List canary captures |
| `GET /api/v1/dashboard/monitored-apps` | Backend source of monitored apps (kills hardcoded drift) |
| `GET /api/v1/dashboard/threat-map` | Country-grouped attacker counts |
| `POST /api/v1/phantom/canary` | Honeypot canary ingest (open auth, called by decoy JS) |

### Demo / UX polish

- Demo mode banner on Firewall + Threats with mutations disabled
- Deception Enterprise upsell with Lock icon + mailto CTA
- Threats CSV export wired
- TopNav `prefers-reduced-motion` + `aria-haspopup`

---

## Commits pushed (chronological)

```
59f8fb1 fix(ai_manager): provider quarantine on quota errors (402/429)
d421fbe fix(pi-firewall): write to AEGIS_BLOCK chain (not INPUT)
56a015e chore(frontend): align versions to v1.6.2
e8a6bc6 feat(log_watcher): AEGIS_EXTRA_LOG_PATHS
0xxxx... feat(aegis-feed): unified log feed Python + Node writers
0xxxx... feat(web-server-logger): inline AEGIS feed emit
0xxxx... feat(sable / sid-backend / wilabia-backend / landing-wilab middleware): emit unified feed
38ec8ab feat(pi-honeypot): standalone HTTP honeypot
... (mid-sprint commits omitted for brevity) ...
81e9e59 feat(nav): TopNav + section sub-tabs
990e849 feat(dashboard): incident-first redesign
b7727c2 fix(dashboard): TS chart formatter
a358cfe feat(ui): AEGIS premium primitive library
d598770 refactor(dashboard): route surfaces through primitives
bd7b8cc docs(ops): threats cleanup audit
e6ca419 feat(threats/campaigns): premium redesign with MITRE matrix
6c99455 fix(p0): notifier + reject + threat-map shape
93f269c feat(mitre): plain-language explanations
0d5576d feat(mitre): matrix tooltip
6313bee feat(phantom): list canary captures
194a8e0 feat(dashboard): monitored-apps endpoint
16683c3 refactor(ui): primitives in response/ip-intel/firewall + TopNav a11y
ff58800 feat(ux): demo banner + deception upsell + threats CSV
```

---

## Production state

- **Pi blocklist**: 7 real attackers
- **Phantom profiles**: 7
- **Open incidents**: low (test artifacts cleared)
- **AI mode**: `full` (provider chain functioning via OpenRouter free models)
- **Honeypots**: Mac Pro :2222 / :8888 / :8889 (JA4) + Pi :8081 — all listening
- **Threat feeds**: tor_exit (1,277) · spamhaus (1,613) · emerging_threats (538) · feodo (1) · all refreshed periodically
- **External services**: ipinfo / ip.guide / ipquery / ipapi.is / proxycheck / ip-api / GeoJS / OTX (no key) / Shodan InternetDB all live; VirusTotal / AbuseIPDB / IPInfo Lite optional (env-gated)

---

## Documented follow-ups (no current blockers)

1. **Test coverage gap** — 26 services without test files (ai_engine, correlation_engine, behavioral_ml, counter_attack, etc.). Critical security path `ai_engine.process_alert()` → incident → firewall has zero unit tests.
2. **JA4 known-tool table sparse** — 14 patterns curated; ingest ja4db.com dump for production-grade tool identification.
3. **OpenRouter free model drift** — 9 hardcoded model names will rotate; refresh quarterly.
4. **Behavioral fingerprint window** — reads last 8 MB of unified feed; correlation limited beyond ~24h of traffic.
5. **TLS honeypot doesn't engage** — captures JA4 then closes connection (no decoy served). Engagement value low.
6. **`74.244.193.0/24` (Starlink) whitelisted** — confirmed as user's own IP block via Sable testing. Re-evaluate if Starlink ranges shift.
7. **DSL firewall rules table** — kept legacy `<Card>` rows (complex grid). Refactor when ergonomic.
8. **db-ip city CSV deferred** (685 MB) — city/region falls back to online providers.
