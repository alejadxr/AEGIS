# AEGIS — Brand, Product & Marketing Master Doc

> Single source of truth for what AEGIS is, how it looks, who it's for, and how to talk about it. Last updated 2026-05-04 (v1.6.3.2 published + Gemini provider live + SEO/GEO landed).

---

## 1. One-line pitch

**AEGIS is the open-source autonomous defense platform that detects, contains, and recovers from attacks in milliseconds — without an LLM in the hot path.**

## 2. Tagline ladder

- **Hero (≤50 char)**: *Autonomous defense at machine speed.*
- **Sub (≤120 char)**: *Detect, block, and recover from ransomware and intrusions in milliseconds — deterministic-first, AI-optional.*
- **30-second pitch**: AEGIS is a self-driving cybersecurity defense platform. It owns your firewall, watches your logs, runs honeypots, and fires Sigma rules + chain detections in <1 ms. When it sees an attack — brute force, RDP-then-encrypt, shadow-copy delete, ransom note dropped — it auto-blocks the attacker IP, kills the process tree, restores from snapshot, and writes the postmortem. AI assists *if you have a key*. With `AEGIS_AI_MODE=offline` the whole stack runs on rules and templates. v1.6 ships full ransomware defense end-to-end.

## 3. Positioning

| Axis | AEGIS | Conventional EDR | Sentinel/Splunk SIEM |
|---|---|---|---|
| Deployment | Single binary + frontend, ~3 min | Agent rollout, license, console | Cloud + connectors, weeks |
| Detection latency | <1 ms in-memory eval | 5–60 s pipeline | minutes |
| Action latency | <50 ms (local pfctl/iptables) | Approval queue | Manual SOAR playbook |
| AI dependency | Optional enrichment | Often hard requirement | Hard requirement (often per-event $$$) |
| Cost | Free, open source | $5–25/endpoint/mo | $1k–10k/mo entry |
| Audience | Indie hackers, homelabs, SMB security | Enterprise SOC | Enterprise SOC |

**Where AEGIS wins**: solo operators, indie SaaS, homelab pros, and SMB shops that want SOC-grade defense without SOC-grade billing or three full-time analysts.

**Where AEGIS doesn't try to win**: Fortune 500 multi-region SIEM consolidation, regulated environments needing Magic-Quadrant vendors, customers who want managed detection-as-a-service.

## 4. What it does (as of v1.6)

### Three pillars
- **Surface** — attack-surface management. nmap + nuclei on a schedule, AI risk scoring (optional), hardening checks. Every service AEGIS sees becomes an asset with a CVSS history.
- **Response** — autonomous incident response. Ingests PM2/journalctl logs, fires the rule pack (134 Sigma + 6 chains), runs guardrailed playbooks (auto_approve / require_approval / never_auto), executes `pfctl`/`iptables` blocks via `firewall_local.py` when `AEGIS_REAL_FW=1`, returns 403 via FastAPI middleware otherwise.
- **Phantom** — deception. SSH honeypot on :2222, HTTP decoy on :8888, rotation engine, breadcrumb tracker. Templates in `app/templates/honeypot/` so it works offline.

### v1.6 — Autonomous Ransomware Defense (just shipped)
- 12 ransomware Sigma rules + 1 kill-chain (T1490 / T1486 / T1105 / T1218 / T1021)
- RaaS threat intel feed (RansomLook + CISA), refreshes every 6 h, persists locally
- Recovery orchestration: `snapshot_manager` (tmutil / btrfs / zfs / VSS), `decryptor_library` (NoMoreRansom seed)
- Dedicated `/dashboard/ransomware` route with RaaS group timeline + decryptor lookup + recent events
- Hardened Rust agent: canary watcher, sliding-window entropy classifier (≥50 writes/s + ≥7.5 bits/byte), kill-chain process killer with forensic snapshot, self-protection (`prctl(PR_SET_DUMPABLE,0)` on Linux, `SetProcessMitigationPolicy` on Windows)
- Livefire emulation harness gated by `AEGIS_LIVEFIRE=1`

### Deterministic-first guarantee (v1.5+)
Every AI call site has a deterministic fallback. Set `AEGIS_AI_MODE=offline` and:
- Honeypot decoys serve from Jinja templates (not LLM-generated)
- Incident analysis comes from MITRE rule mapper + chain heuristics
- Counter-attack uses a static `threat_type → action_sequence` table
- IP enrichment uses RBL + GeoIP (no model call)
- Reports render from Jinja templates per type
- All 6 in-code playbooks ship; the AI selector is replaced by `THREAT_TO_PLAYBOOK` dict

## 5. Visual identity

### Theme name: **"Refined Dark Command"**
Influenced by Sentry, Linear, Vercel — utilitarian, dense, signal-over-chrome.

### Color tokens (frontend/src/app/globals.css)
| Role | Token | Value |
|---|---|---|
| Surface 0 (page bg) | `--bg-base` | `#0A0A0B` |
| Surface 1 (cards) | `--bg-card` | `#18181B` |
| Surface 2 (popovers) | `--bg-pop` | `#27272A` |
| Border subtle | `--border-subtle` | `rgba(255,255,255,0.06)` |
| Text primary | `--text-1` | `#FAFAFA` |
| Text secondary | `--text-2` | `#A1A1AA` |
| Accent — info / signal | `--accent-cyan` | `#22D3EE` |
| Accent — alert / kinetic | `--accent-orange` | `#F97316` |
| Success | `--success` | `#10B981` |
| Critical | `--critical` | `#EF4444` |

Light mode mirrors via `data-theme="light"` on `<html>`. The `.dark` class is the default; light is opt-in. Both themes pass WCAG AA on every shipped component.

### Typography
- **Headlines / UI**: Outfit (variable, 100–900). Set on `<body>`.
- **Data / numbers / IDs / log lines**: Azeret Mono (variable). Used inside `<code>`, `<kbd>`, table cells flagged `font-mono`.
- **Scale**: 12 / 13 / 14 (body) / 16 / 20 / 24 / 32 / 48. Line-height 1.4 body, 1.15 headlines.

### Iconography
- Primary set: **hugeicons-react** (line-style, 1.5 stroke).
- Fallback: lucide-react when a hugeicon doesn't fit.
- Sidebar uses `ShieldX` for Ransomware, `Shield` for Defense overall, `Network` for Surface, `Eye` for Phantom, `Activity` for Threats.

### Card pattern (universal)
```tsx
<div className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-6">
  ...
</div>
```

### Status pills (universal)
- `pill-success` — green border + bg-tint, used for "rules active", "uptime ok"
- `pill-warning` — amber, used for "feeds stale", "approval pending"
- `pill-critical` — red, used for "incidents in last 24 h"
- `pill-info` — cyan, used for "RaaS groups tracked", "AI mode optional"

### Logo / wordmark
- Wordmark: `AEGIS` set in Outfit Bold, all caps, letter-spacing 0.08em.
- Mark: shield silhouette filled with cyan→orange gradient (matches the two accent tokens). Used in favicon and app icon.
- Avoid: stock padlock icons, "blue cyber" gradients, code-rain backgrounds.

### Voice
- Direct. Active voice. Numbers when possible.
- "AEGIS blocks the IP and writes the postmortem" — not "an action will be taken".
- Avoid: "AI-powered", "next-gen", "revolutionary", "leverage", "unlock". They make us sound like a mid-tier vendor.
- We do say: "deterministic", "offline-capable", "self-hosted", "auditable".

## 6. Audience

### Primary persona — **The Solo Operator** (Diego, indie hacker, 28–45)
- Runs 2–6 services on a Mac mini / homelab / VPS
- Has technical chops but no time to babysit Splunk
- Wants "set it and forget it" with explicit human-in-the-loop where it matters
- Pain: Cloudflare/WAF gives surface protection but nothing about lateral movement, ransomware, or recovery
- Buying trigger: a successful brute-force attempt or first-ransomware-scare news cycle

### Secondary — **The Indie SaaS team** (1–5 engineers)
- Need SOC2/ISO evidence without a $30k SIEM
- Want auto-block + audit log + a dashboard their auditor can screenshot
- Buying trigger: a customer asks "how do you detect intrusions"

### Tertiary — **The Pentester / Red-teamer**
- Uses AEGIS as a target during engagements (ourselves included on Mac Pro / Kali pair)
- Pushes us to harden detection, finds blind spots
- Often becomes a contributor

### Anti-persona — **The Enterprise SOC**
- We do not chase RFPs, MSSP partnerships, or compliance frameworks beyond SOC2 / ISO27001 / NIST CSF.
- That's a separate product. Refer them to elastic-security or Wazuh.

## 7. Distribution channels (priority order)

1. **GitHub Releases** — desktop binaries (.dmg / .msi / .AppImage / .deb / .rpm), Docker images on GHCR. Public releases drive trust.
2. **Show HN / r/selfhosted / r/homelab** — every minor version. Lead with a single screenshot of the dashboard + a 30-second loom.
3. **Reddit r/cybersecurity, r/sysadmin** — major versions only, focus on the deterministic-first angle.
4. **Twitter/X** — short builds-in-public threads, GIFs of attacks being blocked live, behind-the-scenes screenshots.
5. **somoswilab.com** — landing page (Next.js 16, hosted on Mac Pro). Newsletter signup.
6. **Indie podcasts / OSS interviews** — opportunistic, don't chase.

We do not currently:
- Pay for Google Ads
- Run cold outbound
- Sponsor newsletters

## 8. Pricing & business model

- **Open source, AGPL-3.0**, free forever.
- **Hosted edition** (planned, not shipping yet): managed AEGIS-as-a-service for teams that want the dashboard but not the ops. Pricing TBD; start at $29/mo for solo, $99/mo for team-of-5.
- **Commercial support contracts** (planned): on-call response + custom rule packs for $2–5k/mo. Only if 3+ inbound asks.

## 9. Roadmap (post-v1.6)

### v1.7 — "Federation" (target: Q3 2026)
- Multi-host AEGIS instances share threat intel via signed gossip
- Central pane-of-glass dashboard for managing N nodes from one UI
- Per-tenant rule packs

### v1.8 — "Auditor" (target: Q4 2026)
- Built-in SOC2 / ISO27001 evidence exports
- Tamper-evident audit log (signed, append-only)
- Compliance dashboard with control-mapping

### v2.0 — "Anyone Can Defend" (target: H1 2027)
- One-click installers per OS
- Web-based onboarding wizard
- Hosted edition GA

### Not on the roadmap (explicit no)
- Mobile app
- Browser extension
- Crypto/web3 integrations
- "AI agent" that pretends to be a SOC analyst

## 10. Tech stack snapshot

| Layer | Stack |
|---|---|
| Backend | FastAPI · SQLAlchemy 2 (async) · PostgreSQL 16 · APScheduler |
| Frontend | Next.js 14 (app router) · TypeScript · Tailwind · recharts · react-simple-maps |
| Desktop | Tauri 2 (Rust 1.7+) · `notify` for fs · `sysinfo` for proc |
| Endpoint agent | Rust workspace (`agent-rust/`), `tokio` runtime |
| Honeypots | paramiko (SSH) · aiohttp (HTTP) · Jinja2 templates |
| AI (optional) | OpenRouter · Inception Mercury-2 · Anthropic · OpenAI · Ollama (local) · **Google Gemini (`gemini-flash-lite-latest` default)** — multi-provider, all opt-in via env keys |
| Threat intel | RansomLook · CISA advisories · Spamhaus · Tor exit list · MaxMind GeoIP-Lite |
| Deploy | Docker Compose · PM2 · Tailscale (cross-machine) |

## 11. Operational primitives

| Env var | Purpose |
|---|---|
| `AEGIS_AI_MODE` | `full` / `local` / `offline` — gates every AI call site |
| `AEGIS_REAL_FW` | `1` to enable real `pfctl`/`iptables` |
| `AEGIS_REAL_RECOVERY` | `1` to enable real snapshot restore subprocess |
| `AEGIS_LIVEFIRE` | `1` to allow the destructive emulator (tempdir-only) |
| `AEGIS_FIREWALL_URL` | Optional remote firewall agent (currently unset in prod) |
| `AEGIS_MONITORED_APPS` | Comma-separated PM2 app names to tail |
| `OPENROUTER_API_KEY` | Optional — when unset, AI mode auto-falls to `offline` |
| `GEMINI_API_KEY` | Optional — Google Gemini provider (`gemini-flash-lite-latest` default) |
| `GEMINI_BASE_URL` | Override Gemini endpoint (defaults to `generativelanguage.googleapis.com/v1beta`) |
| `INCEPTION_API_KEY` | Optional — Inception Labs Mercury-2 (preferred when set) |

| Port | Service |
|---|---|
| 3007 | Frontend (`cayde6-frontend` PM2) |
| 8000 | API (`cayde6-api` PM2) |
| 8888 | HTTP honeypot |
| 2222 | SSH honeypot |
| 5432 | PostgreSQL |

## 12. How to talk about us in one sentence

> "AEGIS is the open-source defense brain that runs on your own box, blocks attackers in milliseconds, and recovers from ransomware without phoning home to anyone."

## 13. How NOT to talk about us

- ❌ "AI-powered cybersecurity" → we are deterministic-first.
- ❌ "Next-gen XDR/SOAR" → buzzword bingo, our audience tunes out.
- ❌ "Replaces your SOC" → we augment, we don't replace.
- ❌ "Ransomware-proof" → marketing legalese; we say "ransomware defense" or "ransomware kill-chain detection".
- ❌ "Zero false positives" → impossible claim, kills credibility.

## 14. Quick links

- **Repo**: https://github.com/alejadxr/AEGIS
- **Latest release**: https://github.com/alejadxr/AEGIS/releases/tag/v1.6.3.2
- **Docker images**: `ghcr.io/alejadxr/aegis/aegis-api:1.6.3.2`, `:aegis-frontend:1.6.3.2`
- **Landing**: somoswilab.com (when live)
- **CHANGELOG**: in repo

## 15. v1.6 launch checklist

- [x] Code merged to main
- [x] Tag v1.6.3.2 pushed
- [x] Release workflow green (8/8 jobs after 5 fix iterations on release.yml + Dockerfile)
- [x] Desktop binaries built (mac arm64 .dmg + .app.tar.gz, mac x64 .dmg, linux x64 .deb/.rpm/.AppImage, windows x64 .exe/.msi)
- [x] Docker images on GHCR (`ghcr.io/alejadxr/aegis/aegis-{api,frontend}:1.6.3.2` + `:latest`)
- [x] Release published (no longer draft) — https://github.com/alejadxr/AEGIS/releases/tag/v1.6.3.2
- [x] README rewrite for AI-search citability (H1, FAQ, comparison table, JSON-LD schema)
- [x] `docs/seo/` published (what-is-aegis, ransomware-defense, comparison)
- [x] `.well-known/llms.txt` standard for LLM discovery
- [x] Frontend `<head>` JSON-LD (SoftwareApplication + FAQPage) + OG + Twitter Card
- [x] Gemini provider integrated (`gemini-flash-lite-latest` default) — opt-in via `GEMINI_API_KEY`
- [ ] Post on r/selfhosted (use MEDIUM version of `AEGIS_RELEASE_POST_v1.6.md`)
- [ ] Post on r/cybersecurity / r/homelab
- [ ] Twitter/X thread (10 tweets ready)
- [ ] Show HN (LONG version)
- [ ] Update somoswilab.com hero with v1.6 ransomware angle
- [ ] Newsletter blast (if list >100)

## 16. Post-v1.6 deltas (since launch)

- **Gemini provider** (commit `be2548f`) — multi-provider AI manager now includes Google Gemini; precedence Inception → OpenRouter → Gemini. 8 unit tests cover translation + factory + happy-path HTTP shape.
- **SEO/GEO pass** — README rewritten with H1+FAQ+comparison+JSON-LD; new `docs/seo/` cluster; `.well-known/llms.txt`; `frontend/src/app/layout.tsx` metadata + Open Graph + structured data.
- **Release published** — no longer draft. 7 desktop assets with correct v1.6.3.2 filenames after Tauri version bump (`desktop-tauri/src-tauri/{tauri.conf.json,Cargo.toml}` 1.5.0 → 1.6.3.2).
