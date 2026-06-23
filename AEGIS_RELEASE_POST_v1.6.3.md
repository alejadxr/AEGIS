# AEGIS v1.6.3 — June 2026 Threat-Intel Pack + Frontend Completeness

**Released:** 2026-06-23 · [Download](https://github.com/alejadxr/AEGIS/releases/tag/v1.6.3) · [CHANGELOG](https://github.com/alejadxr/AEGIS/blob/main/CHANGELOG.md#163---2026-06-23-late)

> v1.6.2 shipped a few hours earlier and fixed the false-positive firehose. v1.6.3 takes the cleaned-up baseline and pushes coverage forward: 26 new detection rules from the June 1–23 2026 threat landscape, plus a complete frontend pass that closes a 404 on `/login` and 10 other broken/incomplete UI surfaces.

---

## TL;DR

- **26 new Sigma rules** mined from June 2026 KEV catalog additions, NVD CVEs, Microsoft/Cisco advisories, npm + PyPI supply-chain attacks, RaaS launches, and AI-infra CVEs (MCP, LiteLLM, Marimo). Each rule has both an in-code dict and a YAML mirror under `backend/app/rules/sigma/<category>/`. 52 smoke tests included.
- **New `/login` page** — the dashboard auth gate now redirects to a real URL with `?next=` preservation instead of silently swapping content on `/dashboard/*` routes.
- **11 frontend fixes** across 22 dashboard pages: download links wired, demo-mode banner now global instead of per-button tooltip, compliance roadmap visible, backend connection errors surface in a red retry banner, heartbeat fetch failures no longer swallowed.
- **Frontend hardening signals**: `metadataBase` set so OG/Twitter images resolve correctly; eslint-disable suppressions removed; pre-existing JSX-comment ESLint blocker fixed.

---

## The threat intel that drove this

The day v1.6.2 shipped we kicked off a parallel research workflow with 15 area-specific Haiku agents and an adversarial Opus verifier. Each agent covered one slice of the June 2026 landscape:

| Slice | Highlight |
|---|---|
| KEV catalog additions | CVE-2026-48907 Joomla JCE editor pre-auth RCE; CVE-2026-45247 Magento Mirasvit deserialization; CVE-2026-10520 Ivanti Sentry MICS API command injection; CVE-2026-20253 Splunk PostgreSQL sidecar unauthenticated RCE |
| AI-infra CVEs | CVE-2026-42271 BerriAI LiteLLM MCP REST command injection; CVE-2026-39987 Marimo notebook pre-auth WebSocket terminal RCE; CVE-2026-XXX SGLang `/v1/rerank` server-side template injection |
| Web framework advisories | Next.js WebSocket SSRF; Drupal JSON:API SQLi; Ghost CMS Content API SQLi; cPanel WHM CRLF injection |
| Network appliances | PAN-OS GlobalProtect auth bypass; Schneider Saitel HMI path traversal; AVer PTC cameras CGI RCE |
| Ransomware / RaaS | PrinzEugen and ShinySp1d3r encryption file extensions |
| C2 / botnets | AyySSHush ASUS botnet IOC IPs; Qilin Check Point campaign C2; Fortinet "Fortibleed" leak fallout |
| npm supply chain | Shai-Hulud "Hades" + "Firedalazer" + "Miasma" + Anthropic-impersonating variants; mastra-ai `easyday[.]live` C2; axios compromise → `sfrclak[.]com`; node-ipc backdoor → `sh.azurestaticprovider.net`; Solana FakeFix Telegram exfil |

Verifier kept 26 findings (clear HTTP/log/process signatures, low false-positive risk), deferred 25 (kernel-only — slated for v1.6.4 endpoint agent), and rejected 32 (too vague or duplicate). Each kept finding landed as both a `correlation_engine.py` PATTERNS dict and a YAML file under `backend/app/rules/sigma/<category>/`, with a smoke test pair (positive event must match, negative event must not).

---

## What you'll notice in the dashboard

### A real `/login` page

Before v1.6.3, `/login` returned a 404 and the dashboard's auth gate silently swapped content in place. Now:

- `/login` serves a dedicated form with `?next=<encoded-path>` support.
- The dashboard layout reads pathname; unauthenticated users get redirected to `/login?next=<their-path>`.
- `/dashboard/guide` stays public (no auth required) as a pre-trial landing.
- "Continue as guest" link on `/login` points at the guide.

### Demo mode is now visible

Demo deployments previously greyed out controls with per-button tooltips that most users never hovered. v1.6.3 ships `<DemoModeBanner/>` — a single amber banner at the top of the affected page with a "Sign in →" CTA pointing at `/login?next=`. Wired into `/dashboard/firewall` and `/dashboard/threats` initially.

### Real download links

`/dashboard/infra` had three "Download AEGIS for Windows / macOS / Linux" buttons that all linked to `#`. They now point at the latest GitHub release asset URLs (`https://github.com/alejadxr/AEGIS/releases/latest/download/...`).

### Honest compliance roadmap

`/dashboard/compliance` had CC8 Change Management hardcoded as `not_met` with no context. It's now `roadmap` with a visible "Planned for v1.7" line — operators see what's coming instead of a static red dot.

### Backend errors surface

`/setup` previously swallowed `ERR_CONNECTION_REFUSED` silently when the backend was down. Now a red banner at the top of the page shows "Cannot reach AEGIS API at &lt;url&gt;. Make sure cayde6-api is running." with a Retry button. Premium honeypot gating is visibly disabled (grayscale + lock icon + tooltip) instead of console-only.

### NodeHeartbeatGrid stops lying

The component previously caught heartbeat fetch failures with `.catch(() => {})` and rendered no failure signal. Now it logs the error, sets local state, and renders a red error indicator with hover tooltip showing the actual failure message.

### OG/Twitter images resolve correctly

`metadataBase` is now set to `process.env.NEXT_PUBLIC_APP_URL` (fallback `https://aegis.somoswilab.com`). Previously the metadata generator resolved Open Graph and Twitter image URLs against `http://localhost:3007`, which produced broken previews when AEGIS pages were shared.

---

## What v1.6.4 owes you

The threat intel workflow also produced 25 verified findings that we did NOT ship in v1.6.3 because AEGIS's current observability doesn't reach them. They need an endpoint agent:

- **Kernel CVEs** — Dirty Frag (CVE-2026-43284), Copy Fail (CVE-2026-31431), runc escape series, systemd-machined D-Bus race. Need eBPF or auditd.
- **Syscall-trace TTPs** — Lazarus toolchain June campaign, several APT loader chains observed in the wild.
- **Compiled-binary diffing** — supply-chain attacks that modify package binaries post-install (silent compromise of legitimate npm packages without source-level markers).

v1.6.4 builds the endpoint agent.

Also still owed from v1.6.2 deferred list:
- Behavioral baseline for slow-and-low APT (rotating-IP brute force across hours)
- Cross-source incident dedup at correlation_engine level (residual fast_triage doubling)
- Severity rebalancing for remaining audit-flagged rules

---

## Links

- **Release page:** https://github.com/alejadxr/AEGIS/releases/tag/v1.6.3
- **Full CHANGELOG:** https://github.com/alejadxr/AEGIS/blob/main/CHANGELOG.md
- **Source diff:** https://github.com/alejadxr/AEGIS/compare/v1.6.2...v1.6.3
- **v1.6.2 release notes (shipped earlier today):** https://github.com/alejadxr/AEGIS/blob/main/AEGIS_RELEASE_POST_v1.6.2.md

Upgrade path: `git pull && pm2 restart cayde6-api cayde6-frontend`. New env vars: none — v1.6.3 uses the same `AEGIS_*` configuration as v1.6.2.
