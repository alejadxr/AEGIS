# AEGIS v1.6 — Autonomous Ransomware Defense

> Cross-channel post pack for r/selfhosted, r/cybersecurity, r/homelab, X/Twitter, Show HN, and the project newsletter. Pick the version that fits the channel; tone notes inline.
>
> **Status (2026-05-04):** v1.6.0 is live (release published, not draft) at https://github.com/alejadxr/AEGIS/releases/tag/v1.6.0 with 7 desktop assets + Docker images on GHCR. Posts below are ready to ship — no edits needed unless you want to add the v1.6.x patch deltas (Gemini provider, SEO pass) which are linked at the bottom.

---

## SHORT (Twitter/X — primary thread)

🛡️ AEGIS v1.6 just shipped: full ransomware defense end-to-end.

Open-source. Self-hosted. Runs without an LLM.

Detects → blocks → recovers in milliseconds.

Thread 🧵👇

---

1/ AEGIS is the defense brain that lives on your box. v1.6 closes every ransomware-defense gap: server-side rules, RaaS threat intel, recovery orchestration, dedicated playbook + dashboard, hardened endpoint agent, and a livefire test harness.

2/ 12 new Sigma rules + 1 kill-chain detection mapped to MITRE T1490 / T1486 / T1105 / T1218 / T1021. Engine evaluates each event in <1 ms via a regex-aware filter system.

Watching for: vssadmin/wbadmin/bcdedit shadow-delete, mass extension change, canary tripped, ransom note dropped, certutil/rundll32 LOLBin staging, RDP-then-encrypt, SMB lateral, WinRM exec.

3/ RaaS threat intel feed: pulls from RansomLook + CISA every 6 h. C2 IPs, onion addresses, file extensions, ransom-note artifacts. Cached on disk so it works offline.

4/ Recovery: snapshot_manager wraps tmutil (mac), btrfs/zfs (linux), VSS (windows). decryptor_library ships a NoMoreRansom seed (Akira, Babuk, REvil, LockBit, WannaCry, Conti, Locky…). New endpoints: GET /recovery-options/{event_id}, POST /restore, GET /decryptors.

5/ Hardened Rust endpoint agent. Canary watcher (notify), sliding-window entropy classifier (≥50 writes/s + ≥7.5 bits/byte mean), kill-chain process killer with forensic snapshot before SIGKILL, self-protect (`prctl(PR_SET_DUMPABLE,0)` on linux, `SetProcessMitigationPolicy` on windows).

6/ Livefire emulator gated by `AEGIS_LIVEFIRE=1`. Generates 100 dummy files, XOR + entropy-pads them to look real, drops a ransom note, races the agent to the kill-chain. End-to-end repeatable test of the entire stack.

7/ Deterministic-first stays. `AEGIS_AI_MODE=offline` and the whole product runs on Sigma rules + Jinja templates + static playbooks. AI is an optional enrichment, never a hard dep.

8/ Ship details:
🐙 https://github.com/alejadxr/AEGIS
📦 v1.6.0 tag — 25 commits over R-A through R-F
✅ 156 tests green (125 Python + 21 Rust + 10 e2e gated)
🐳 ghcr.io/alejadxr/aegis/aegis-{api,frontend}:1.6.0
🖥️ macOS / Windows / Linux desktop binaries on the release page

9/ Built by one operator + 4 sonnet sub-agents in parallel + opus controller. File-ownership boundaries, two-stage review, zero merge conflicts. The dev process is itself a case study; will write it up next week.

10/ AEGIS is for indie hackers, homelabs, indie SaaS teams. Free forever. Apache-2.0. If your defense story today is "Cloudflare + hope", give it a spin: docker compose up -d, and you have rules + honeypots + autoblock in 3 min.

⭐ if useful, issues + PRs welcome.

---

## MEDIUM (r/selfhosted, r/homelab — value-led)

**Title**: AEGIS v1.6 — open-source autonomous defense, now with full ransomware kill-chain detection

Just shipped v1.6 of [AEGIS](https://github.com/alejadxr/AEGIS), an open-source self-hosted defense platform.

**What it is in one sentence**: a single FastAPI + Next.js app that owns your firewall, watches your logs and honeypots, and fires Sigma rules + chain detections in <1 ms. When it sees an attack, it auto-blocks the IP, kills the process tree, restores from snapshot, and writes the postmortem.

**What's new in v1.6** (Phase R-A through R-F):

- **12 ransomware Sigma rules + 1 kill-chain** — shadow-copy delete (vssadmin / wbadmin / bcdedit / tmutil / btrfs), mass extension change, canary tripped, ransom note dropped, certutil/rundll32 LOLBin staging, RDP-then-encrypt, SMB lateral, WinRM remote exec. Mapped to MITRE T1490 / T1486 / T1105 / T1218 / T1021.
- **RaaS threat intel feed** — pulls IOCs from RansomLook + CISA every 6 h. Group-aware: aliases, C2 IPs, onion addresses, file extensions, ransom-note artifacts.
- **Recovery orchestration** — `snapshot_manager` wraps tmutil/btrfs/zfs/VSS, gated by `AEGIS_REAL_RECOVERY=1`. `decryptor_library` ships a NoMoreRansom seed list. New REST endpoints to query recovery options + trigger restore.
- **Dedicated `/dashboard/ransomware` route** — RaaS group activity timeline (recharts), recent events table, decryptor lookup widget. Light + dark themes.
- **Hardened Rust endpoint agent** — canary watcher, sliding-window entropy classifier (≥50 writes/s + ≥7.5 bits/byte), kill-chain process killer with forensic snapshot before kill, self-protect via `prctl` (linux) and `SetProcessMitigationPolicy` (windows).
- **Livefire emulator** — gated by `AEGIS_LIVEFIRE=1`, never touches real files (tempdir-only).

**Stays true to the v1.5 promise**: `AEGIS_AI_MODE=offline` and the whole stack runs on Sigma rules + Jinja templates. No LLM in the hot path, ever.

**Get it running** (3 min):
```bash
git clone https://github.com/alejadxr/AEGIS && cd AEGIS
docker compose up -d --build
# dashboard at localhost:3007
# API at localhost:8000
```

For Mac mini / Pi / homelab folks: it's tested on Mac Pro + Raspberry Pi 5 (Hailo-10H gateway) over Tailscale, but standalone Docker works anywhere.

Apache-2.0. Issues + PRs welcome. Roadmap (federation, audit-grade evidence exports, hosted edition) in the repo.

---

## LONG (Show HN — story-driven, dev-tribe)

**Title**: Show HN: AEGIS v1.6 — Open-source autonomous defense brain that detects ransomware in <1 ms

Hey HN,

I'm Diego, the maintainer of [AEGIS](https://github.com/alejadxr/AEGIS). Today I'm shipping v1.6 — full ransomware defense end-to-end — and I wanted to share both the product and the build process.

**The problem we set out to solve**

Every solo operator and indie team I know has the same defense story: Cloudflare for surface, hope for the rest. EDRs are licensed per endpoint and assume you have a SOC. SIEMs cost $1k–10k/month and need three full-time analysts to be useful. There's a gap between "I run a few services" and "I have an enterprise security team".

AEGIS is a single binary + frontend that fills that gap. It owns your firewall, runs honeypots, watches your logs, and fires 134 Sigma rules + 6 chain detections in real time. When it sees an attack it auto-blocks (pfctl/iptables), runs guardrailed playbooks (auto_approve / require_approval / never_auto), and emits a structured incident.

**What v1.6 adds**

The previous release (v1.5 "Autonomous Edge") shipped the deterministic core — 122 in-code rules moved to a YAML rule pack, an AI mode flag with full fallback paths, real firewall execution. v1.6 makes ransomware a first-class concern:

1. **Server-side detection (R-A)** — 12 ransomware Sigma rules + 1 kill-chain. Engine `_matches_filter` was extended to honor `_regex` suffix on filter keys, mirroring the existing `_gt` convention. Rules cover the full ransomware lifecycle: LOLBin staging → shadow-delete → encryption → ransom note → lateral movement.

2. **Threat intel (R-B)** — `RaaSIntel` service pulls from RansomLook + CISA every 6 h, normalizes per-group payloads (aliases, C2, onion, extensions, notes), persists to `app/data/raas/*.json`. Network failures swallow + log. Cache survives restarts.

3. **Recovery (R-C)** — `SnapshotManager` with platform providers (Mac tmutil / Linux btrfs/zfs / Windows VSS via Rust agent / Noop default). All subprocess calls argv-list, IP-injection-safe via `ipaddress.ip_address()` validation. `DecryptorLibrary` ships a 10-entry NoMoreRansom seed.

4. **Frontend + playbook (R-D)** — `solutions/ransomware-defense/` pack (manifest + 7-step playbook + canary SMB share + log parser). New `/dashboard/ransomware` route with three components: RecentEventsTable, RaaSGroupTimeline (recharts), DecryptorLookup.

5. **Endpoint agent (R-E)** — Rust workspace gets a `ransomware/` module: canary watcher (notify), entropy classifier (≥50 writes/s + ≥7.5 bits/byte sliding window), kill-chain process killer with forensic snapshot before SIGKILL/TerminateProcess, rollback wrapper (gated by `AEGIS_REAL_RECOVERY=1`), self-protect (`prctl(PR_SET_DUMPABLE,0)` on linux, `SetProcessMitigationPolicy` on windows).

6. **Test harness (R-F)** — Rust emulator generates 100 dummy files in tempdir, XOR + entropy-pads them, drops a ransom note. Python e2e test runs the agent against the emulator under `AEGIS_LIVEFIRE=1`, asserts kill within 500 ms, asserts incident reaches the API, asserts chain rule fires, asserts recovery options return ≥1 snapshot, asserts synthetic C2 IP gets auto-blocked.

156 tests green (125 Python + 21 Rust + 10 gated e2e). Frontend builds clean. Cargo + clippy green.

**The build process is part of the story**

I built v1.6 in a single session by:
- Writing the spec via the brainstorming skill
- Generating a detailed plan via the writing-plans skill
- Dispatching 4 Sonnet sub-agents in parallel — one per phase — with strict file-ownership boundaries
- Coordinating from an Opus controller that handled engine fixes (e.g. the `_regex` filter support that 5 of 6 agents implicitly needed) and the merge/tag/release flow

Total wall-clock: ~6 hours including 5 release.yml/Dockerfile fix iterations. Zero merge conflicts. The plan, the agent prompts, and the file-ownership decisions were the load-bearing work — once those were right, the agents just shipped.

**Try it**

```bash
git clone https://github.com/alejadxr/AEGIS && cd AEGIS
docker compose up -d
# dashboard at localhost:3007
```

Or grab the desktop binary for your OS from the release page.

Repo: https://github.com/alejadxr/AEGIS
Release: https://github.com/alejadxr/AEGIS/releases/tag/v1.6.0
Docker: `ghcr.io/alejadxr/aegis/aegis-api:1.6.0` and `:aegis-frontend:1.6.0`

Apache-2.0. Roadmap in the repo (federation, SOC2/ISO evidence exports, hosted edition).

Happy to answer questions about the architecture, the deterministic-first decision, the multi-agent build process, or anything else.

---

## NEWSLETTER (somoswilab.com / Substack — short + visual)

**Subject**: AEGIS v1.6 ships — autonomous ransomware defense, end to end

Hey,

Quick update: AEGIS v1.6 is out.

This release closes every ransomware-defense gap from v1.5: 12 new Sigma rules + a kill-chain detection, a RaaS threat intel feed (RansomLook + CISA, refreshed every 6 h), recovery orchestration (snapshot restore + decryptor lookup), a dedicated dashboard route, a hardened Rust endpoint agent, and a livefire emulation harness for repeatable end-to-end testing.

156 tests green. Desktop binaries for macOS, Windows, Linux on the [release page](https://github.com/alejadxr/AEGIS/releases/tag/v1.6.0). Docker images on GHCR.

Deterministic-first stays — `AEGIS_AI_MODE=offline` and the whole stack runs without an LLM call.

If you've been waiting for ransomware coverage, now's the time.

— Diego

---

## VISUAL NOTES (for whoever ships the post)

- Hero image: dashboard `/dashboard/ransomware` screenshot in dark mode, 1600x900, with the RaaS group timeline visible.
- Secondary: a terminal showing the livefire emulator getting killed within ~300 ms (gif preferred).
- Tertiary: code snippet of the Sigma rule for `ransomware_chain` — operators love seeing the actual rule.

Avoid:
- Stock cyber imagery (red lock icons, code-rain, Anonymous masks).
- AI-generated "futuristic SOC" mockups.
- Marketing over-promises ("ransomware-proof", "zero FP", "AI-powered").

---

## POST-LAUNCH DELTAS (optional thread additions)

If you post a few days after the release, you can append a follow-up tweet / Reddit comment with the post-launch additions:

> Update since v1.6.0 shipped:
>
> - 🆕 **Google Gemini provider** added (`gemini-flash-lite-latest` default) — opt-in via `GEMINI_API_KEY`, joins the existing OpenRouter / Inception / Anthropic / OpenAI / Ollama lineup. Cheap+fast for hot-path enrichment, still optional.
> - 🆕 **SEO/GEO pass** — README rewritten with FAQ + comparison table + JSON-LD schema; new `docs/seo/` cluster (what-is-aegis, ransomware-defense, comparison); `.well-known/llms.txt` for LLM discovery; frontend metadata with Open Graph + Twitter Card + structured data.
>
> Same Apache-2.0 / AGPL-3.0 (per LICENSE), same `docker compose up` to run. No breaking changes.
