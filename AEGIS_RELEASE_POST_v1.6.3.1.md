# AEGIS v1.6.3.1 — Retro ASCII Map + UA Safelist + Durable FP Gate

**Released:** 2026-06-23 (patch) · [Download](https://github.com/alejadxr/AEGIS/releases/tag/v1.6.3.1) · [CHANGELOG](https://github.com/alejadxr/AEGIS/blob/main/CHANGELOG.md#1631---2026-06-23-patch)

> Operator-facing UX + false-positive-reduction patch on top of v1.6.3. Same evening, no breaking changes. Three things shipped: a retro ASCII threat map that replaces the SVG, a 30-entry User-Agent safelist for crawlers without stable IPs, and a durable fix that stops cosmetic FP purges from recurring every 5 minutes.

---

## TL;DR

- **Retro ASCII world map** replaces `react-simple-maps`. 84×22 monospace ASCII art world with absolutely-positioned coloured threat markers, pulsing on the top severity tier, CRT scanline overlay. ~38 KB lighter dashboard bundle.
- **BENIGN_UAS safelist** — 30 known-good crawler/monitor User-Agents (Discordbot, Vercelbot, Pingdom, UptimeRobot, Censys, BitSight, Archive.org, etc.) now bypass detection entirely. Hooks both the FastAPI middleware and the `log_watcher` line filter.
- **AEGIS_SAFE_IPS expanded from 17 → 133 CIDRs** (2 094 chars) covering 25+ monitoring/scanner/crawler services researched by 4 parallel Sonnet agents (~1.1 M tokens).
- **Durable safelist gate on firewall_sync** — `_sync_blocked_ips()` now refuses to insert safelisted IPs into `threat_intel`, killing the FP-purge-recurrence loop that the v1.6.2 audit predicted.
- **Threat Detection chart** now shows a full 7-day window (`?since=7d`) instead of just today + yesterday.

---

## The ASCII map

The dashboard's `GlobalThreatMap` was a `react-simple-maps` SVG with 50 KB of world topojson + a custom scanline overlay. v1.6.3.1 replaces it with a pure-CSS ASCII version:

```
       ,_      ,,,,,,,,,,                       __
    ,;~  ~~~,,,        ~~,,            ,,~~,,~~~  ~~,_      ~~,    ~~_  _,
  ,~              ~~~,_   ~,_       ,~~              ~,,_  ,~ ~~~~~  ~~ ~ ,_
,~                    ~~_  ~~~~~~~~~                    ~~~~          ~~_  ~_
~                       ~_          ,;~~~,~~~      _,,~~       ___       ~_  ~,
 ~,                      ~          ;     `   ,~~~~,_  ~~,_,~~~   ~~~~_    `~_~_
   ...
```

Threat dots are absolutely positioned over the `<pre>` block at the (col, row) centroid of each ISO-3166 country. Severity colours: cyan (`<33 %` of peak), orange (`33–66 %`), red (`>66 %`, pulses). Bottom-right legend shows top-8 countries plus a `N CN · M ATK` summary. CRT scanline overlay applied to the whole panel. Renders identically at any zoom level because there's no SVG to scale.

Internal trade-off: country positions are approximated centroids on an 84-column canvas, so two countries that share a row appear as overlapping dots. Acceptable for the dashboard SOC use-case where you care about "is there activity in $REGION" more than precise placement.

---

## BENIGN_UAS — User-Agent based safelist

CIDRs solve half the false-positive problem. The other half is bots that publish their User-Agent but rotate IPs across cloud providers (Discordbot, Slackbot, Vercelbot, Inoreader, Mastodon federation, etc.). Or bots with so many individual IPs that listing them is impractical (DuckDuckBot, 381 individual /32s).

v1.6.3.1 adds `BENIGN_UAS` — a frozenset of ~30 known-good UA substrings checked in two places:

1. **`attack_detector.py` middleware** — between `_is_safe_ip()` and `_check_scanner_ua()`. If the UA matches, the request returns straight to `call_next` with zero tracking. Same effect as if the source IP were safelisted.
2. **`log_watcher._is_internal_line()`** — extracts the last quoted segment of `[HTTP] METHOD PATH STATUS IP "UA"` log lines. Matching lines are treated as internal so no detection patterns fire.

Coverage (defaults, extended by `AEGIS_BENIGN_UAS=...,...` env var):

| Category | UAs |
|---|---|
| Search engines | DuckDuckBot, YandexBot (web/images/video/news), Baiduspider, Sogou (3), 360Spider/HaoSouSpider, Yeti (Naver), CCBot, SeznamBot, Applebot, Googlebot, Bingbot/MSNBot/AdIdxBot, Twitterbot, LinkedInBot, facebookexternalhit (Meta + WhatsApp), FacebookCatalog |
| Social/messaging unfurl | Discordbot, Slackbot (incl. Slackbot-LinkExpanding), TelegramBot, Mastodon/Akkoma, Vercelbot, Qwantbot |
| RSS readers | Feedly/FeedlyBot, NewsBlur, Inoreader |
| Uptime / monitoring | Pingdom, UptimeRobot, Better Uptime (BetterStack), Checkly, FreshpingBot, DatadogSynthetics, NewRelic-Synthetics |
| Self-identifying scanners | CensysInspect, BitSightBot, archive.org_bot, Shadowserver |

E2E test on production: request with `Twitterbot/1.0` UA from a fresh public IP returns 200 with zero detection events. Control request from the same IP with `sqlmap/1.7.2` UA still triggers `scanner_detect` WARNING. Both expected.

---

## AEGIS_SAFE_IPS expansion

Four parallel Sonnet agents researched published IP CIDRs for legitimate scanners/crawlers/monitors. Combined output (deduplicated + range-collapsed):

| Category | CIDRs added | Highlights |
|---|---:|---|
| Uptime/monitoring | ~46 | Pingdom (8), UptimeRobot (5), BetterStack (13), Datadog Synthetics, New Relic, Checkly, Freshping (11) |
| Security scanners | ~43 | Censys (16), Shodan (8 registered netblocks), Rapid7 Project Sonar (5), Shadowserver (9), BitSight (5) |
| Search/social crawlers | 24 | Applebot (12), Telegram (9, from `core.telegram.org/resources/cidr.txt`), Archive.org (2), Qwantbot (1) |
| Audit-discovered gaps | 2 | `192.178.0.0/15` (Googlebot's newer block, not in 66.249/16), `52.167.144.0/24` (Bingbot's Azure block) |

Total: **17 → 133 CIDRs (2 094 chars)** in the `AEGIS_SAFE_IPS` env value.

Plus a one-shot `DELETE FROM threat_intel WHERE source='firewall' AND ioc_value IN (...)` — 18 PTR-verified FPs removed (5 Googlebot + 4 Bingbot + 9 Twitter/X). Tor exits explicitly excluded.

---

## The durable fix that mattered most

The v1.6.2 audit predicted that **every cosmetic SQL purge would recur on the next firewall_sync cycle (every 5 minutes)** because `_sync_blocked_ips()` ingested IPs from the Pi without consulting `AEGIS_SAFE_IPS`. v1.6.3.1 closes that loop:

```python
# v1.6.4 [SHIPPED IN v1.6.3.1]: gate threat_intel writes against AEGIS_SAFE_IPS
from app.core.attack_detector import _is_safe_ip

for ip in blocked:
    if _is_safe_ip(ip):
        skipped_safe += 1
        continue
    # ... existing insert/upsert logic ...
```

Telemetry adds a `skipped_safe` counter to the `_pull_blocklist_from_pi` return dict so operators can see how many crawler/monitor IPs the gate is catching per cycle.

---

## Threat Detection chart — full week

Before v1.6.3.1, the dashboard's gradient-area Threat Detection chart only showed today + yesterday because `api.response.incidents()` defaulted to `limit=100` and on a busy day all 100 most-recent rows fell within today.

Now: backend accepts `?since=24h|7d|30d|all`. Frontend dashboard passes `{ since: '7d', limit: 10000 }`. Chart fills the full 7-day window. Verified on production: 1 765 rows returned for the active 7-day window.

---

## Links

- **Release page:** https://github.com/alejadxr/AEGIS/releases/tag/v1.6.3.1
- **Full CHANGELOG:** https://github.com/alejadxr/AEGIS/blob/main/CHANGELOG.md
- **Source diff:** https://github.com/alejadxr/AEGIS/compare/v1.6.3...v1.6.3.1

Upgrade path from v1.6.3: `git pull && pm2 restart cayde6-api cayde6-frontend`. No new required env vars. Optional: `AEGIS_BENIGN_UAS=foo,bar` to extend the User-Agent safelist beyond defaults.
