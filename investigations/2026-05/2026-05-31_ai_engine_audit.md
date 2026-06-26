# AI Engine Audit — 2026-05-31 (last 72h)

## Configuration

- **AI mode:** `full` (`AEGIS_AI_MODE=full`)
- **Providers with keys:** OpenRouter, Inception
- **No keys configured:** OpenAI, Anthropic, Gemini, VirusTotal, OTX
- **Currently quarantined:** None detected. No quarantine events in PM2 logs.
- **Active route:** Triage → `openrouter:google/gemma-4-26b-a4b-it:free` → Classification → `openrouter:meta-llama/llama-3.3-70b-instruct:free`
- **OpenAI stub risk:** Zero — no OpenAI key configured, and no "OpenAI API key not configured" stub leaks found (0 incidents).

---

## Triage / Classification Coverage

| Metric | Count | % of 1,400 total |
|---|---|---|
| Total incidents (72h) | 1,400 | 100% |
| Full agent analysis (triage + classification) | 719 | **51.4%** |
| Fast-triage only (algorithm, no AI analysis) | 681 | **48.6%** |
| Stub error leaks ("OpenAI API key not configured") | 0 | 0% |

**Pattern:** The pipeline runs a fast-triage path (algorithm, ~50ms) first, then asynchronously spawns a full AI analysis. This means roughly half the incidents in the snapshot only have a fast-triage record because the full analysis fires on a second incident record. This is intentional architecture — it is not a coverage bug.

**Within the 719 agent-analysed incidents:**
- Triage model: `google/gemma-4-26b-a4b-it:free` (100%)
- Classification model: `meta-llama/llama-3.3-70b-instruct:free` (100%)
- No other models observed; Inception key is configured but not currently routing traffic.

---

## Triage Quality

- **Summaries with generic stub text** ("Security alert received"): **104 / 719** (14.5%)
  - These fire when Gemma receives an ambiguous or partially-formed prompt and falls back to a default.
  - Example incident: `8a2b96e5` (2026-05-31 16:21:09)
  - The triage provenance still shows `kind: agent`, so it is not counted as a failure by the stats query, but content is useless.
- **Rich summaries (>= 50 chars, specific threat type):** ~615 / 719 (85.5%)
  - Example: *"Multiple failed SSH authentication attempts detected from IP 148.0.72.76, indicating a brute force attack targeting SSH credentials. The correlation engine flagged the activity as a high-severity incident."* (205 chars)
  - MITRE mappings correct: T1110.001 / Credential Access consistently applied.
  - Confidence field: "high" in good summaries, 0.5 in stubs — a reliable signal for filtering.

---

## Classification Quality

- **Fully rich classification** (structured attack_vector + impact + recommended_actions): **598 / 719** (83.2%)
  - Llama-3.3-70b produces 5–8 specific remediation steps, MITRE technique references, and business impact assessments when it has context.
- **Stub classification** (attack_vector: "unknown", impact: "unknown", empty recommended_actions): **121 / 719** (16.8%)
  - These co-occur heavily with the 104 generic triage summaries — Llama receives a weak triage context and cannot classify.
  - Example incident: `53845465` (2026-05-31 16:30:50) — triage is good but classification is stub (confidence: 0.5).
  - Example incident: `dbdeff4d` (2026-05-31 16:35:29) — same pattern: Gemma produced a valid triage, Llama returned a stub.

---

## Latency + Cost

| Metric | Value |
|---|---|
| Triage-to-classification avg | **15,713 ms (15.7s)** |
| p50 | 15,685 ms |
| p95 | 29,700 ms |
| Fast-triage (algo path) elapsed | ~49–55 ms |
| Tokens tracked | Not stored — no `tokens_used` or `cost_usd` fields in ai_analysis |
| Cost tracking | Not implemented |

**Critical finding:** The avg end-to-end AI pipeline takes ~15.7 seconds and p95 hits 30 seconds. These are free-tier OpenRouter models with rate limits and variable queue depth. There are no timeout failures visible (no quarantine events), but at this latency the AI analysis arrives well after the fast-triage has already fired and actions have been taken. AI analysis is post-hoc enrichment, not real-time decision input.

---

## IP Threat Brief Quality

- **`ip_intel.ai_summary` field:** NULL in all incidents. No AI-generated prose briefs for IPs.
- **What is present:** Structured GeoIP + reputation data from 9 providers (ipapi.is, proxycheck, ipquery, ipinfo, ipapi, geojs, ipguide, greynoise, dbip_offline). The `ip_intel` block is rich and algorithm-generated — but there is no prose narrative layer on top of it.
- **Observation:** GreyNoise data is present (`greynoise_seen: false`) but the `ai_summary` key is never populated. This field appears to be reserved for a future AI enrichment step that has not been implemented or wired up.

---

## Failure Modes Found

### Bug 1 — Gemma stub triage (14.5% rate)
- **Incident examples:** `8a2b96e5`, `6f26e4f3`, `e2d2f3af`, `c62eb3da`, `de5c6b36`
- Gemma returns `summary: "Security alert received"`, `threat_type: "unknown"`, empty MITRE fields.
- Provenance still shows `kind: agent` — the agent ran but produced content-empty output.
- Root cause: likely the prompt contains insufficient event context when the correlation engine fires before log enrichment completes, or Gemma is throttled and returns a minimal response.

### Bug 2 — Llama stub classification (16.8% rate)
- **Incident examples:** `53845465`, `dbdeff4d`, `2526e276`
- Llama receives a valid triage context but returns `attack_vector: "unknown"`, `impact: "unknown"`, `recommended_actions: []`, `confidence: 0.5`.
- Pattern: happens independently of whether triage was a stub — Llama stubs even when Gemma produced a good triage (incident `53845465`: good triage, stub classification).
- This is the more serious failure — Llama is the classification model and its output is the primary analyst-facing artifact.

### Bug 3 — No IP AI brief implemented
- `ip_intel.ai_summary` is never populated despite the field being referenced in the data schema.
- GreyNoise context (seen/not seen, tags) and abuse scores are available but not synthesized into prose.

### Bug 4 — Latency exceeds usefulness threshold for real-time response
- p95 at ~30s means the AI analysis arrives after the fast-triage has already executed actions. This is acceptable if AI analysis is only for human review, but the 30s tail is near standard HTTP gateway timeouts.
- No timeout-cliff failures observed, but the Inception key (which may route to faster models) is unused.

---

## Verdict

**AI engine is: MARGINAL → PRODUCTIVE**

The engine is genuinely producing content for 51.4% of incidents (719 full analyses), and within those, 83-85% have substantive prose with correct MITRE mappings, specific remediation steps, and structured impact assessments. This is real analyst value, not decoration. However, 14-17% stub rates on both triage and classification reduce reliability, and the 15.7s average latency (30s p95) means AI output is always post-hoc.

**Best provider+model combo:**
- Triage: `openrouter:google/gemma-4-26b-a4b-it:free` — correct 85.5% of the time, fast enough
- Classification: `openrouter:meta-llama/llama-3.3-70b-instruct:free` — rich output when it works, but 16.8% stub rate

**Top 3 fixes to land more agent provenance and quality:**

1. **Fix Llama stub classification (Bug 2 — highest impact):** Add a retry with simplified prompt when `attack_vector == "unknown"` and `confidence < 0.6`. The 121 stub classifications likely result from a JSON parsing failure or context-window edge — a fallback prompt with explicit JSON schema enforcement would recover most of them.

2. **Route Inception key or add a paid OpenRouter tier for classification:** Free-tier Llama-3.3-70b has variable queue depth causing the 30s p95. Routing classification through Inception (already keyed) or a paid OpenRouter model would cut latency below 5s and reduce stub rate from timeout-induced failures.

3. **Implement `ip_intel.ai_summary` population (Bug 3):** Wire the existing GreyNoise + ipapi.is abuse data into a brief prompt (one sentence: seen/not seen, abuse score, ASN type). This requires minimal tokens and adds the most missing analyst-facing value — right now the IP block has rich structured data with no narrative summary.
