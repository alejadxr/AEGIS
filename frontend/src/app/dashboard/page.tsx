'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '@/lib/api';
import { subscribeTopic } from '@/lib/ws';

import { CommandBar, type TimeWindow } from '@/components/dashboard/CommandBar';
import { VerdictLine } from '@/components/dashboard/VerdictLine';
import { TriageQueue, type TriageIncident, type TriagePendingAction } from '@/components/dashboard/TriageQueue';
import { WatchPanel, type WatchPanelApp } from '@/components/dashboard/WatchPanel';
import { OriginMap, type OriginMapEntry } from '@/components/dashboard/OriginMap';
import { AssetRiskPanel, type AssetRiskItem, type RiskBand, type AssetExposure } from '@/components/dashboard/AssetRiskPanel';
import { Ledger, type LedgerEntry } from '@/components/dashboard/Ledger';

/**
 * Dashboard — Command Center.
 *
 * Six bands (CommandBar is full-bleed outside the grid; VerdictLine,
 * TriageQueue/WatchPanel, OriginMap, AssetRiskPanel and Ledger share one
 * 12-col grid):
 *   0. CommandBar    — sticky instrument strip + first-run strip
 *   1. VerdictLine   — the one display-size sentence, the 3am answer
 *   2. TriageQueue (8) / WatchPanel (4) — the hero + the evidence rail
 *   3. OriginMap     — full-width world map + SourceRank + ASN attribution
 *   4. AssetRiskPanel — full attack-surface inventory (distribution + top risk)
 *   5. Ledger        — chronological incident/audit log
 *
 * No component in this tree fetches its own list data (IncidentDossier is
 * the sole exception — it fetches its own detail on expand). Every band is
 * pure props-in, mirroring the ten-call Promise.allSettled below so a
 * single endpoint failure degrades only its own panel.
 */

// ---------------------------------------------------------------------------
// Raw wire types — mirrored from lib/api.ts (Overview/Incident/Action) or,
// for /dashboard/timeline, from the ACTUAL backend response model
// (backend/app/api/dashboard.py TimelineEvent). TimelineEvent gained
// description/module/decision/confidence/model_used/linked_incident_id/
// navigable in this change. Fetched directly via api.get() with an explicit
// ?limit= because api.dashboard.timeline() takes no parameters and the
// backend default of 50 (25 incidents + 25 audit rows) is too easily
// starved once FP-titled incidents are stripped client-side below.
// ---------------------------------------------------------------------------

type Overview = Awaited<ReturnType<typeof api.dashboard.overview>>;
type RawIncident = Awaited<ReturnType<typeof api.response.incidents>>[number];
type RawAction = Awaited<ReturnType<typeof api.response.actions>>[number];
type MonitoredAppsResponse = Awaited<ReturnType<typeof api.dashboard.monitoredApps>>;
type ThreatMapResponse = Awaited<ReturnType<typeof api.dashboard.threatMap>>;
type FirewallBlocked = Awaited<ReturnType<typeof api.firewall.blocked>>;
type FirewallStats = Awaited<ReturnType<typeof api.firewall.stats>>;
type AssetsResponse = Awaited<ReturnType<typeof api.surface.assets>>;
type HoneypotsResponse = Awaited<ReturnType<typeof api.phantom.honeypots>>;

interface RawTimelineEvent {
  id: string;
  type: string;
  title: string;
  description: string | null;
  severity: string | null;
  module: string | null;
  timestamp: string;
  decision: string | null;
  confidence: number | null;
  model_used: string | null;
  linked_incident_id: string | null;
  navigable: boolean;
}

// ---------------------------------------------------------------------------
// Asset risk wire type — the backend's `/surface/assets` scorer is now the
// deterministic, service-aware model (service_weighted_v1): `ports` is an
// object array (was number[]) and the response carries the full risk
// breakdown (risk_band/risk_method/risk_ai_used/exposure/
// exposure_multiplier/base_score/vuln_term/risk_drivers/service_classes/
// host_wide_count/owned_count). lib/api.ts's `surface.assets()` wrapper
// already returns this exact shape (kept in sync with AssetRiskPanel.tsx's
// AssetRiskItem/AssetRiskPort/AssetRiskDriver/AssetServiceClass), so
// `AssetsResponse[number]` is used directly below with no widening/
// Partial<> — a real backend contract, not a defensive guess.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Severity normalization — explicit allow-list, never template-literal
// interpolation, matching the SEV_VAR convention already established in
// Ledger.tsx / TriageQueue.tsx / OriginMap.tsx. An unrecognised or missing
// severity string must never reach a component typed to the 5-key union.
// ---------------------------------------------------------------------------

type SevKey = 'critical' | 'high' | 'medium' | 'low' | 'info';
const SEV_KEYS: readonly SevKey[] = ['critical', 'high', 'medium', 'low', 'info'];

function severityKey(sev: string | null | undefined): SevKey {
  const lower = (sev ?? '').toLowerCase();
  return (SEV_KEYS as readonly string[]).includes(lower) ? (lower as SevKey) : 'info';
}

function severityKeyOrNull(sev: string | null | undefined): SevKey | null {
  return sev ? severityKey(sev) : null;
}

// ---------------------------------------------------------------------------
// Window filter — /dashboard/timeline has no server-side `since` param (only
// `limit`), so the CommandBar/Ledger time-window control is applied
// client-side against the already-fetched 200-row page. Backend datetimes
// are naive UTC without a trailing Z (documented gotcha in lib/utils.ts);
// normalize the same way formatRelativeTime does before parsing.
// ---------------------------------------------------------------------------

const WINDOW_DAYS: Record<TimeWindow, number> = { '24h': 1, '7d': 7, '30d': 30 };

// Module-scope (not per-render) so the assetRiskItems useMemo below never
// needs to list them as dependencies — narrows a live backend response's
// risk_band/exposure strings to their literal unions rather than casting.
const RISK_BANDS: readonly RiskBand[] = ['contained', 'watch', 'elevated', 'exposed', 'critical'];
const ASSET_EXPOSURES: readonly AssetExposure[] = ['local', 'lan', 'tailnet', 'public', 'unknown'];

function withinWindow(iso: string, win: TimeWindow): boolean {
  const normalized = iso.endsWith('Z') || iso.includes('+') ? iso : `${iso}Z`;
  const ms = Date.parse(normalized);
  if (Number.isNaN(ms)) return true; // never hide on a parse failure
  return Date.now() - ms <= WINDOW_DAYS[win] * 86400_000;
}

/** Backend emits naive UTC datetimes without a trailing Z — normalize before
 * parsing, matching the convention already used throughout this tree
 * (formatRelativeTime, Ledger.toDate, AssetRiskPanel.toUtcMillis). */
function toUtcMillis(iso: string): number {
  const normalized = iso.endsWith('Z') || iso.includes('+') ? iso : `${iso}Z`;
  return Date.parse(normalized);
}

export default function DashboardPage() {
  const [timeWindow, setTimeWindow] = useState<TimeWindow>('7d');
  const [refreshKey, setRefreshKey] = useState(0);

  const [overview, setOverview] = useState<Overview | null>(null);
  const [overviewError, setOverviewError] = useState(false);

  const [incidentsRaw, setIncidentsRaw] = useState<RawIncident[] | null>(null);
  const [incidentsError, setIncidentsError] = useState(false);

  // No dedicated UI surface exists for "actions failed to load" (TriageQueue's
  // `error` prop is documented as scoped to response.incidents() only), so a
  // failed fetch here degrades to an empty pending-actions list rather than
  // tracking a boolean nothing would ever read.
  const [actionsRaw, setActionsRaw] = useState<RawAction[] | null>(null);

  const [threatMapData, setThreatMapData] = useState<ThreatMapResponse | null>(null);
  const [threatMapError, setThreatMapError] = useState(false);

  const [monitoredAppsData, setMonitoredAppsData] = useState<MonitoredAppsResponse | null>(null);
  const [monitoredAppsError, setMonitoredAppsError] = useState(false);

  const [timelineRaw, setTimelineRaw] = useState<RawTimelineEvent[] | null>(null);
  const [timelineError, setTimelineError] = useState(false);

  const [firewallBlocked, setFirewallBlocked] = useState<FirewallBlocked | null>(null);
  const [firewallBlockedError, setFirewallBlockedError] = useState(false);

  const [firewallStats, setFirewallStats] = useState<FirewallStats | null>(null);
  const [firewallStatsError, setFirewallStatsError] = useState(false);

  const [assetsData, setAssetsData] = useState<AssetsResponse | null>(null);
  const [assetsError, setAssetsError] = useState(false);

  const [honeypotsData, setHoneypotsData] = useState<HoneypotsResponse | null>(null);
  const [honeypotsError, setHoneypotsError] = useState(false);

  // ── Initial load + refresh (WS events / mutations bump refreshKey) ──────
  useEffect(() => {
    let mounted = true;

    async function load() {
      const [ov, inc, act, tm, apps, tl, fwBlocked, fwStats, assets, honeypots] = await Promise.allSettled([
        api.dashboard.overview(),
        // Fixed 7d/50 window regardless of the CommandBar/Ledger time-window
        // control — TriageQueue must always show the true current backlog,
        // not a slice the operator could accidentally window out. /response/
        // incidents already excludes [FP-titled rows server-side by default
        // (include_fp=false) — the client-side filter below is defense in
        // depth, not the primary filter.
        api.response.incidents({ since: '7d', limit: 50 }),
        api.response.actions(),
        // /dashboard/threat-map already excludes [FP- rows server-side —
        // must NOT be re-filtered here.
        api.dashboard.threatMap(),
        api.dashboard.monitoredApps(),
        api.get<RawTimelineEvent[]>('/dashboard/timeline?limit=200'),
        api.firewall.blocked(),
        api.firewall.stats(),
        api.surface.assets(),
        api.phantom.honeypots(),
      ]);
      if (!mounted) return;

      if (ov.status === 'fulfilled') { setOverview(ov.value); setOverviewError(false); }
      else setOverviewError(true);

      if (inc.status === 'fulfilled') { setIncidentsRaw(inc.value); setIncidentsError(false); }
      else setIncidentsError(true);

      if (act.status === 'fulfilled') setActionsRaw(act.value);
      else setActionsRaw((prev) => prev ?? []);

      if (tm.status === 'fulfilled') { setThreatMapData(tm.value); setThreatMapError(false); }
      else setThreatMapError(true);

      if (apps.status === 'fulfilled') { setMonitoredAppsData(apps.value); setMonitoredAppsError(false); }
      else setMonitoredAppsError(true);

      if (tl.status === 'fulfilled') { setTimelineRaw(tl.value); setTimelineError(false); }
      else setTimelineError(true);

      if (fwBlocked.status === 'fulfilled') { setFirewallBlocked(fwBlocked.value); setFirewallBlockedError(false); }
      else setFirewallBlockedError(true);

      if (fwStats.status === 'fulfilled') { setFirewallStats(fwStats.value); setFirewallStatsError(false); }
      else setFirewallStatsError(true);

      if (assets.status === 'fulfilled') { setAssetsData(assets.value); setAssetsError(false); }
      else setAssetsError(true);

      if (honeypots.status === 'fulfilled') { setHoneypotsData(honeypots.value); setHoneypotsError(false); }
      else setHoneypotsError(true);
    }

    load();
    return () => { mounted = false; };
  }, [refreshKey]);

  // ── Live WS: soft re-pull on incident/action/honeypot events ────────────
  useEffect(() => {
    const offIncidents = subscribeTopic('incidents.new', () => setRefreshKey((k) => k + 1));
    const offActions = subscribeTopic('actions.new', () => setRefreshKey((k) => k + 1));
    const offHoneypot = subscribeTopic('honeypot.interactions', () => setRefreshKey((k) => k + 1));
    return () => {
      offIncidents();
      offActions();
      offHoneypot();
    };
  }, []);

  const handleRefresh = useCallback(() => setRefreshKey((k) => k + 1), []);

  const handleApprove = useCallback(async (actionId: string) => {
    await api.response.approveAction(actionId);
    handleRefresh();
  }, [handleRefresh]);

  const handleReject = useCallback(async (actionId: string, reason?: string) => {
    await api.response.rejectAction(actionId, reason);
    handleRefresh();
  }, [handleRefresh]);

  // ── Derived data ──────────────────────────────────────────────────────
  // MANDATORY DEFENSIVE FILTER — /response/incidents already excludes
  // [FP-titled rows by default, but this line must never be removed: it is
  // the only thing standing between the operator and 1741 incidents from
  // their own device (179.52.12.148, tagged "[FP-USER-DEVICE-179]") if the
  // backend default is ever flipped.
  const clean = useMemo(
    () => (incidentsRaw ?? []).filter((i) => !i.title.startsWith('[FP-')),
    [incidentsRaw],
  );

  // VerdictLine's count and TriageQueue's list are derived from this SAME
  // array so the headline and the queue can never contradict each other.
  const openIncidents = useMemo(
    () => clean.filter((i) => ['open', 'investigating'].includes((i.status || '').toLowerCase())),
    [clean],
  );

  const pendingActions = useMemo(
    () => (actionsRaw ?? []).filter((a) => (a.status || '').toLowerCase() === 'pending'),
    [actionsRaw],
  );

  const lastIncidentAt = clean[0]?.detected_at ?? null;

  const triageIncidents: TriageIncident[] = useMemo(
    () => openIncidents.map((i) => ({
      id: i.id,
      title: i.title,
      severity: severityKey(i.severity),
      status: i.status,
      source: i.source ?? null,
      source_ip: i.source_ip,
      mitre_technique: i.mitre_technique,
      mitre_tactic: i.mitre_tactic,
      detected_at: i.detected_at,
    })),
    [openIncidents],
  );

  const triagePendingActions: TriagePendingAction[] = useMemo(
    () => pendingActions.map((a) => ({
      id: a.id,
      incident_id: a.incident_id,
      action_type: a.action_type,
      target: a.target ?? null,
      status: a.status,
      created_at: a.created_at,
    })),
    [pendingActions],
  );

  // Same defensive filter applied to the ledger — /dashboard/timeline does
  // NOT exclude [FP- rows server-side (unlike /response/incidents and
  // /dashboard/threat-map), so this one is load-bearing, not redundant.
  const cleanTimeline = useMemo(
    () => (timelineRaw ?? []).filter((e) => !(e.type === 'incident' && e.title.startsWith('[FP-'))),
    [timelineRaw],
  );

  const ledgerEntries: LedgerEntry[] = useMemo(
    () => cleanTimeline
      .filter((e) => withinWindow(e.timestamp, timeWindow))
      .map((e) => ({
        id: e.id,
        type: e.type,
        title: e.title,
        description: e.description,
        severity: severityKeyOrNull(e.severity),
        timestamp: e.timestamp,
        module: e.module,
        decision: e.decision,
        confidence: e.confidence,
        model_used: e.model_used,
        linked_incident_id: e.linked_incident_id,
        navigable: e.navigable,
      })),
    [cleanTimeline, timeWindow],
  );

  const lastEventAt = cleanTimeline[0]?.timestamp ?? null;

  const monitoredApps: WatchPanelApp[] = monitoredAppsData?.apps ?? [];

  // Firewall/enforcement derivations — null means "we could not ask", never
  // collapsed into a fake 0. See WatchPanelProps docblock.
  const blockedIps = firewallBlocked ? firewallBlocked.items.map((i) => i.ip) : null;
  const blockedIpsNow = firewallBlocked ? firewallBlocked.count : null;
  const piReachable = firewallBlocked ? firewallBlocked.pi_reachable : null;
  const realFirewallActive = firewallStats ? firewallStats.real_firewall_active : null;
  const actionsExecuted30d = overview ? overview.actions_taken : null;
  const firewallError = firewallBlockedError || firewallStatsError;

  const activeAssets = assetsData ? assetsData.filter((a) => a.status === 'active').length : null;
  const honeypotsRunning = honeypotsData ? honeypotsData.filter((h) => h.status === 'running').length : null;

  // max(assets[].last_scan_at) — the one honestly-derivable "last scan" the
  // approved call set can produce; null when no asset has ever been scanned.
  const lastScanAt = useMemo(() => {
    if (!assetsData) return null;
    let newest: string | null = null;
    let newestMs = -Infinity;
    for (const a of assetsData) {
      if (!a.last_scan_at) continue;
      const ms = toUtcMillis(a.last_scan_at);
      if (!Number.isNaN(ms) && ms > newestMs) {
        newestMs = ms;
        newest = a.last_scan_at;
      }
    }
    return newest;
  }, [assetsData]);

  const originMapData: OriginMapEntry[] = threatMapData ?? [];

  // Defensive defaults per field, never a fabricated value: 'contained' is
  // the lowest/safest risk band (never over-flag on a stale response),
  // count/array fields default to 0/[] so the panel can iterate without
  // crashing, and every other risk-provenance field is still defensively
  // guarded even though lib/api.ts's contract now declares them non-optional
  // — a live backend response is never guaranteed to match its TS type, so
  // `risk_band`/`exposure` are narrowed to their literal unions (falling
  // back to the lowest/safest values, 'contained'/null) rather than cast.
  const assetRiskItems: AssetRiskItem[] = useMemo(
    () => (assetsData ?? []).map((a) => ({
      id: a.id,
      hostname: a.hostname,
      ip_address: a.ip_address,
      asset_type: a.asset_type,
      ports: a.ports ?? [],
      technologies: a.technologies ?? [],
      status: a.status,
      risk_score: a.risk_score,
      last_scan_at: a.last_scan_at,
      risk_band: (RISK_BANDS as readonly string[]).includes(a.risk_band)
        ? (a.risk_band as RiskBand)
        : 'contained',
      risk_method: a.risk_method ?? null,
      risk_ai_used: a.risk_ai_used ?? false,
      exposure: (ASSET_EXPOSURES as readonly string[]).includes(a.exposure)
        ? (a.exposure as AssetExposure)
        : null,
      exposure_multiplier: a.exposure_multiplier ?? null,
      base_score: a.base_score ?? null,
      vuln_term: a.vuln_term ?? null,
      risk_drivers: a.risk_drivers ?? [],
      service_classes: a.service_classes ?? [],
      host_wide_count: a.host_wide_count ?? 0,
      owned_count: a.owned_count ?? 0,
    })),
    [assetsData],
  );

  const homeAsn = process.env.NEXT_PUBLIC_AEGIS_HOME_ASN ?? null;

  // ── Per-panel loading flags — no single blanket spinner. Each band shows
  // its own skeleton on first paint and its own error state on failure. ──
  const overviewLoading = overview === null && !overviewError;
  const incidentsLoading = incidentsRaw === null && !incidentsError;
  const monitoredAppsLoading = monitoredAppsData === null && !monitoredAppsError;
  const threatMapLoading = threatMapData === null && !threatMapError;
  const timelineLoading = timelineRaw === null && !timelineError;
  const firewallBlockedLoading = firewallBlocked === null && !firewallBlockedError;
  const firewallStatsLoading = firewallStats === null && !firewallStatsError;
  const assetsLoading = assetsData === null && !assetsError;
  const honeypotsLoading = honeypotsData === null && !honeypotsError;

  // VerdictLine and CommandBar both read totalAssets/monitoredApps counts
  // sourced from overview() and monitoredApps() respectively — wait on both
  // (plus the firewall count VerdictLine's sub-line also reports) so none
  // ever flashes a zero/absent segment before the real numbers land.
  const verdictLoading = overviewLoading || incidentsLoading || monitoredAppsLoading || firewallBlockedLoading;
  const commandBarLoading = overviewLoading || monitoredAppsLoading;
  // WatchPanel renders all three of its regions (Enforcement/Coverage/Blind
  // Spots) behind one shared `loading` flag — wait on every call any region
  // reads so no region resolves ahead of its siblings.
  const watchPanelLoading =
    overviewLoading ||
    monitoredAppsLoading ||
    firewallBlockedLoading ||
    firewallStatsLoading ||
    assetsLoading ||
    honeypotsLoading;
  const apiOnline = !overviewError && overview !== null;

  return (
    <>
      {/* BAND 0 — COMMAND BAR + grid, ONE shared containing block.
          Full-bleed within <main>'s max-w-[1440px] container: negative
          margins cancel dashboard/layout.tsx's px-4/sm:px-6/lg:px-8 and
          py-6 so the sticky strip sits flush under TopNav instead of
          floating inset inside page padding. The grid re-applies that same
          horizontal padding to itself so its own content stays inset.
          CommandBar and the grid MUST share one wrapper: `position: sticky`
          can only "stick" while scrolling through its containing block, and
          a wrapper sized to CommandBar alone (the previous structure) gives
          it zero room to travel — it was verified via getBoundingClientRect
          to scroll away 1:1 with the page instead of pinning under TopNav. */}
      <div className="-mx-4 -mt-6 sm:-mx-6 lg:-mx-8">
        <CommandBar
          monitoredApps={monitoredAppsData?.count ?? 0}
          totalAssets={overview?.total_assets ?? 0}
          lastEventAt={lastEventAt}
          window={timeWindow}
          onWindowChange={setTimeWindow}
          loading={commandBarLoading}
          apiOnline={apiOnline}
        />

        <div className="grid grid-cols-12 gap-x-4 gap-y-6 px-4 pb-10 sm:px-6 lg:px-8">
        {/* BAND 1 — VERDICT LINE. Wrapped (rather than passing a className
            prop VerdictLine does not accept) so the mobile order swap below
            can move it without touching VerdictLine.tsx — mirrors the same
            wrap-for-grid-placement pattern already used for WatchPanel. */}
        <div className="col-span-12 max-lg:order-1 lg:order-none">
        <VerdictLine
          activeIncidents={openIncidents.length}
          pendingActions={pendingActions.length}
          totalAssets={overview?.total_assets ?? 0}
          monitoredApps={monitoredAppsData?.count ?? 0}
          lastIncidentAt={lastIncidentAt}
          actionsExecuted30d={actionsExecuted30d}
          blockedIpsNow={blockedIpsNow}
          loading={verdictLoading}
        />
        </div>

        {/* BAND 2 — TRIAGE QUEUE (8) / WATCH PANEL (4). On phones this band
            moves to position 3 (after WatchPanel) via CSS order only — the
            TriageQueue → Map → Surface → Ledger sequence inside it is
            untouched, and at >=lg order-none restores byte-identical grid
            auto-placement. */}
        <div className="col-span-12 lg:col-span-8 flex flex-col gap-6 min-w-0 max-lg:order-3 lg:order-none">
        <TriageQueue
          incidents={triageIncidents}
          pendingActions={triagePendingActions}
          onApprove={handleApprove}
          onReject={handleReject}
          loading={incidentsLoading}
          error={incidentsError}
          totalAssets={overview?.total_assets}
          monitoredApps={monitoredAppsData?.count}
          onRetry={handleRefresh}
        />

        

        {/* BAND 3 — ORIGIN MAP */}
        <OriginMap
          data={originMapData}
          homeAsn={homeAsn}
          loading={threatMapLoading}
          error={threatMapError}
          onRetry={handleRefresh}
        />

        {/* BAND 4 — ATTACK SURFACE / ASSET RISK */}
        <AssetRiskPanel
          assets={assetRiskItems}
          loading={assetsLoading}
          error={assetsError}
          onRetry={handleRefresh}
        />

        {/* BAND 5 — LEDGER */}
        <Ledger
          entries={ledgerEntries}
          window={timeWindow}
          onWindowChange={setTimeWindow}
          loading={timelineLoading}
          error={timelineError}
          onRetry={handleRefresh}
        />
        </div>

        {/* RIGHT RAIL — its OWN grid column for the whole scroll region.
            Previously WatchPanel was a col-span-4 sibling in row 2 while
            OriginMap/AssetRiskPanel/Ledger were col-span-12 rows beneath it,
            so the sticky rail travelled DOWN OVER them: measured at 1600px it
            covered 1040-1488px of panels that spanned 112-1488px, clipping the
            map legend, the risk list and the ledger's EVENT column. Giving the
            rail its own column makes the overlap structurally impossible. */}
        <div className="col-span-12 lg:col-span-4 min-w-0 max-lg:order-2 lg:order-none">
        <WatchPanel
          blockedIps={blockedIps}
          piReachable={piReachable}
          realFirewallActive={realFirewallActive}
          actionsExecuted30d={actionsExecuted30d}
          totalAssets={overview?.total_assets ?? 0}
          activeAssets={activeAssets}
          apps={monitoredApps}
          honeypotsRunning={honeypotsRunning}
          honeypotHits30d={overview?.honeypot_interactions ?? 0}
          openVulnerabilities={overview?.open_vulnerabilities ?? 0}
          lastScanAt={lastScanAt}
          loading={watchPanelLoading}
          firewallError={firewallError}
        />
        </div>

        </div>
      </div>
    </>
  );
}
