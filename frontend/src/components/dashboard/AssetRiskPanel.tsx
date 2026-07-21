'use client';

import * as React from 'react';
import { ChevronDown } from 'lucide-react';
import { Panel, SectionHeader, EmptyState, StatusBadge, ProvenanceBadge } from '@/components/aegis';
import type { StatusVariant } from '@/components/aegis';
import { cn, formatRelativeTime } from '@/lib/utils';

/**
 * AssetRiskPanel — "which assets are actually dangerous, and what kind of
 * services am I exposing".
 *
 * Replaces the old port-count distribution with the deterministic
 * `service_weighted_v1` model: risk_score is produced ONLY by a port-weight
 * table + host-share damping + an exposure multiplier — never by an LLM.
 * The AI call (when alive) writes prose into AuditLog.ai_reasoning; it can
 * never move the number. This panel states that fact on its own face
 * (Region D) instead of leaving it implicit.
 *
 * Four stacked regions, each separated by a hairline:
 *   A. DANGEROUS SERVICES — direct answer to "que tipo de servicios": every
 *      service class weighted >=6 present anywhere in the fleet.
 *   B. BANDS / EXPOSURE / SERVICE CLASSES — three columns: risk-band
 *      distribution, exposure breakdown (with the loopback disclaimer), and
 *      a full service-class inventory.
 *   C. HIGHEST RISK — top 8 assets, each expandable into its literal driver
 *      table and the arithmetic that produced its score.
 *   D. DERIVATION FOOTER — always visible: no AI in this number.
 *
 * Purely presentational — no internal fetch, no page-level scroll capture
 * (this panel never opens its own `overflow-y-auto` region). All counts
 * derive from the `assets` prop at render time; nothing here is hardcoded.
 *
 * NULLABILITY NOTE: `risk_method`, `exposure`, `exposure_multiplier`,
 * `base_score` and `vuln_term` are typed nullable here because
 * dashboard/page.tsx's asset mapper (the sole caller) explicitly defaults
 * each of them to `null` — never a fabricated value — when the backend
 * response omits them (see that file's `assetRiskItems` useMemo). This
 * panel mirrors that honesty: every render path below degrades to a plain
 * "unavailable" line rather than crashing on `.toFixed()` of `null` or
 * silently treating "unknown" as "loopback".
 */

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type RiskBand = 'contained' | 'watch' | 'elevated' | 'exposed' | 'critical';
export type AssetExposure = 'local' | 'lan' | 'tailnet' | 'public' | 'unknown';

export interface AssetRiskPort {
  port: number;
  protocol?: string;
  service?: string;
  version?: string;
  state?: string;
}

export interface AssetRiskDriver {
  port: number;
  protocol: string;
  service: string;
  klass: string;
  label: string;
  weight: number;
  host_wide: boolean;
  contribution: number;
}

export interface AssetServiceClass {
  klass: string;
  label: string;
  weight: number;
  count: number;
}

export interface AssetRiskItem {
  id: string;
  hostname: string;
  ip_address: string | null;
  asset_type: string;
  ports: AssetRiskPort[];
  technologies: string[];
  status: string;
  risk_score: number;
  last_scan_at: string | null;
  risk_band: RiskBand;
  risk_method: string | null;
  risk_ai_used: boolean;
  exposure: AssetExposure | null;
  exposure_multiplier: number | null;
  base_score: number | null;
  vuln_term: number | null;
  risk_drivers: AssetRiskDriver[];
  service_classes: AssetServiceClass[];
  host_wide_count: number;
  owned_count: number;
}

export interface AssetRiskPanelProps {
  assets: AssetRiskItem[];
  loading?: boolean;
  error?: boolean;
  onRetry?: () => void;
}

// ---------------------------------------------------------------------------
// Band + exposure vocabulary — single source of truth for colour/label pairs.
// Reuses the existing --sev-* ramp (critical=red high=orange medium=amber
// low=cyan info=zinc) so a fifth "severity-shaped" scale reads consistently
// with TriageQueue/Ledger rather than inventing new tokens.
// ---------------------------------------------------------------------------

const BAND_ORDER: RiskBand[] = ['critical', 'exposed', 'elevated', 'watch', 'contained'];

const BAND_META: Record<RiskBand, { label: string; color: string; badgeVariant: StatusVariant }> = {
  critical: { label: 'Critical', color: 'var(--sev-critical, var(--danger))', badgeVariant: 'danger' },
  exposed: { label: 'Exposed', color: 'var(--sev-high, var(--brand-accent))', badgeVariant: 'warning' },
  elevated: { label: 'Elevated', color: 'var(--sev-medium, var(--warning))', badgeVariant: 'warning' },
  watch: { label: 'Watch', color: 'var(--sev-low, var(--brand))', badgeVariant: 'info' },
  contained: { label: 'Contained', color: 'var(--sev-info, var(--muted-foreground))', badgeVariant: 'muted' },
};

/**
 * Raw-number-to-band mapping used ONLY to colour a bare weight value (Region
 * B3's chip) when there is no asset-level `risk_band` to defer to. Threshold
 * 6 intentionally matches the panel's own "dangerous service" gate, so a
 * service that qualifies for the DANGEROUS SERVICES strip always reads
 * exposed-or-worse here too. This never overrides an asset's own
 * authoritative `risk_band` field.
 */
function bandForWeight(weight: number): RiskBand {
  if (weight >= 8) return 'critical';
  if (weight >= 6) return 'exposed';
  if (weight >= 4) return 'elevated';
  if (weight >= 2) return 'watch';
  return 'contained';
}

const EXPOSURE_LABEL: Record<AssetExposure, string> = {
  local: 'loopback',
  lan: 'LAN',
  tailnet: 'tailnet',
  public: 'public',
  unknown: 'unknown',
};

/** Most-exposed first — drives both the EXPOSURE column's row order and the
 * "max exposure" rank comparison in the dangerous-services strip. */
const EXPOSURE_ORDER: AssetExposure[] = ['public', 'tailnet', 'lan', 'unknown', 'local'];

/** `null` and the literal 'unknown' carry the same meaning here — "we could
 * not determine this asset's reachability" — so a missing value is folded
 * into the existing 'unknown' bucket rather than inventing a new one. */
function exposureKey(exposure: AssetExposure | null): AssetExposure {
  return exposure ?? 'unknown';
}

function exposureLabel(exposure: AssetExposure | null): string {
  return EXPOSURE_LABEL[exposureKey(exposure)];
}

/** Backend returns naive UTC datetimes without a `Z` suffix — normalize so
 *  `Date.parse` treats them as UTC, matching formatRelativeTime's convention. */
function toUtcMillis(dateStr: string): number {
  const normalized = dateStr.endsWith('Z') || dateStr.includes('+') ? dateStr : `${dateStr}Z`;
  return new Date(normalized).getTime();
}

function newestScanAt(assets: AssetRiskItem[]): string | null {
  let newest: string | null = null;
  let newestTime = -Infinity;
  for (const a of assets) {
    if (!a.last_scan_at) continue;
    const t = toUtcMillis(a.last_scan_at);
    if (!Number.isNaN(t) && t > newestTime) {
      newestTime = t;
      newest = a.last_scan_at;
    }
  }
  return newest;
}

// ---------------------------------------------------------------------------
// Fleet-wide service-class aggregation — shared by Region A and Region B3 so
// the fleet is only walked once per render.
// ---------------------------------------------------------------------------

interface ServiceClassAgg {
  klass: string;
  label: string;
  weight: number;
  assetIds: Set<string>;
}

function aggregateServiceClasses(assets: AssetRiskItem[]): ServiceClassAgg[] {
  const map = new Map<string, ServiceClassAgg>();
  for (const asset of assets) {
    for (const sc of asset.service_classes ?? []) {
      let entry = map.get(sc.klass);
      if (!entry) {
        entry = { klass: sc.klass, label: sc.label, weight: sc.weight, assetIds: new Set() };
        map.set(sc.klass, entry);
      }
      entry.assetIds.add(asset.id);
    }
  }
  return Array.from(map.values()).sort((a, b) => {
    if (b.weight !== a.weight) return b.weight - a.weight;
    return b.assetIds.size - a.assetIds.size;
  });
}

interface DangerousEntry extends ServiceClassAgg {
  topBand: RiskBand;
  maxExposureLabel: string;
}

/** For each weight>=6 klass, finds the highest-scoring carrying asset (for
 * the swatch colour) and the most-exposed carrying asset (for the label) —
 * two independent maxima over the same asset set. */
function computeDangerousEntries(assets: AssetRiskItem[], aggregates: ServiceClassAgg[]): DangerousEntry[] {
  return aggregates
    .filter((agg) => agg.weight >= 6)
    .map((agg) => {
      let topAsset: AssetRiskItem | null = null;
      let bestExposureRank = Infinity;
      for (const asset of assets) {
        if (!agg.assetIds.has(asset.id)) continue;
        if (!topAsset || asset.risk_score > topAsset.risk_score) topAsset = asset;
        const rank = EXPOSURE_ORDER.indexOf(exposureKey(asset.exposure));
        if (rank !== -1 && rank < bestExposureRank) bestExposureRank = rank;
      }
      const exposureAtBest = EXPOSURE_ORDER[bestExposureRank] ?? 'unknown';
      return {
        ...agg,
        topBand: topAsset?.risk_band ?? 'contained',
        maxExposureLabel: EXPOSURE_LABEL[exposureAtBest],
      };
    });
}

// ---------------------------------------------------------------------------
// Loading skeleton — static (no animation, matching the zero-idle-motion
// convention elsewhere on this dashboard), sized to the real regions below
// so there is no layout shift when data arrives.
// ---------------------------------------------------------------------------

function LoadingSkeleton() {
  return (
    <div aria-hidden="true">
      <div className="flex flex-col gap-2 px-5 py-3">
        <div className="h-3 w-40 rounded bg-muted opacity-40" />
        <div className="h-3 w-full rounded bg-muted opacity-25" />
        <div className="h-3 w-2/3 rounded bg-muted opacity-25" />
      </div>
      <div className="grid grid-cols-1 border-t border-[var(--border)] md:grid-cols-3 md:divide-x md:divide-[var(--border)]">
        <div className="px-5 py-4">
          <div className="h-2 w-full rounded-full bg-muted opacity-40" />
        </div>
        <div className="px-5 py-4">
          <div className="h-24 w-full rounded-[6px] bg-muted opacity-30" />
        </div>
        <div className="px-5 py-4">
          <div className="h-24 w-full rounded-[6px] bg-muted opacity-30" />
        </div>
      </div>
      <div className="grid grid-cols-1 gap-x-6 gap-y-2 border-t border-[var(--border)] px-5 py-4 lg:grid-cols-2">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="min-h-[56px] rounded-[6px] bg-muted opacity-40 lg:h-12" />
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// REGION A — Dangerous services strip
// ---------------------------------------------------------------------------

function DangerousServicesStrip({ entries }: { entries: DangerousEntry[] }) {
  if (entries.length === 0) {
    return (
      <div className="px-5 py-3">
        <p className="text-[12px] text-muted-foreground">
          No high-weight services (SMB, VNC, RDP, telnet, exposed datastores) found in this inventory.
        </p>
      </div>
    );
  }

  return (
    <div className="px-5 py-3">
      <p className="mb-2 text-[11px] uppercase tracking-[0.14em] text-muted-foreground">DANGEROUS SERVICES</p>
      <div className="flex flex-wrap gap-x-4 gap-y-2">
        {entries.map((entry) => (
          <div key={entry.klass} className="flex items-center gap-2">
            <span
              aria-hidden="true"
              className="h-[6px] w-[6px] shrink-0"
              style={{ background: BAND_META[entry.topBand].color }}
            />
            <span className="text-[13px] text-foreground">{entry.label}</span>
            <span className="font-mono text-[11px] text-muted-foreground">
              {'· on '}
              {entry.assetIds.size}
              {' assets · max exposure '}
              {entry.maxExposureLabel}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// REGION B1 — Risk bands
// ---------------------------------------------------------------------------

function buildBandCounts(assets: AssetRiskItem[]): Record<RiskBand, number> {
  const counts: Record<RiskBand, number> = { critical: 0, exposed: 0, elevated: 0, watch: 0, contained: 0 };
  for (const a of assets) {
    if (a.risk_band in counts) counts[a.risk_band] += 1;
  }
  return counts;
}

function BandsColumn({ assets }: { assets: AssetRiskItem[] }) {
  const total = assets.length;
  const counts = React.useMemo(() => buildBandCounts(assets), [assets]);
  const barLabel = BAND_ORDER.map((b) => `${counts[b]} ${BAND_META[b].label}`).join(', ');

  return (
    <div className="px-5 py-4">
      <p className="mb-3 text-[11px] uppercase tracking-[0.14em] text-muted-foreground">RISK BANDS</p>

      <div
        role="img"
        aria-label={`Risk bands: ${barLabel}`}
        className="flex h-2 w-full overflow-hidden rounded-full bg-muted"
      >
        {BAND_ORDER.map((b) => {
          const count = counts[b];
          if (count === 0) return null;
          const pct = total > 0 ? Math.max((count / total) * 100, 2) : 0;
          return <div key={b} style={{ width: `${pct}%`, background: BAND_META[b].color }} className="h-full" />;
        })}
      </div>

      <div className="mt-3 flex flex-col gap-1.5">
        {BAND_ORDER.map((b) => (
          <div key={b} className="flex items-center gap-2 text-[11px]">
            <span
              aria-hidden="true"
              className="h-2 w-2 shrink-0 rounded-[2px]"
              style={{ background: BAND_META[b].color }}
            />
            <span className="min-w-0 flex-1 truncate text-muted-foreground">{BAND_META[b].label}</span>
            <span className="font-mono tabular-nums text-foreground">{counts[b]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// REGION B2 — Exposure
// ---------------------------------------------------------------------------

interface ExposureGroup {
  exposure: AssetExposure;
  count: number;
  multiplier: number | null;
}

function buildExposureGroups(assets: AssetRiskItem[]): ExposureGroup[] {
  const map = new Map<AssetExposure, { count: number; multiplier: number | null }>();
  for (const a of assets) {
    const key = exposureKey(a.exposure);
    const cur = map.get(key);
    if (cur) cur.count += 1;
    else map.set(key, { count: 1, multiplier: a.exposure_multiplier });
  }
  return EXPOSURE_ORDER.filter((exp) => map.has(exp)).map((exp) => {
    const v = map.get(exp)!;
    return { exposure: exp, count: v.count, multiplier: v.multiplier };
  });
}

function ExposureColumn({ assets }: { assets: AssetRiskItem[] }) {
  const total = assets.length;
  const groups = React.useMemo(() => buildExposureGroups(assets), [assets]);
  const localCount = React.useMemo(() => assets.filter((a) => exposureKey(a.exposure) === 'local').length, [assets]);
  const showDisclaimer = total > 0 && localCount / total >= 0.5;

  return (
    <div className="px-5 py-4">
      <p className="mb-3 text-[11px] uppercase tracking-[0.14em] text-muted-foreground">EXPOSURE</p>

      <div className="flex flex-col gap-1.5">
        {groups.map((g) => (
          <div key={g.exposure} className="flex items-center gap-2 text-[11px]">
            <span className="min-w-0 flex-1 truncate text-muted-foreground">{EXPOSURE_LABEL[g.exposure]}</span>
            <span className="font-mono tabular-nums text-foreground">{g.count}</span>
            <span className="shrink-0 text-[10.5px] text-muted-foreground">
              {g.multiplier != null ? `×${g.multiplier}` : '×—'}
            </span>
          </div>
        ))}
      </div>

      {showDisclaimer && (
        <p className="mt-4 border-t border-border pt-3 text-[11px] leading-[15px] text-muted-foreground">
          {localCount} of {total} assets are loopback-only (exposure ×0.25). Their scores are held down by
          unreachability, not by cleanliness.
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// REGION B3 — Service classes
// ---------------------------------------------------------------------------

function ServiceClassesColumn({ aggregates }: { aggregates: ServiceClassAgg[] }) {
  const visible = aggregates.slice(0, 8);
  const remaining = aggregates.length - visible.length;

  return (
    <div className="px-5 py-4">
      <p className="mb-3 text-[11px] uppercase tracking-[0.14em] text-muted-foreground">SERVICE CLASSES</p>

      <div className="flex flex-col gap-1.5">
        {visible.map((sc) => {
          const band = bandForWeight(sc.weight);
          return (
            <div key={sc.klass} className="flex items-center gap-2 text-[11px]">
              <span className="min-w-0 flex-1 truncate text-muted-foreground">{sc.label}</span>
              <span className="font-mono tabular-nums text-foreground">{sc.assetIds.size}</span>
              <span
                className="shrink-0 text-right font-mono text-[10px] tabular-nums"
                style={{ color: BAND_META[band].color }}
              >
                w {sc.weight.toFixed(1)}
              </span>
            </div>
          );
        })}
      </div>

      {remaining > 0 && <p className="mt-1.5 font-mono text-[11px] text-muted-foreground">+{remaining} more</p>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// REGION C — Highest risk
// ---------------------------------------------------------------------------

const DRV_TH_CLASS = 'px-2 py-1 text-left text-[10px] uppercase tracking-[0.1em] text-muted-foreground';
const DRV_TD_CLASS = 'px-2 py-1 align-top font-mono text-[11px] tabular-nums text-foreground';
const HOST_WIDE_TITLE = 'Present on ≥60% of assets sharing this IP — counted at ×0.35';

function DriverPanel({ asset, panelId }: { asset: AssetRiskItem; panelId: string }) {
  const drivers = asset.risk_drivers ?? [];
  const hasDerivation = asset.base_score != null && asset.exposure_multiplier != null && asset.vuln_term != null;

  return (
    <div
      id={panelId}
      className="border-b border-border bg-[color-mix(in_oklab,var(--foreground)_2%,transparent)] px-3 py-3"
    >
      <table className="hidden w-full border-collapse sm:table">
        <thead>
          <tr>
            <th scope="col" className={DRV_TH_CLASS}>
              Port
            </th>
            <th scope="col" className={DRV_TH_CLASS}>
              Service
            </th>
            <th scope="col" className={DRV_TH_CLASS}>
              Class
            </th>
            <th scope="col" className={DRV_TH_CLASS}>
              Weight
            </th>
            <th scope="col" className={DRV_TH_CLASS}>
              Shared
            </th>
            <th scope="col" className={DRV_TH_CLASS}>
              Contrib
            </th>
          </tr>
        </thead>
        <tbody>
          {drivers.map((d, i) => (
            <tr key={`${d.port}-${d.klass}-${i}`}>
              <td className={DRV_TD_CLASS}>{d.port}</td>
              <td className={DRV_TD_CLASS}>{d.service || '—'}</td>
              <td className={DRV_TD_CLASS}>{d.klass}</td>
              <td className={DRV_TD_CLASS}>{d.weight.toFixed(1)}</td>
              <td className={DRV_TD_CLASS} title={d.host_wide ? HOST_WIDE_TITLE : undefined}>
                {d.host_wide ? <span className="text-muted-foreground">HOST-WIDE</span> : null}
              </td>
              <td className={DRV_TD_CLASS}>{d.contribution.toFixed(1)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* A 6-column table cannot survive ~350px — stacked definition list below `sm`. */}
      <dl className="flex flex-col gap-2 sm:hidden">
        {drivers.map((d, i) => (
          <div key={`${d.port}-${d.klass}-${i}`} className="font-mono text-[11px]">
            <dt className="tabular-nums text-foreground">
              {d.port}/{d.service || '—'}
            </dt>
            <dd className="tabular-nums text-muted-foreground">
              {d.klass} · w {d.weight.toFixed(1)}
              {d.host_wide ? ' · HOST-WIDE' : ''} · {d.contribution.toFixed(1)}
            </dd>
          </div>
        ))}
      </dl>

      {hasDerivation ? (
        <p className="mt-3 font-mono text-[11px] text-foreground">
          base {asset.base_score!.toFixed(1)} × exposure {asset.exposure_multiplier} ({exposureLabel(asset.exposure)}
          ) + vulns {asset.vuln_term!.toFixed(1)} = {asset.risk_score.toFixed(1)}
        </p>
      ) : (
        <p className="mt-3 font-mono text-[11px] text-muted-foreground">Derivation unavailable for this asset.</p>
      )}
    </div>
  );
}

function HighestRiskRegion({ assets }: { assets: AssetRiskItem[] }) {
  const [expandedId, setExpandedId] = React.useState<string | null>(null);

  const topAssets = React.useMemo(
    () =>
      [...assets]
        .sort((a, b) => {
          if (b.risk_score !== a.risk_score) return b.risk_score - a.risk_score;
          return a.hostname.localeCompare(b.hostname);
        })
        .slice(0, 8),
    [assets],
  );

  // Last row in each column of the 2-col grid (CSS grid row-major fill):
  // the final iteration for each index-parity wins, giving the bottom-most
  // item per column whether the total count is even or odd.
  const lastIndexByParity = React.useMemo(() => {
    const map = new Map<number, number>();
    topAssets.forEach((_, i) => map.set(i % 2, i));
    return map;
  }, [topAssets]);

  return (
    <div className="border-t border-[var(--border)] px-5 pt-4">
      <p className="mb-3 text-[11px] uppercase tracking-[0.14em] text-muted-foreground">HIGHEST RISK</p>
      <div className="grid grid-cols-1 gap-x-6 lg:grid-cols-2">
        {topAssets.map((asset, i) => {
          const isLastInColumn = lastIndexByParity.get(i % 2) === i;
          const isOpen = expandedId === asset.id;
          const band = BAND_META[asset.risk_band];
          const fillPct = Math.max(0, Math.min(100, asset.risk_score * 10));
          const panelId = `drv-${asset.id}`;

          const topDrivers = [...(asset.risk_drivers ?? [])].sort((a, b) => b.contribution - a.contribution).slice(0, 3);
          const driverLineText = topDrivers.map((d) => `${d.label.toUpperCase()} ${d.port}`).join(' · ');

          return (
            <div key={asset.id}>
              <button
                type="button"
                onClick={() => setExpandedId((cur) => (cur === asset.id ? null : asset.id))}
                aria-expanded={isOpen}
                aria-controls={panelId}
                className={cn(
                  'flex min-h-[56px] w-full items-center gap-3 text-left lg:h-12',
                  !isLastInColumn && 'border-b border-border',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--ring)]',
                )}
              >
                <span className="flex min-w-0 flex-1 flex-col gap-0.5">
                  <span className="truncate font-mono text-[12px] text-foreground">{asset.hostname}</span>
                  {driverLineText && (
                    <span className="truncate font-mono text-[10.5px] text-muted-foreground sm:hidden">
                      {driverLineText}
                    </span>
                  )}
                </span>

                <StatusBadge size="sm" variant={band.badgeVariant} className="shrink-0">
                  {band.label}
                </StatusBadge>

                <span className="shrink-0 text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                  {exposureLabel(asset.exposure)}
                </span>

                {driverLineText && (
                  <span className="hidden w-[150px] shrink-0 truncate font-mono text-[10.5px] text-muted-foreground sm:block">
                    {driverLineText}
                  </span>
                )}

                <span aria-hidden="true" className="h-1 w-11 shrink-0 overflow-hidden rounded-full bg-muted">
                  <span
                    className="block h-full rounded-full motion-safe:transition-[width] motion-safe:duration-150"
                    style={{ width: `${fillPct}%`, background: band.color }}
                  />
                </span>

                <span
                  className="w-[34px] shrink-0 text-right font-mono text-[12px] tabular-nums"
                  style={{ color: band.color }}
                >
                  {asset.risk_score.toFixed(1)}
                </span>

                <span aria-hidden="true" className="-m-2 shrink-0 p-2">
                  <ChevronDown
                    size={12}
                    className={cn('motion-safe:transition-transform motion-safe:duration-150', isOpen && 'rotate-180')}
                  />
                </span>
              </button>

              {isOpen && <DriverPanel asset={asset} panelId={panelId} />}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// REGION D — Derivation footer
// ---------------------------------------------------------------------------

function DerivationFooter({ assets }: { assets: AssetRiskItem[] }) {
  const total = assets.length;
  const aiUsedCount = React.useMemo(() => assets.filter((a) => a.risk_ai_used).length, [assets]);
  const riskMethod = React.useMemo(() => assets.find((a) => a.risk_method != null)?.risk_method ?? null, [assets]);
  const scanAt = React.useMemo(() => newestScanAt(assets), [assets]);

  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 border-t border-border px-5 py-3">
      <ProvenanceBadge source="algorithm" label="Deterministic" size="sm" />
      <StatusBadge variant="muted" size="sm">
        {riskMethod ?? 'method unavailable'}
      </StatusBadge>
      <span className="font-mono text-[11px] text-muted-foreground">
        no AI in this number · recomputed per request · last scan {formatRelativeTime(scanAt)}
      </span>
      <span className="w-full font-mono text-[11px] leading-[15px] text-muted-foreground">
        {aiUsedCount === 0
          ? 'AI scoring is disabled by design — this number is reproducible from the port list and the bind address alone.'
          : `${aiUsedCount} of ${total} scores include an AI justification; the number itself is still deterministic.`}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------------

export function AssetRiskPanel({ assets, loading = false, error = false, onRetry }: AssetRiskPanelProps) {
  const isEmpty = !loading && !error && assets.length === 0;

  const serviceClassAggregates = React.useMemo(() => aggregateServiceClasses(assets), [assets]);
  const dangerousEntries = React.useMemo(
    () => computeDangerousEntries(assets, serviceClassAggregates),
    [assets, serviceClassAggregates],
  );

  return (
    <Panel
      variant="default"
      padding="none"
      as="section"
      aria-label="Attack surface"
      aria-busy={loading}
      className="col-span-12"
    >
      {loading && (
        <span className="sr-only" role="status">
          Loading asset risk data.
        </span>
      )}

      <SectionHeader
        flush
        title="ATTACK SURFACE"
        count={!loading && !error ? `${assets.length} assets` : undefined}
      />

      {error ? (
        <EmptyState
          size="md"
          title="Asset inventory unavailable."
          action={
            <button
              type="button"
              onClick={() => onRetry?.()}
              className="rounded-sm text-[12px] font-semibold text-[var(--brand-text,var(--brand))] hover:underline"
            >
              Retry
            </button>
          }
        />
      ) : loading ? (
        <LoadingSkeleton />
      ) : isEmpty ? (
        <EmptyState
          size="md"
          title="No assets discovered yet."
          description="Surface scanning runs every 2 hours; discovery every hour."
        />
      ) : (
        <>
          <DangerousServicesStrip entries={dangerousEntries} />

          <div className="grid grid-cols-1 divide-y divide-[var(--border)] border-t border-[var(--border)] md:grid-cols-3 md:divide-x md:divide-y-0 md:divide-[var(--border)]">
            <BandsColumn assets={assets} />
            <ExposureColumn assets={assets} />
            <ServiceClassesColumn aggregates={serviceClassAggregates} />
          </div>

          <HighestRiskRegion assets={assets} />

          <DerivationFooter assets={assets} />
        </>
      )}
    </Panel>
  );
}

export default AssetRiskPanel;
