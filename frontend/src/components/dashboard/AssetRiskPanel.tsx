'use client';

import * as React from 'react';
import { Panel, SectionHeader, EmptyState } from '@/components/aegis';
import { cn, formatRelativeTime } from '@/lib/utils';

/**
 * AssetRiskPanel — "what do I own and which part of it is most exposed".
 *
 * Surfaces the full asset inventory that `api.surface.assets()` already
 * returns and that the rest of the dashboard collapses into a single
 * scalar ("80 assets"). Two views of the same dataset side by side: a
 * risk-score distribution (left third) and the eight riskiest assets
 * (right two-thirds).
 *
 * Purely presentational — no internal fetch, no sorting/filter state, no
 * links (there is no per-asset detail route to link to). The page scrolls,
 * not this panel: no nested `overflow-y-auto` region.
 *
 * All counts derive from the `assets` prop at render time. Nothing here is
 * hardcoded — an empty/short array degrades gracefully (buckets read 0,
 * fewer than 8 rows render, "last scan —" when no scan exists).
 */

export interface AssetRiskItem {
  id: string;
  hostname: string;
  ip_address: string;
  asset_type: string;
  ports: number[];
  technologies: string[];
  status: string;
  risk_score: number;
  last_scan_at: string | null;
}

export interface AssetRiskPanelProps {
  assets: AssetRiskItem[];
  loading?: boolean;
  error?: boolean;
  onRetry?: () => void;
}

// ---------------------------------------------------------------------------
// Per-row severity — explicit 5-value scale, matches the SEV_VAR convention
// established in TriageQueue.tsx / Ledger.tsx / OriginMap.tsx: defensive
// var(x, fallback) chains so rows still render correctly before the
// --sev-* tokens land in globals.css.
//
// Deliberately DIFFERENT from the 4-bucket distribution scale below — the
// spec fixes both scales independently, no implementer judgement.
// ---------------------------------------------------------------------------

function severityVar(riskScore: number): string {
  if (riskScore >= 7) return 'var(--sev-critical, var(--danger))';
  if (riskScore >= 5) return 'var(--sev-high, var(--brand-accent))';
  if (riskScore >= 3) return 'var(--sev-medium, var(--warning))';
  if (riskScore > 0) return 'var(--sev-low, var(--brand))';
  return 'var(--sev-info, var(--muted-foreground))';
}

// ---------------------------------------------------------------------------
// Distribution — coarser 4-bucket scale for the stacked bar + legend:
// r>=6 / 3<=r<6 / 0<r<3 / r===0. Computed fresh from `assets` every render.
// ---------------------------------------------------------------------------

interface DistBucket {
  key: string;
  label: string;
  count: number;
  color: string;
}

function buildDistribution(assets: AssetRiskItem[]): DistBucket[] {
  let sixPlus = 0;
  let threeToSix = 0;
  let zeroToThree = 0;
  let none = 0;
  for (const a of assets) {
    if (a.risk_score >= 6) sixPlus += 1;
    else if (a.risk_score >= 3) threeToSix += 1;
    else if (a.risk_score > 0) zeroToThree += 1;
    else none += 1;
  }
  return [
    { key: 'critical', label: 'Risk 6+', count: sixPlus, color: 'var(--sev-critical, var(--danger))' },
    { key: 'high', label: 'Risk 3-6', count: threeToSix, color: 'var(--sev-high, var(--brand-accent))' },
    { key: 'medium', label: 'Risk 0-3', count: zeroToThree, color: 'var(--sev-medium, var(--warning))' },
    { key: 'none', label: 'No risk score', count: none, color: 'var(--muted)' },
  ];
}

/** Backend returns naive UTC datetimes without a `Z` suffix — normalize so
 *  `Date.parse` treats them as UTC, matching formatRelativeTime's convention. */
function toUtcMillis(dateStr: string): number {
  const normalized = dateStr.endsWith('Z') || dateStr.includes('+') ? dateStr : `${dateStr}Z`;
  return new Date(normalized).getTime();
}

// ---------------------------------------------------------------------------
// Loading skeleton — bar + 8 rows at their real heights so there is no
// layout shift when data arrives.
// ---------------------------------------------------------------------------

function LoadingSkeleton() {
  return (
    <div
      aria-hidden="true"
      className="grid grid-cols-1 md:grid-cols-3 md:divide-x md:divide-[var(--border)]"
    >
      <div className="px-5 py-4">
        <div className="h-2 w-full rounded-[6px] bg-[var(--muted)] opacity-40" />
      </div>
      <div className="px-5 py-4 md:col-span-2 grid grid-cols-1 lg:grid-cols-2 gap-x-6 gap-y-2">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="h-10 rounded-[6px] bg-[var(--muted)] opacity-40" />
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Column 1 — distribution
// ---------------------------------------------------------------------------

function DistributionColumn({ assets }: { assets: AssetRiskItem[] }) {
  const total = assets.length;
  const buckets = React.useMemo(() => buildDistribution(assets), [assets]);

  const activeCount = React.useMemo(
    () => assets.filter((a) => a.status.toLowerCase() === 'active').length,
    [assets],
  );
  const inactiveCount = total - activeCount;

  const newestScanAt = React.useMemo(() => {
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
  }, [assets]);

  const barLabel = buckets.map((b) => `${b.count} ${b.label}`).join(', ');

  return (
    <div className="px-5 py-4">
      <p className="mb-3 text-[11px] uppercase tracking-[0.14em] text-muted-foreground">
        DISTRIBUTION
      </p>

      <div
        role="img"
        aria-label={`Risk distribution: ${barLabel}`}
        className="flex h-2 w-full overflow-hidden rounded-full bg-muted"
      >
        {buckets.map((b) => {
          if (b.count === 0) return null;
          const pct = total > 0 ? Math.max((b.count / total) * 100, 2) : 0;
          return (
            <div key={b.key} style={{ width: `${pct}%`, background: b.color }} className="h-full" />
          );
        })}
      </div>

      <div className="mt-3 flex flex-col gap-1.5">
        {buckets.map((b) => (
          <div key={b.key} className="flex items-center gap-2 text-[11px]">
            <span
              aria-hidden="true"
              className="h-2 w-2 shrink-0 rounded-[2px]"
              style={{ background: b.color }}
            />
            <span className="min-w-0 flex-1 truncate text-muted-foreground">{b.label}</span>
            <span className="font-mono tabular-nums text-foreground">{b.count}</span>
          </div>
        ))}
      </div>

      <div className="mt-4 flex flex-col gap-1 border-t border-border pt-3">
        <p className="font-mono text-[11px] tabular-nums text-muted-foreground">
          {activeCount} of {total} active &middot; {inactiveCount} inactive
        </p>
        <p className="font-mono text-[11px] text-muted-foreground">
          last scan {formatRelativeTime(newestScanAt)}
        </p>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Columns 2-3 — highest risk
// ---------------------------------------------------------------------------

function HighestRiskColumn({ assets }: { assets: AssetRiskItem[] }) {
  const topAssets = React.useMemo(() => {
    return [...assets]
      .sort((a, b) => {
        if (b.risk_score !== a.risk_score) return b.risk_score - a.risk_score;
        return a.hostname.localeCompare(b.hostname);
      })
      .slice(0, 8);
  }, [assets]);

  // Last row in each column of the 2-col grid (CSS grid row-major fill):
  // the final iteration for each index-parity wins, giving the bottom-most
  // item per column whether the total count is even or odd.
  const lastIndexByParity = React.useMemo(() => {
    const map = new Map<number, number>();
    topAssets.forEach((_, i) => map.set(i % 2, i));
    return map;
  }, [topAssets]);

  return (
    <div className="px-5 py-4 md:col-span-2">
      <p className="mb-3 text-[11px] uppercase tracking-[0.14em] text-muted-foreground">
        HIGHEST RISK
      </p>
      <div className="grid grid-cols-1 gap-x-6 gap-y-0 lg:grid-cols-2">
        {topAssets.map((asset, i) => {
          const isLastInColumn = lastIndexByParity.get(i % 2) === i;
          const sevColor = severityVar(asset.risk_score);
          const fillPct = Math.max(0, Math.min(100, (asset.risk_score / 10) * 100));
          return (
            <div
              key={asset.id}
              className={cn('flex h-10 items-center gap-3', !isLastInColumn && 'border-b border-border')}
            >
              <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-foreground">
                {asset.hostname}
              </span>
              <span className="shrink-0 text-[10px] uppercase tracking-[0.08em] text-muted-foreground">
                {asset.asset_type.replace(/_/g, ' ')}
              </span>
              {asset.ports.length > 0 && (
                <span className="shrink-0 font-mono text-[10.5px] text-muted-foreground">
                  {asset.ports.length}p
                </span>
              )}
              <span aria-hidden="true" className="h-1 w-11 shrink-0 overflow-hidden rounded-full bg-muted">
                <span
                  className="block h-full rounded-full"
                  style={{ width: `${fillPct}%`, background: sevColor }}
                />
              </span>
              <span
                className="w-[30px] shrink-0 text-right font-mono text-[12px] tabular-nums"
                style={{ color: sevColor }}
              >
                {asset.risk_score.toFixed(1)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------------

export function AssetRiskPanel({ assets, loading = false, error = false, onRetry }: AssetRiskPanelProps) {
  const isEmpty = !loading && !error && assets.length === 0;

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
        <div className="grid grid-cols-1 md:grid-cols-3 md:divide-x md:divide-[var(--border)]">
          <DistributionColumn assets={assets} />
          <HighestRiskColumn assets={assets} />
        </div>
      )}
    </Panel>
  );
}

export default AssetRiskPanel;
