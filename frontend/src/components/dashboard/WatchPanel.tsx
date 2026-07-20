'use client';

import type { ReactNode } from 'react';
import Link from 'next/link';
import { Panel, SectionHeader, DataRow } from '@/components/aegis';
import { cn, formatRelativeTime } from '@/lib/utils';

/**
 * WatchPanel — the evidence rail.
 *
 * Replaces SecurityPostureGauge (donut) + AssetRiskTable (9 rows of
 * full-width green "100%" bars meaning "we found nothing"). Three regions:
 *
 *   A. POSTURE  — horizontal meter, always cyan, disclaimer in normal flow
 *      (no more clipped mid-word caption crammed into a 120px circle hole).
 *   B. COUNTERS — the four overview numbers, colour-coded only when they
 *      mean trouble (Active Incidents), zero rendered as an honest finding
 *      with evidence + provenance, never a triumphant green bar.
 *   C. FLEET    — nine monitored apps collapsed to one dense line of dot +
 *      name chips instead of a 9-row / 5-column table where 4 columns were
 *      byte-identical.
 *
 * The score formula (Region A) is SALVAGED VERBATIM from
 * SecurityPostureGauge.tsx lines 53-67 — do not re-derive it. Its
 * `totalAssets === 0` edge case is preserved exactly.
 *
 * This component never fetches. The parent page calls
 * api.dashboard.overview() and api.dashboard.monitoredApps() and passes the
 * results straight through as props.
 */
export interface MonitoredApp {
  name: string;
  status: string;
  open_incidents: number;
  last_activity: string | null;
  resolved_count: number;
}

export interface WatchPanelProps {
  totalAssets: number;
  openVulnerabilities: number;
  activeIncidents: number;
  honeypotInteractions: number;
  assetsTrend: number;
  vulnsTrend: number;
  incidentsTrend: number;
  interactionsTrend: number;
  apps: MonitoredApp[];
  /** ISO timestamp of the newest surface scan, or null. */
  lastScanAt: string | null;
  loading?: boolean;
}

/** "never" for a null timestamp, otherwise the shared relative-time helper. */
function relativeOrNever(iso: string | null): string {
  if (!iso) return 'never';
  return formatRelativeTime(iso);
}

/** Most recent last_activity across the fleet, or null if none reported. */
function mostRecentActivity(apps: MonitoredApp[]): string | null {
  let latest: string | null = null;
  let latestMs = -Infinity;
  for (const app of apps) {
    if (!app.last_activity) continue;
    const normalized =
      app.last_activity.endsWith('Z') || app.last_activity.includes('+')
        ? app.last_activity
        : `${app.last_activity}Z`;
    const ms = Date.parse(normalized);
    if (!Number.isNaN(ms) && ms > latestMs) {
      latestMs = ms;
      latest = app.last_activity;
    }
  }
  return latest;
}

/**
 * Trend chip — never colour-coded by direction. A rising asset count is not
 * bad news and a falling one is not good news; only var(--sev-high) on the
 * Active Incidents value itself carries meaning.
 */
function TrendChip({ value }: { value: number }) {
  if (value === 0) {
    return (
      <span
        className="font-mono tabular-nums text-[10px] leading-none text-muted-foreground"
        aria-label="No change"
      >
        —
      </span>
    );
  }
  const up = value > 0;
  return (
    <span
      className="inline-flex items-center gap-0.5 font-mono tabular-nums text-[10px] leading-none text-muted-foreground"
      aria-label={`${up ? 'Up' : 'Down'} ${Math.abs(value)} from prior period`}
    >
      <span aria-hidden>{up ? '↑' : '↓'}</span>
      {up ? `+${value}` : `${value}`}
    </span>
  );
}

interface CounterRowProps {
  label: string;
  value: number;
  trend: number;
  /** Active Incidents is the sole exception to the zero/non-zero colour rule. */
  isIncidents?: boolean;
  subline?: ReactNode;
  borderless?: boolean;
}

function CounterRow({ label, value, trend, isIncidents, subline, borderless }: CounterRowProps) {
  const valueClass =
    isIncidents && value > 0
      ? 'text-[color:var(--sev-high)]'
      : value > 0
        ? 'text-foreground'
        : 'text-muted-foreground';

  return (
    <div>
      <DataRow
        density="compact"
        borderless={borderless}
        leading={<span className="text-[12px] font-normal text-muted-foreground">{label}</span>}
        trailing={
          <>
            <span
              className={cn(
                'font-mono tabular-nums text-[20px] font-semibold tracking-[-0.6px]',
                valueClass,
              )}
            >
              {value}
            </span>
            <TrendChip value={trend} />
          </>
        }
      />
      {subline && (
        <div className="px-4 sm:px-5 pb-2.5 font-mono tabular-nums text-[10px] leading-relaxed text-muted-foreground">
          {subline}
        </div>
      )}
    </div>
  );
}

const focusRingClass =
  'text-foreground underline decoration-dotted underline-offset-2 hover:text-[var(--brand)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] rounded-sm';

export function WatchPanel({
  totalAssets,
  openVulnerabilities,
  activeIncidents,
  honeypotInteractions,
  assetsTrend,
  vulnsTrend,
  incidentsTrend,
  interactionsTrend,
  apps,
  lastScanAt,
  loading = false,
}: WatchPanelProps) {
  const noAssets = !loading && totalAssets === 0;

  // SCORE FORMULA — salvaged verbatim from SecurityPostureGauge.tsx, do not
  // re-derive. 1 open vuln / asset (avg) maxes the 50-pt vuln penalty
  // bucket. 0.5 active incidents / asset (avg) maxes the 50-pt incident
  // penalty bucket — incidents are weighted 2x vulns per unit because they
  // represent active compromise, not just exposure. honeypotInteractions is
  // deliberately excluded: decoy activity isn't a posture signal.
  let score: number | null = null;
  if (!loading && !noAssets) {
    const assets = Math.max(totalAssets, 1);
    const vulnRate = openVulnerabilities / assets;
    const incidentRate = activeIncidents / assets;
    const vulnPenalty = Math.min(50, vulnRate * 50);
    const incidentPenalty = Math.min(50, incidentRate * 100);
    score = Math.round(Math.max(0, Math.min(100, 100 - vulnPenalty - incidentPenalty)));
  }

  const meterFillPercent = noAssets ? 0 : (score ?? 0);
  const lastScanLabel = relativeOrNever(lastScanAt);

  const appsWithIncidents = apps.filter((a) => a.open_incidents > 0);
  const allQuiet = apps.length > 0 && appsWithIncidents.length === 0;
  const mostRecentLabel = relativeOrNever(mostRecentActivity(apps));

  return (
    <Panel
      variant="default"
      padding="none"
      as="aside"
      aria-label="Security watch panel"
      aria-busy={loading}
      className="col-span-12 lg:col-span-4 lg:sticky lg:top-[76px]"
    >
      {loading && (
        <span className="sr-only" role="status">
          Loading watch panel data.
        </span>
      )}

      {/* ═══ REGION A — POSTURE ═══ */}
      <div>
        <SectionHeader flush title="POSTURE" />
        <div className="px-4 sm:px-5 py-5">
          <div className="flex items-baseline">
            {loading ? (
              <span
                className="inline-block h-[28px] w-[60px] rounded-md bg-muted opacity-30"
                aria-hidden
              />
            ) : noAssets ? (
              <span className="font-mono tabular-nums text-[28px] font-semibold tracking-[-1px] text-foreground">
                &mdash;
              </span>
            ) : (
              <>
                <span className="font-mono tabular-nums text-[28px] font-semibold tracking-[-1px] text-foreground">
                  {score}
                </span>
                <span className="ml-0.5 font-mono tabular-nums text-[13px] text-muted-foreground">
                  /100
                </span>
              </>
            )}
          </div>

          <div
            role="meter"
            aria-valuenow={loading ? undefined : meterFillPercent}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label="Security posture score"
            className={cn(
              'mt-3 h-[6px] w-full overflow-hidden rounded-full bg-border',
              loading && 'opacity-30',
            )}
          >
            {!loading && (
              <div
                className="h-full rounded-full bg-brand"
                style={{ width: `${meterFillPercent}%` }}
              />
            )}
          </div>

          {!loading && (
            <p className="mt-3 max-w-[46ch] text-[11px] font-normal leading-[17px] text-muted-foreground">
              {noAssets ? (
                <>
                  No assets monitored. Run a{' '}
                  <Link href="/dashboard/surface" className={focusRingClass}>
                    Surface scan
                  </Link>{' '}
                  to establish a baseline.
                </>
              ) : (
                'Derived from open vulnerabilities and active incidents per asset — a heuristic, not a measured score.'
              )}
            </p>
          )}
        </div>
      </div>

      {/* ═══ REGION B — COUNTERS ═══ */}
      <div className="border-t border-border py-5">
        {loading ? (
          <div className="space-y-1 px-4 sm:px-5">
            {['Total Assets', 'Open Vulnerabilities', 'Active Incidents', 'Honeypot Interactions'].map(
              (label, i) => (
                <div key={label} className={cn('flex items-center justify-between py-2.5', i > 0 && 'border-t border-border')}>
                  <span className="text-[12px] font-normal text-muted-foreground">{label}</span>
                  <span className="inline-block h-[20px] w-10 rounded bg-muted opacity-30" aria-hidden />
                </div>
              ),
            )}
          </div>
        ) : (
          <>
            <CounterRow label="Total Assets" value={totalAssets} trend={assetsTrend} borderless />
            <CounterRow
              label="Open Vulnerabilities"
              value={openVulnerabilities}
              trend={vulnsTrend}
              subline={
                openVulnerabilities === 0 ? (
                  <>
                    No open findings &middot; {totalAssets} assets covered &middot; last scan{' '}
                    {lastScanLabel}
                  </>
                ) : undefined
              }
            />
            <CounterRow
              label="Active Incidents"
              value={activeIncidents}
              trend={incidentsTrend}
              isIncidents
            />
            <CounterRow
              label="Honeypot Interactions"
              value={honeypotInteractions}
              trend={interactionsTrend}
              subline={
                honeypotInteractions === 0 ? (
                  <>
                    <div>2 decoys armed &middot; ssh:2222 &middot; http:8888</div>
                    <div className="mt-0.5 text-muted-foreground/80">
                      A hit here means someone reached a decoy. Zero is the expected steady state.
                    </div>
                  </>
                ) : undefined
              }
            />
          </>
        )}
      </div>

      {/* ═══ REGION C — FLEET ═══ */}
      <div className="border-t border-border px-4 sm:px-5 py-5">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
            FLEET
          </span>
          {loading ? (
            <span className="inline-block h-[10px] w-9 rounded bg-muted opacity-30" aria-hidden />
          ) : (
            <span className="font-mono tabular-nums text-[10px] text-muted-foreground">
              {apps.length} APPS
            </span>
          )}
        </div>

        <div className="mt-3">
          {loading ? (
            <div className="flex flex-wrap gap-x-2.5 gap-y-1.5" aria-hidden>
              {Array.from({ length: 6 }).map((_, i) => (
                <span
                  key={i}
                  className="inline-block h-[11px] w-[60px] rounded bg-muted opacity-30"
                />
              ))}
            </div>
          ) : apps.length === 0 ? (
            <p className="font-mono text-[11px] text-muted-foreground">
              No applications registered for monitoring.{' '}
              <Link href="/dashboard/settings" className={focusRingClass}>
                Go to Settings
              </Link>
            </p>
          ) : (
            <>
              <div className="flex flex-wrap gap-x-2.5 gap-y-1.5">
                {apps.map((app, idx) => {
                  const hasIncidents = app.open_incidents > 0;
                  return (
                    <span key={`${app.name}-${idx}`} className="inline-flex items-center gap-1.5">
                      <span
                        aria-hidden
                        className={cn(
                          'h-[5px] w-[5px] shrink-0 rounded-full',
                          hasIncidents ? 'bg-[color:var(--sev-high)]' : 'bg-success',
                        )}
                      />
                      <span
                        className={cn(
                          'font-mono tabular-nums text-[11px]',
                          hasIncidents ? 'text-foreground' : 'text-muted-foreground',
                        )}
                      >
                        {app.name}
                      </span>
                      {hasIncidents && (
                        <span className="font-mono tabular-nums text-[10px] text-[color:var(--sev-high)]">
                          {app.open_incidents}
                        </span>
                      )}
                      <span className="sr-only">
                        {hasIncidents
                          ? `, ${app.open_incidents} open incident${app.open_incidents === 1 ? '' : 's'}`
                          : ', no open incidents'}
                      </span>
                    </span>
                  );
                })}
              </div>

              <p className="mt-3 font-mono tabular-nums text-[10px] text-muted-foreground">
                {allQuiet
                  ? `all quiet · last event ${mostRecentLabel}`
                  : `${appsWithIncidents.length} app${appsWithIncidents.length === 1 ? '' : 's'} with open incidents`}
              </p>
            </>
          )}
        </div>
      </div>
    </Panel>
  );
}

export default WatchPanel;
