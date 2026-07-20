'use client';

import * as React from 'react';
import Link from 'next/link';
import { InformationCircleIcon } from 'hugeicons-react';
import { Panel, EmptyState } from '@/components/aegis';
import { cn } from '@/lib/utils';
import { CC_TO_LATLON } from '@/lib/geo-centroids';
import { LAND_PATH, MAP_W, VIEW_Y, VIEW_H, projectLonLat } from '@/lib/geo/land-dots.generated';
import { resolveCountryName } from '@/lib/geo/country-names';

/**
 * OriginMap — the single most visible failure in the old build, rebuilt.
 *
 * Replaces GlobalThreatMap.tsx, ThreatMapCanvas.tsx and world-geometry.ts
 * entirely. The old map drew a sparse hand-drawn dot cloud with no ocean
 * reference, so land never resolved into recognisable continents. This
 * version rasterises real world-atlas landmass geometry at build time
 * (scripts/build-land-dots.mjs -> src/lib/geo/land-dots.generated.ts,
 * 4,783 dots, ONE <path> node) against a faint ocean lattice so land reads
 * by contrast, not by hoping sparse dots self-organise into continents.
 *
 * Two-region layout: a full-bleed dot-matrix world map answers WHERE, a
 * ranked, keyboard-operable country list answers HOW MUCH — every fact a
 * marker carries is also present as text, so the map is never the sole
 * carrier of information (WCAG: no info by hover/colour alone).
 *
 * Zero runtime dependency on d3-geo / topojson-client / world-atlas — those
 * only run inside the build script. The browser loads a static path string
 * and a plain lon/lat -> xy linear projection helper.
 */

export interface OriginMapEntry {
  country: string;
  country_code: string;
  count: number;
  /**
   * Operator/ASN attribution, resolved server-side from the same GeoIP
   * lookup that produced `country`. All three fields are OPTIONAL — the
   * backend returns them as null until the GeoIP CSV warmup completes
   * after an API restart. Absent data means an absent line, never a
   * placeholder: see the per-change null rules below.
   */
  top_asn?: string | null;
  top_asn_owner?: string | null;
  distinct_operators?: number | null;
}

export interface OriginMapProps {
  /** From api.dashboard.threatMap(). ALREADY FP-filtered server-side — do not re-filter. */
  data: OriginMapEntry[];
  /**
   * The operator's own uplink ASN, e.g. 'AS6400' (from
   * process.env.NEXT_PUBLIC_AEGIS_HOME_ASN, read and passed through by the
   * page). When it case-insensitively matches a row's top_asn, that row is
   * marked 'YOUR UPLINK'. Configuration only — never inferred from data.
   */
  homeAsn?: string | null;
  loading?: boolean;
  error?: boolean;
  /**
   * Optional refetch hook for the error state's Retry action. If omitted,
   * Retry falls back to a full page reload — a real handler either way,
   * never a decorative button with no effect.
   */
  onRetry?: () => void;
}

type Tier = 'critical' | 'high' | 'medium' | 'low';

const SEV_VAR: Record<Tier, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
};

const TRANSITION = 'stroke-opacity 150ms cubic-bezier(0.22, 1, 0.36, 1), stroke-width 150ms cubic-bezier(0.22, 1, 0.36, 1)';

function tierFor(count: number, maxCount: number): Tier {
  const ratio = maxCount > 0 ? count / maxCount : 0;
  if (ratio >= 0.66) return 'critical';
  if (ratio >= 0.33) return 'high';
  if (ratio >= 0.12) return 'medium';
  return 'low';
}

function markerRadius(count: number, maxCount: number): number {
  const ratio = maxCount > 0 ? count / maxCount : 0;
  return Math.min(11, 3 + 7 * Math.sqrt(ratio));
}

// ---------------------------------------------------------------------------
// ASN attribution — the "your uplink vs. Starlink vs. Amazon" answer. Every
// helper here degrades to `null` (an omitted line) the instant top_asn_owner
// is missing; nothing is ever guessed or filled with a placeholder.
// ---------------------------------------------------------------------------

/** Rail-row / chip line 2: "{owner} · {asn}[ +N]". Raw db-ip strings — no
 * cleanup, may contain quotes or exceed 50 chars; callers must `truncate`. */
function formatAsnLine(entry: OriginMapEntry): string | null {
  if (!entry.top_asn_owner) return null;
  const asnPart = entry.top_asn ? ` · ${entry.top_asn}` : '';
  let line = `${entry.top_asn_owner}${asnPart}`;
  if (entry.distinct_operators != null && entry.distinct_operators > 1) {
    line += ` +${entry.distinct_operators - 1}`;
  }
  return line;
}

/** Map-marker annotation: same "{owner} · {asn}" pair, hard-truncated to
 * `max` chars with an ellipsis (SVG <text> has no CSS text-overflow). */
function truncateAsnForMarker(entry: OriginMapEntry, max = 32): string | null {
  if (!entry.top_asn_owner) return null;
  const asnPart = entry.top_asn ? ` · ${entry.top_asn}` : '';
  const full = `${entry.top_asn_owner}${asnPart}`;
  if (full.length <= max) return full;
  return `${full.slice(0, Math.max(0, max - 1)).trimEnd()}…`;
}

/** True when the row's top ASN is the operator's own uplink — configured
 * via `homeAsn`, never inferred. Case-insensitive, whitespace-tolerant. */
function isHomeUplink(entry: OriginMapEntry, homeAsn: string | null | undefined): boolean {
  const home = homeAsn?.trim();
  const rowAsn = entry.top_asn?.trim();
  if (!home || !rowAsn) return false;
  return home.toLowerCase() === rowAsn.toLowerCase();
}

/** Local, self-contained — does not depend on globals.css having a media
 * query for this. Disables the marker-ring hover transition only. */
function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = React.useState(false);
  React.useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduced(mq.matches);
    const handler = (e: MediaQueryListEvent) => setReduced(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, []);
  return reduced;
}

interface Marker {
  code: string;
  country: string;
  count: number;
  cx: number;
  cy: number;
  r: number;
  tier: Tier;
  isTop: boolean;
  showLabel: boolean;
  /** Truncated "{owner} · {asn}" annotation, or null when unattributed. */
  asnLabel: string | null;
}

const rowFocusRing =
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-1 focus-visible:ring-offset-card';

export function OriginMap({ data, homeAsn, loading = false, error = false, onRetry }: OriginMapProps) {
  const reactId = React.useId();
  const oceanPatternId = `aegis-ocean-${reactId}`;
  const prefersReducedMotion = usePrefersReducedMotion();
  const [hoveredCode, setHoveredCode] = React.useState<string | null>(null);

  const sorted = React.useMemo(() => [...data].sort((a, b) => b.count - a.count), [data]);
  const maxCount = React.useMemo(
    () => sorted.reduce((max, d) => Math.max(max, d.count), 1),
    [sorted],
  );
  const totalAttacks = React.useMemo(() => sorted.reduce((sum, d) => sum + d.count, 0), [sorted]);
  const top5Codes = React.useMemo(
    () => new Set(sorted.slice(0, 5).map((d) => d.country_code.toUpperCase())),
    [sorted],
  );
  const topCode = sorted[0]?.country_code?.toUpperCase() ?? null;

  const markers = React.useMemo<Marker[]>(() => {
    const out: Marker[] = [];
    for (const entry of sorted) {
      const code = entry.country_code?.toUpperCase();
      const latlon = code ? CC_TO_LATLON[code] : undefined;
      if (!latlon) continue;
      const [lon, lat] = latlon;
      const [cx, cy] = projectLonLat(lon, lat);
      out.push({
        code,
        country: resolveCountryName(code).name,
        count: entry.count,
        cx,
        cy,
        r: markerRadius(entry.count, maxCount),
        tier: tierFor(entry.count, maxCount),
        isTop: code === topCode,
        showLabel: top5Codes.has(code),
        asnLabel: truncateAsnForMarker(entry),
      });
    }
    return out;
  }, [sorted, maxCount, topCode, top5Codes]);

  const unmappedCount = sorted.length - markers.length;

  const top3 = sorted.slice(0, 3);
  const ariaLabel = error
    ? 'World map of attack origins. Origin data unavailable.'
    : sorted.length === 0
      ? 'World map of attack origins. No external origins attributed.'
      : `World map of attack origins. Top sources: ${top3
          .map((d) => `${resolveCountryName(d.country_code).name} ${d.count}`)
          .join(', ')}.`;

  const handleRetry = React.useCallback(() => {
    if (onRetry) onRetry();
    else if (typeof window !== 'undefined') window.location.reload();
  }, [onRetry]);

  const showMarkers = !loading && !error && markers.length > 0;
  const showLegend = !loading && !error && sorted.length > 0;

  return (
    <Panel
      as="section"
      variant="default"
      padding="none"
      aria-label="Threat origin map"
      className="col-span-12 flex flex-col min-[820px]:flex-row min-[820px]:h-[440px] overflow-hidden"
    >
      {/* ═══ LEFT — THE MAP ═══ */}
      <div className="relative flex-1 min-w-0 h-[300px] min-[820px]:h-full p-5">
        <svg
          viewBox={`0 ${VIEW_Y} ${MAP_W} ${VIEW_H}`}
          preserveAspectRatio="xMidYMid meet"
          role="img"
          aria-label={ariaLabel}
          width="100%"
          height="100%"
          shapeRendering="geometricPrecision"
          className="block w-full h-full"
        >
          <defs>
            <pattern id={oceanPatternId} width="5" height="5" patternUnits="userSpaceOnUse">
              <circle cx="2.5" cy="2.5" r="1" fill="var(--map-ocean)" />
            </pattern>
          </defs>
          <rect x={0} y={VIEW_Y} width={MAP_W} height={VIEW_H} fill={`url(#${oceanPatternId})`} />
          <path d={LAND_PATH} fill="var(--map-land)" fillRule="nonzero" opacity={error ? 0.5 : 1} />
          {showMarkers &&
            markers.map((m) => {
              const showRing = m.isTop || hoveredCode === m.code;
              const ringOpacity = hoveredCode === m.code ? 0.55 : 0.28;
              const ringWidth = hoveredCode === m.code ? 1.5 : 1;
              return (
                <g key={m.code}>
                  {showRing && (
                    <circle
                      cx={m.cx}
                      cy={m.cy}
                      r={m.r + 3.5}
                      fill="none"
                      stroke={SEV_VAR[m.tier]}
                      strokeOpacity={ringOpacity}
                      strokeWidth={ringWidth}
                      style={prefersReducedMotion ? undefined : { transition: TRANSITION }}
                    />
                  )}
                  <circle
                    cx={m.cx}
                    cy={m.cy}
                    r={m.r}
                    fill={SEV_VAR[m.tier]}
                    fillOpacity={0.55}
                    stroke={SEV_VAR[m.tier]}
                    strokeWidth={1.25}
                  />
                  {m.showLabel && (
                    <text
                      x={m.cx}
                      y={m.cy - m.r - 4}
                      textAnchor="middle"
                      fontSize={9}
                      fontFamily="var(--font-mono)"
                      fill="var(--foreground)"
                      paintOrder="stroke"
                      stroke="var(--background)"
                      strokeWidth={2.5}
                    >
                      {m.code}
                    </text>
                  )}
                  {/* Supplementary ASN annotation — purely additive, stacked
                      above the code label so it never overlaps the marker
                      itself. The rail row (below) already carries this same
                      string without hovering, so this satisfies the
                      no-hover-only-information rule even though it renders
                      unconditionally alongside the top-5 code label. */}
                  {m.showLabel && m.asnLabel && (
                    <text
                      x={m.cx}
                      y={m.cy - m.r - 13}
                      textAnchor="middle"
                      fontSize={7}
                      fontFamily="var(--font-mono)"
                      fill="var(--muted-foreground)"
                      paintOrder="stroke"
                      stroke="var(--background)"
                      strokeWidth={2.5}
                    >
                      {m.asnLabel}
                    </text>
                  )}
                </g>
              );
            })}
        </svg>

        {/* Overlay — top-left: identity + the ONE count on the page. */}
        <div className="pointer-events-none absolute top-5 left-5 z-[2] max-w-[70%]">
          <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
            Threat Origin
          </p>
          {loading ? (
            <div
              aria-hidden
              className="mt-1.5 h-3 w-[120px] rounded-sm bg-[color-mix(in_oklab,var(--foreground)_8%,transparent)]"
            />
          ) : error ? (
            <p className="mt-1.5 font-mono tabular-nums text-[12px] font-semibold text-danger">
              ORIGIN DATA UNAVAILABLE
            </p>
          ) : sorted.length === 0 ? (
            <p className="mt-1.5 font-mono tabular-nums text-[12px] text-muted-foreground">
              NO EXTERNAL ORIGINS ATTRIBUTED
            </p>
          ) : (
            <p className="mt-1.5 font-mono tabular-nums text-[12px] text-foreground">
              {sorted.length} COUNTRIES &middot; {totalAttacks} ATTACKS
              {unmappedCount > 0 ? ` · ${unmappedCount} UNMAPPED` : ''}
            </p>
          )}
        </div>

        {/* Overlay — bottom-left: magnitude/severity legend (hidden when nothing to key). */}
        {showLegend && (
          <div className="pointer-events-none absolute bottom-5 left-5 z-[2] flex items-center gap-3.5">
            {(['critical', 'high', 'medium', 'low'] as const).map((tier) => (
              <span key={tier} className="inline-flex items-center gap-1.5">
                <span
                  aria-hidden
                  className="h-1.5 w-1.5 shrink-0 rounded-full"
                  style={{ background: SEV_VAR[tier] }}
                />
                <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">
                  {tier}
                </span>
              </span>
            ))}
          </div>
        )}

        {/* Overlay — bottom-right: honesty disclosure about server-side FP filtering. */}
        <div className="absolute bottom-5 right-5 z-[2] flex items-center gap-1.5">
          <span className="font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground/80">
            Excludes known false positives
          </span>
          <span
            tabIndex={0}
            role="img"
            aria-label="Traffic from devices confirmed as operator-owned is filtered server-side before aggregation."
            title="Traffic from devices confirmed as operator-owned is filtered server-side before aggregation."
            className="inline-flex shrink-0 rounded-sm text-muted-foreground/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
          >
            <InformationCircleIcon size={12} strokeWidth={1.8} />
          </span>
        </div>
      </div>

      {/* ═══ RIGHT — SOURCE RANK ═══ */}
      <div className="w-full min-[820px]:w-[320px] min-[820px]:h-full shrink-0 border-t min-[820px]:border-t-0 min-[820px]:border-l border-border flex flex-col pt-5 pr-5 pb-5 pl-5 min-[820px]:pl-[18px]">
        <h3 className="mb-3.5 shrink-0 text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
          By Volume
        </h3>

        {loading && (
          <ul className="flex flex-1 flex-col gap-0.5" aria-hidden>
            {Array.from({ length: 6 }).map((_, i) => (
              <li
                key={i}
                className="h-7 rounded-md bg-[color-mix(in_oklab,var(--foreground)_6%,transparent)] opacity-30"
              />
            ))}
          </ul>
        )}

        {!loading && error && (
          <div className="flex flex-col items-start gap-2.5 py-1">
            <p className="font-mono tabular-nums text-[12px] text-muted-foreground">
              Could not reach the threat-map endpoint.
            </p>
            <button
              type="button"
              onClick={handleRetry}
              className={cn(
                'font-mono tabular-nums text-[11px] font-semibold text-[var(--brand-text)] underline decoration-dotted underline-offset-2 rounded-sm px-0.5',
                rowFocusRing,
              )}
            >
              Retry
            </button>
          </div>
        )}

        {!loading && !error && sorted.length === 0 && (
          <EmptyState
            size="sm"
            title="No attributed sources"
            description="This list populates when an external IP resolves to a country. GeoIP runs offline — no lookup leaves your server."
            action={
              <Link
                href="/dashboard/surface"
                className={cn(
                  'font-mono tabular-nums text-[11px] font-semibold text-[var(--brand-text)] underline decoration-dotted underline-offset-2 rounded-sm px-0.5',
                  rowFocusRing,
                )}
              >
                Open Surface &rarr;
              </Link>
            }
            className="flex-1"
          />
        )}

        {!loading && !error && sorted.length > 0 && (
          <>
            {/* Desktop / wide: ranked rows, keyboard-operable, linked to map markers. */}
            <ol className="hidden min-[820px]:flex min-[820px]:flex-col flex-1 gap-0.5 overflow-y-auto -mx-1.5 pr-0.5">
              {sorted.map((entry, i) => {
                const code = entry.country_code?.toUpperCase() ?? '??';
                const tier = tierFor(entry.count, maxCount);
                const barPct = maxCount > 0 ? (entry.count / maxCount) * 100 : 0;
                const resolved = resolveCountryName(code);
                const asnLine = formatAsnLine(entry);
                const isUplink = isHomeUplink(entry, homeAsn);
                return (
                  <li key={code + i}>
                    <button
                      type="button"
                      onMouseEnter={() => setHoveredCode(code)}
                      onMouseLeave={() => setHoveredCode((c) => (c === code ? null : c))}
                      onFocus={() => setHoveredCode(code)}
                      onBlur={() => setHoveredCode((c) => (c === code ? null : c))}
                      className={cn(
                        'flex w-full flex-col justify-center gap-0.5 rounded-md px-1.5 text-left transition-colors duration-150 ease-[cubic-bezier(0.22,1,0.36,1)]',
                        asnLine ? 'min-h-[44px] py-1.5' : 'h-7',
                        'hover:bg-[color-mix(in_oklab,var(--foreground)_3%,transparent)]',
                        'focus-visible:bg-[color-mix(in_oklab,var(--foreground)_3%,transparent)]',
                        rowFocusRing,
                      )}
                    >
                      <span className="flex items-center gap-2.5">
                        <span className="w-[22px] shrink-0 font-mono tabular-nums text-[11px] font-semibold uppercase text-foreground">
                          {code}
                        </span>
                        <span
                          className={cn(
                            'min-w-0 flex-1 truncate text-[12px] font-normal text-muted-foreground',
                            !resolved.known && 'italic text-muted-foreground/60',
                          )}
                        >
                          {resolved.name}
                        </span>
                        {isUplink && (
                          <span
                            className="shrink-0 rounded-[4px] border px-1.5 py-[1px] font-mono text-[9px] font-semibold uppercase tracking-[0.1em]"
                            style={{
                              color: 'var(--brand-accent-text)',
                              background: 'color-mix(in oklab, var(--brand-accent) 14%, transparent)',
                              borderColor: 'color-mix(in oklab, var(--brand-accent) 30%, transparent)',
                            }}
                          >
                            Your Uplink
                          </span>
                        )}
                        <span className="h-1 w-14 shrink-0 overflow-hidden rounded-full bg-border">
                          <span
                            className="block h-1 rounded-full"
                            style={{ width: `${barPct}%`, background: SEV_VAR[tier] }}
                          />
                        </span>
                        <span className="w-[34px] shrink-0 text-right font-mono tabular-nums text-[11px] font-semibold text-foreground">
                          {entry.count}
                        </span>
                      </span>
                      {asnLine && (
                        <span className="block pl-[32px]">
                          <span
                            title={asnLine}
                            className="block truncate font-mono text-[10.5px] leading-[14px] text-muted-foreground"
                          >
                            {asnLine}
                          </span>
                        </span>
                      )}
                    </button>
                  </li>
                );
              })}
            </ol>

            {/* Narrow (<1100px): 2-col chip grid — full rows don't fit a stacked half-width panel. */}
            <div
              role="list"
              aria-label="Attack sources by volume"
              className="grid grid-cols-2 gap-2 min-[820px]:hidden"
            >
              {sorted.map((entry, i) => {
                const code = entry.country_code?.toUpperCase() ?? '??';
                const tier = tierFor(entry.count, maxCount);
                const resolved = resolveCountryName(code);
                const asnLine = formatAsnLine(entry);
                return (
                  <div
                    key={code + i}
                    role="listitem"
                    className={cn(
                      'flex flex-col justify-center gap-0.5 rounded-lg border border-border px-2.5',
                      asnLine ? 'min-h-[44px] py-1.5' : 'h-9',
                    )}
                  >
                    <span className="flex items-center gap-2">
                      <span
                        aria-hidden
                        className="h-1.5 w-1.5 shrink-0 rounded-full"
                        style={{ background: SEV_VAR[tier] }}
                      />
                      <span className="shrink-0 font-mono tabular-nums text-[11px] font-semibold uppercase text-foreground">
                        {code}
                      </span>
                      <span
                        className={cn(
                          'min-w-0 flex-1 truncate text-[11px] text-muted-foreground',
                          !resolved.known && 'italic text-muted-foreground/60',
                        )}
                      >
                        {resolved.name}
                      </span>
                      <span className="shrink-0 font-mono tabular-nums text-[11px] font-semibold text-foreground">
                        {entry.count}
                      </span>
                    </span>
                    {asnLine && (
                      <span
                        title={asnLine}
                        className="block truncate pl-[18px] text-[10px] text-muted-foreground"
                      >
                        {asnLine}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>
    </Panel>
  );
}

export default OriginMap;
