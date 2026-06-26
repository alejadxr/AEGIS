'use client';

import { useMemo, useState, useCallback, useEffect } from 'react';
import { MinusCircle, PlusCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Panel, SectionHeader, EmptyState } from '@/components/aegis';

// ─── Types ───────────────────────────────────────────────────────────────────

interface TimelineIncident {
  id: string;
  title: string;
  severity: string;        // critical/high/medium/low
  detected_at: string;     // ISO
}

interface IncidentTimelineProps {
  incidents: TimelineIncident[];
  /** Initial days of history to show. Default 14. Overridden by ?range= URL param. */
  days?: number;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const RANGE_OPTIONS: { label: string; days: number }[] = [
  { label: '24H', days: 1 },
  { label: '3D',  days: 3 },
  { label: '7D',  days: 7 },
  { label: '14D', days: 14 },
  { label: '30D', days: 30 },
  { label: '90D', days: 90 },
];

const RANGE_KEY_MAP: Record<string, number> = {
  '1d': 1, '3d': 3, '7d': 7, '14d': 14, '30d': 30, '90d': 90,
};

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--danger)',
  high:     'var(--brand-accent)',
  medium:   'var(--warning)',
  low:      'var(--chart-5, #22D3EE)',
};

// Fixed-height track layout constants (px, track is exactly 200px tall)
const TRACK_H   = 200;
const ROW0_Y    = 50;   // row-0 dot center (above axis)
const AXIS_Y    = 100;  // horizontal axis
const ROW1_Y    = 136;  // row-1 dot center (below axis)
const LABEL_Y   = 174;  // tick label baseline
const DOT_R     = 4;    // dot radius in px (w-2 h-2 → diameter 8px)

// ─── Helpers ─────────────────────────────────────────────────────────────────

function parseRangeParam(): number {
  if (typeof window === 'undefined') return 14;
  const sp = new URLSearchParams(window.location.search);
  const r = sp.get('range');
  if (r && RANGE_KEY_MAP[r] !== undefined) return RANGE_KEY_MAP[r];
  return 14;
}

function setRangeParam(days: number) {
  if (typeof window === 'undefined') return;
  const sp = new URLSearchParams(window.location.search);
  const key =
    Object.entries(RANGE_KEY_MAP).find(([, v]) => v === days)?.[0] ?? `${days}d`;
  sp.set('range', key);
  window.history.replaceState(null, '', `${window.location.pathname}?${sp.toString()}`);
}

function formatRelative(ts: number, now: number): string {
  const diff = now - ts;
  const mins  = Math.floor(diff / 60_000);
  const hours = Math.floor(diff / 3_600_000);
  const d     = Math.floor(diff / 86_400_000);
  if (mins < 2)   return 'just now';
  if (mins < 60)  return `${mins}m ago`;
  if (hours < 24) return `${hours}h ago`;
  return `${d}d ago`;
}

function formatTickLabel(ts: number, spanMs: number): string {
  const d = new Date(ts);
  if (spanMs <= 6 * 3_600_000) {
    // â‰¤ 6 h → HH:MM
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  }
  if (spanMs <= 48 * 3_600_000) {
    // â‰¤ 48 h → DD/MM HH:00
    return `${d.getDate()}/${d.getMonth() + 1} ${String(d.getHours()).padStart(2, '0')}h`;
  }
  // longer → DD/MM
  return `${d.getDate()}/${d.getMonth() + 1}`;
}

// ─── Component ───────────────────────────────────────────────────────────────

/**
 * IncidentTimeline — horizontal time-scrubber with range selector pills,
 * auto-zoom when events cluster, count badges per range, dot events with
 * hover halo + tooltip, ruler lines, and a fixed 200px canvas height.
 */
export function IncidentTimeline({ incidents, days: propDays = 14 }: IncidentTimelineProps) {
  const [days, setDays]           = useState<number>(propDays);
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  // Sync with URL param on mount (client-only)
  useEffect(() => {
    setDays(parseRangeParam());
  }, []);

  const setDaysAndUrl = useCallback((d: number) => {
    setDays(d);
    setRangeParam(d);
  }, []);

  const zoomIn = useCallback(() => {
    setDays((d) => {
      const next = Math.max(1, Math.round(d / 2));
      setRangeParam(next);
      return next;
    });
  }, []);

  const zoomOut = useCallback(() => {
    setDays((d) => {
      const next = Math.min(90, d * 2);
      setRangeParam(next);
      return next;
    });
  }, []);

  // Count incidents per range for badges
  const countPerRange = useMemo<Record<number, number>>(() => {
    const now = Date.now();
    return Object.fromEntries(
      RANGE_OPTIONS.map((opt) => {
        const start = now - opt.days * 86_400_000;
        const count = incidents.filter((inc) => {
          const t = new Date(inc.detected_at).getTime();
          return !Number.isNaN(t) && t >= start && t <= now;
        }).length;
        return [opt.days, count];
      }),
    );
  }, [incidents]);

  // Compute track viewport (auto-zoom), ticks, and event positions
  const derived = useMemo(() => {
    const now        = Date.now();
    const rangeStart = now - days * 86_400_000;
    const rangeSpan  = now - rangeStart;

    // Collect incidents within the selected range
    const inRange = incidents
      .map((inc) => {
        const t = new Date(inc.detected_at).getTime();
        if (Number.isNaN(t) || t < rangeStart || t > now) return null;
        const sev = (inc.severity || 'low').toLowerCase();
        return { ...inc, t, sev, color: SEV_COLOR[sev] ?? SEV_COLOR.low };
      })
      .filter((x): x is NonNullable<typeof x> => x !== null)
      .sort((a, b) => a.t - b.t);

    // Auto-zoom: if all events span < 30% of the selected range, tighten the viewport
    let trackStart   = rangeStart;
    let trackEnd     = now;
    let isAutoZoomed = false;

    if (inRange.length > 0) {
      const minT     = inRange[0].t;
      const maxT     = inRange[inRange.length - 1].t;
      const dataSpan = Math.max(maxT - minT, 1);

      if (dataSpan < rangeSpan * 0.3) {
        // Pad 20% on each side, minimum 30 minutes
        const pad      = Math.max(dataSpan * 0.2, 30 * 60_000);
        trackStart     = Math.max(rangeStart, minT - pad);
        trackEnd       = Math.min(now + 5 * 60_000, maxT + pad);
        // Enforce minimum viewport of 1 hour so the track isn't crushed
        const minSpan  = 3_600_000;
        if (trackEnd - trackStart < minSpan) {
          const center = (trackStart + trackEnd) / 2;
          trackStart   = center - minSpan / 2;
          trackEnd     = center + minSpan / 2;
        }
        isAutoZoomed = true;
      }
    }

    const trackSpan = trackEnd - trackStart;

    // Pick tick interval based on viewport span
    let tickIntervalMs: number;
    if      (trackSpan <= 2  * 3_600_000)  tickIntervalMs = 15 * 60_000;    // 15 min
    else if (trackSpan <= 6  * 3_600_000)  tickIntervalMs = 3_600_000;      // 1 h
    else if (trackSpan <= 24 * 3_600_000)  tickIntervalMs = 4 * 3_600_000;  // 4 h
    else if (trackSpan <= 72 * 3_600_000)  tickIntervalMs = 12 * 3_600_000; // 12 h
    else if (trackSpan <= 14 * 86_400_000) tickIntervalMs = 86_400_000;     // 1 d
    else                                    tickIntervalMs = 7 * 86_400_000; // 1 w

    // Ensure at most ~10 ticks
    const estCount = Math.floor(trackSpan / tickIntervalMs);
    if (estCount > 10) tickIntervalMs = tickIntervalMs * Math.ceil(estCount / 8);

    // Align tick starts to clean calendar boundaries
    const firstTick = Math.ceil(trackStart / tickIntervalMs) * tickIntervalMs;
    const ticks: { pct: number; label: string }[] = [];
    for (let ts = firstTick; ts <= trackEnd; ts += tickIntervalMs) {
      const pct = ((ts - trackStart) / trackSpan) * 100;
      if (pct < 0 || pct > 100) continue;
      ticks.push({ pct, label: formatTickLabel(ts, trackSpan) });
    }

    // Map incidents to horizontal %
    const items = inRange
      .slice(0, 40) // performance cap
      .map((inc, idx) => ({
        ...inc,
        pct: Math.max(1, Math.min(99, ((inc.t - trackStart) / trackSpan) * 100)),
        row: idx % 2 as 0 | 1,
      }));

    const nowPct   = ((now - trackStart) / trackSpan) * 100;
    const showNow  = nowPct >= 0 && nowPct <= 100;

    const firstIncidentAgo =
      inRange.length > 0 ? formatRelative(inRange[0].t, now) : null;

    return { ticks, items, isAutoZoomed, firstIncidentAgo, nowPct, showNow, trackStart, trackEnd };
  }, [incidents, days]);

  const { ticks, items, isAutoZoomed, firstIncidentAgo, nowPct, showNow } = derived;

  // ── Legend (right slot of SectionHeader) ──
  const legend = (
    <div className="flex items-center gap-3">
      {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
        <span
          key={s}
          className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground/70"
        >
          <span className="w-2 h-2 rounded-full" style={{ background: SEV_COLOR[s] }} aria-hidden />
          {s}
        </span>
      ))}
    </div>
  );

  // ── Subtitle ──
  const subtitle = isAutoZoomed
    ? `Â· last ${days === 1 ? '24h' : `${days}d`} Â· auto-zoomed`
    : `Â· last ${days === 1 ? '24h' : `${days}d`}`;

  return (
    <Panel>
      <SectionHeader title="Incident Timeline" subtitle={subtitle} action={legend} />

      {/* ── Range pills + zoom controls ── */}
      <div className="flex items-center gap-2 px-4 sm:px-5 pt-3 pb-2 flex-wrap">
        <div className="flex items-center gap-1 flex-wrap">
          {RANGE_OPTIONS.map((opt) => {
            const active = days === opt.days;
            const count  = countPerRange[opt.days] ?? 0;
            return (
              <button
                key={opt.label}
                type="button"
                onClick={() => setDaysAndUrl(opt.days)}
                className={cn(
                  'inline-flex items-center gap-1 text-[10px] uppercase tracking-wider',
                  'px-2 py-0.5 rounded-md border transition-colors',
                  active
                    ? 'bg-[color-mix(in_oklab,var(--brand-accent)_12%,transparent)] text-[var(--brand-accent)] border-[color-mix(in_oklab,var(--brand-accent)_30%,transparent)]'
                    : 'border-border bg-card hover:bg-muted/40 text-muted-foreground',
                )}
                aria-pressed={active}
              >
                {opt.label}
                {count > 0 && (
                  <span
                    className={cn(
                      'font-mono text-[9px] px-1 rounded leading-tight',
                      active
                        ? 'bg-[color-mix(in_oklab,var(--brand-accent)_20%,transparent)] text-[var(--brand-accent)]'
                        : 'bg-muted/60 text-muted-foreground/70',
                    )}
                  >
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {isAutoZoomed && (
          <span className="text-[9px] font-mono text-muted-foreground/40 ml-1 select-none">
            âŠ™ zoomed
          </span>
        )}

        <div className="flex items-center gap-1 ml-auto shrink-0">
          <button
            type="button"
            onClick={zoomIn}
            disabled={days <= 1}
            className={cn(
              'p-1 rounded-md text-muted-foreground transition-colors',
              'hover:text-foreground hover:bg-muted/40',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand-accent)]/60',
              'disabled:opacity-30 disabled:cursor-not-allowed',
            )}
            aria-label="Zoom in"
          >
            <PlusCircle size={14} />
          </button>
          <button
            type="button"
            onClick={zoomOut}
            disabled={days >= 90}
            className={cn(
              'p-1 rounded-md text-muted-foreground transition-colors',
              'hover:text-foreground hover:bg-muted/40',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand-accent)]/60',
              'disabled:opacity-30 disabled:cursor-not-allowed',
            )}
            aria-label="Zoom out"
          >
            <MinusCircle size={14} />
          </button>
        </div>
      </div>

      {/* ── Track canvas ── */}
      <div className="px-4 sm:px-5 pb-4">
        {/* Fixed 200px height so siblings below never get negative dimensions */}
        <div className="relative h-[200px]" style={{ overflow: 'visible' }}>

          {/* ── Empty state ── */}
          {items.length === 0 && (
            <div className="absolute inset-0 flex flex-col items-center justify-center gap-1 pointer-events-none">
              {/* Still draw a faint axis so the empty area has structure */}
              <div className="absolute left-0 right-0 h-px bg-border/30" style={{ top: AXIS_Y }} aria-hidden />
              <span className="text-[11px] font-mono text-muted-foreground/45 relative z-10">
                No incidents in this window
              </span>
              <span className="text-[9px] font-mono text-muted-foreground/30 relative z-10">
                System quiet
              </span>
            </div>
          )}

          {items.length > 0 && (
            <>
              {/* ── Vertical ruler lines (per tick) ── */}
              {ticks.map((tick, i) => (
                <div
                  key={`ruler-${i}`}
                  className="absolute w-px bg-border/20 pointer-events-none"
                  style={{
                    left:   `${tick.pct}%`,
                    top:    0,
                    height: LABEL_Y - 4,
                  }}
                  aria-hidden
                />
              ))}

              {/* ── Horizontal axis ── */}
              <div
                className="absolute left-0 right-0 h-px bg-border"
                style={{ top: AXIS_Y }}
                aria-hidden
              />

              {/* ── Tick labels ── */}
              {ticks.map((tick, i) => (
                <div
                  key={`label-${i}`}
                  className="absolute flex flex-col items-center pointer-events-none"
                  style={{
                    left:      `${tick.pct}%`,
                    top:       LABEL_Y,
                    transform: 'translateX(-50%)',
                  }}
                  aria-hidden
                >
                  <span className="block w-px h-1.5 bg-border/50" />
                  <span className="text-[8px] font-mono text-muted-foreground/40 whitespace-nowrap mt-0.5">
                    {tick.label}
                  </span>
                </div>
              ))}

              {/* ── First-incident annotation (auto-zoom context) ── */}
              {isAutoZoomed && firstIncidentAgo && (
                <div
                  className="absolute top-2 left-0 pointer-events-none"
                  aria-hidden
                >
                  <span className="text-[9px] font-mono text-muted-foreground/40">
                    first: {firstIncidentAgo}
                  </span>
                </div>
              )}

              {/* ── Now cursor ── */}
              {showNow && (
                <div
                  className="absolute pointer-events-none"
                  style={{
                    left:   `${Math.min(99.5, nowPct)}%`,
                    top:    0,
                    bottom: TRACK_H - LABEL_Y + 4,
                  }}
                  aria-hidden
                >
                  <div className="relative w-px h-full bg-[var(--brand-accent)]">
                    <span className="absolute -top-0.5 -translate-x-1/2 flex">
                      <span className="absolute inline-flex h-2.5 w-2.5 rounded-full bg-[var(--brand-accent)] opacity-60 animate-ping" />
                      <span className="relative inline-flex h-2   w-2   rounded-full bg-[var(--brand-accent)]" />
                    </span>
                    <span className="absolute top-full translate-y-1 -translate-x-1/2 text-[8px] font-mono uppercase tracking-wider text-[var(--brand-accent)] whitespace-nowrap">
                      now
                    </span>
                  </div>
                </div>
              )}

              {/* ── Connector lines + event dots ── */}
              {items.map((it) => {
                const isHovered = hoveredId === it.id;
                const dotY      = it.row === 0 ? ROW0_Y : ROW1_Y;

                // Connector from dot edge to axis
                const connectorTop    = it.row === 0 ? dotY + DOT_R : AXIS_Y;
                const connectorHeight = Math.abs(AXIS_Y - dotY) - DOT_R;

                // Tooltip placement: above for row-0, below for row-1
                const tooltipAbove = it.row === 0;

                return (
                  <div key={it.id}>
                    {/* Vertical connector */}
                    <div
                      className="absolute w-px pointer-events-none"
                      style={{
                        left:      `${it.pct}%`,
                        top:       connectorTop,
                        height:    Math.max(0, connectorHeight),
                        background: it.color,
                        opacity:   0.35,
                        transform: 'translateX(-50%)',
                      }}
                      aria-hidden
                    />

                    {/* Dot + halo + tooltip wrapper */}
                    <div
                      className="absolute"
                      style={{
                        left:      `${it.pct}%`,
                        top:       dotY,
                        transform: 'translate(-50%, -50%)',
                        zIndex:    isHovered ? 40 : 10,
                      }}
                      onMouseEnter={() => setHoveredId(it.id)}
                      onMouseLeave={() => setHoveredId(null)}
                    >
                      {/* Halo ring (appears on hover) */}
                      <div
                        className="absolute rounded-full transition-all duration-200 pointer-events-none"
                        style={{
                          inset:      -10,
                          background: it.color,
                          opacity:    isHovered ? 0.22 : 0,
                        }}
                        aria-hidden
                      />

                      {/* Dot */}
                      <div
                        className="w-2 h-2 rounded-full cursor-pointer transition-transform duration-150"
                        style={{
                          background: it.color,
                          transform:  isHovered ? 'scale(1.6)' : 'scale(1)',
                          boxShadow:  isHovered
                            ? `0 0 0 2px color-mix(in oklab, ${it.color} 40%, transparent)`
                            : 'none',
                        }}
                        role="button"
                        tabIndex={0}
                        aria-label={`${it.title} — ${it.sev} — ${formatRelative(it.t, Date.now())}`}
                      />

                      {/* Tooltip */}
                      {isHovered && (
                        <div
                          className={cn(
                            'absolute z-50 w-max max-w-[220px] px-2.5 py-2 rounded-xl',
                            'bg-card border border-border',
                            'shadow-[0_4px_16px_-4px_rgba(0,0,0,0.5)]',
                            'pointer-events-none',
                            'left-1/2 -translate-x-1/2',
                            tooltipAbove
                              ? 'bottom-[calc(100%+14px)]'
                              : 'top-[calc(100%+14px)]',
                          )}
                          role="tooltip"
                        >
                          <p className="text-[10px] font-medium text-foreground/90 leading-snug">
                            {it.title}
                          </p>
                          <p className="flex items-center gap-1.5 mt-1 text-[9px] font-mono text-muted-foreground/70">
                            <span
                              className="w-1.5 h-1.5 rounded-full shrink-0"
                              style={{ background: it.color }}
                              aria-hidden
                            />
                            {it.sev}
                            <span className="text-muted-foreground/40">Â·</span>
                            {formatRelative(it.t, Date.now())}
                          </p>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </>
          )}
        </div>
      </div>
    </Panel>
  );
}
