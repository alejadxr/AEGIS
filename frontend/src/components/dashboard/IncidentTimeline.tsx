'use client';

import { useMemo, useState, useCallback, useEffect } from 'react';
import { MinusCircle, PlusCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Panel, SectionHeader, EmptyState } from '@/components/aegis';

interface TimelineIncident {
  id: string;
  title: string;
  severity: string;        // critical/high/medium/low
  detected_at: string;     // ISO
}

// Range options in days
const RANGE_OPTIONS: { label: string; days: number }[] = [
  { label: '24h', days: 1 },
  { label: '3d', days: 3 },
  { label: '7d', days: 7 },
  { label: '14d', days: 14 },
  { label: '30d', days: 30 },
  { label: '90d', days: 90 },
];

const RANGE_KEY_MAP: Record<string, number> = {
  '1d': 1, '3d': 3, '7d': 7, '14d': 14, '30d': 30, '90d': 90,
};

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
  const key = Object.entries(RANGE_KEY_MAP).find(([, v]) => v === days)?.[0] ?? `${days}d`;
  sp.set('range', key);
  const newUrl = `${window.location.pathname}?${sp.toString()}`;
  window.history.replaceState(null, '', newUrl);
}

interface IncidentTimelineProps {
  incidents: TimelineIncident[];
  /** Initial days of history to show. Default 14. Overridden by ?range= URL param. */
  days?: number;
}

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--danger)',
  high: 'var(--brand-accent)',
  medium: 'var(--warning)',
  low: 'var(--chart-5, #22D3EE)',
};

/**
 * IncidentTimeline — horizontal time-scrubber with range selector pills
 * and zoom in/out controls.
 */
export function IncidentTimeline({ incidents, days: propDays = 14 }: IncidentTimelineProps) {
  const [days, setDays] = useState<number>(propDays);

  // Sync initial value from URL param on mount (client-only)
  useEffect(() => {
    const fromUrl = parseRangeParam();
    setDays(fromUrl);
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

  const { ticks, items, nowPct } = useMemo(() => {
    const now = Date.now();
    const start = now - days * 24 * 60 * 60 * 1000;
    const span = now - start;

    // Adaptive tick count based on range
    const tickCount = days <= 3 ? days * 24 : days <= 14 ? days : Math.ceil(days / 3);
    const ticksArr: { pct: number; label: string }[] = [];
    for (let i = 0; i <= tickCount; i++) {
      const t = new Date(start + (i / tickCount) * span);
      // Show hours label for short ranges, date for longer
      const label = days <= 3
        ? `${String(t.getHours()).padStart(2, '0')}h`
        : String(t.getDate()).padStart(2, '0');
      ticksArr.push({ pct: (i / tickCount) * 100, label });
    }

    const itemsArr = incidents
      .map((inc) => {
        const t = new Date(inc.detected_at).getTime();
        if (Number.isNaN(t) || t < start || t > now) return null;
        const pct = ((t - start) / span) * 100;
        const sev = (inc.severity || 'low').toLowerCase();
        return {
          ...inc,
          pct,
          color: SEV_COLOR[sev] ?? SEV_COLOR.low,
          sev,
        };
      })
      .filter((x): x is NonNullable<typeof x> => !!x)
      .sort((a, b) => a.pct - b.pct)
      .slice(0, 24); // performance clamp

    return { ticks: ticksArr, items: itemsArr, nowPct: 100 };
  }, [incidents, days]);

  // Distribute chips into 2 rows alternately for legibility
  const rowOf = (idx: number) => idx % 2;

  const legend = (
    <div className="flex items-center gap-3">
      {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
        <span
          key={s}
          className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground/70"
        >
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{ background: SEV_COLOR[s] }}
            aria-hidden
          />
          {s}
        </span>
      ))}
    </div>
  );

  return (
    <Panel>
      <SectionHeader
        title="Incident Timeline"
        subtitle={`· last ${days === 1 ? '24h' : `${days}d`}`}
        action={legend}
      />

      {/* Range selector + zoom controls */}
      <div className="flex items-center gap-2 px-4 sm:px-6 pt-0 pb-2">
        <div className="flex items-center gap-1 flex-wrap">
          {RANGE_OPTIONS.map((opt) => {
            const active = days === opt.days;
            return (
              <button
                key={opt.label}
                type="button"
                onClick={() => setDaysAndUrl(opt.days)}
                className={cn(
                  'text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-md border transition-colors',
                  active
                    ? 'bg-[color-mix(in_oklab,var(--brand-accent)_12%,transparent)] text-[var(--brand-accent)] border-[color-mix(in_oklab,var(--brand-accent)_30%,transparent)]'
                    : 'border-border bg-card hover:bg-muted/40 text-muted-foreground',
                )}
                aria-pressed={active}
              >
                {opt.label}
              </button>
            );
          })}
        </div>
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

      {/* Track */}
      <div className="relative px-4 sm:px-6 py-6 pt-2">
        {/* Background grid line */}
        <div className="absolute left-4 right-4 top-1/2 h-px bg-border" aria-hidden />

        <div className="relative h-32">
          {ticks.map((t, i) => (
            <div
              key={i}
              className="absolute top-1/2 -translate-y-1/2 flex flex-col items-center pointer-events-none"
              style={{ left: `${t.pct}%` }}
              aria-hidden
            >
              <span className="w-px h-2 bg-border" />
              <span className="text-[9px] font-mono text-muted-foreground/40 mt-1">
                {t.label}
              </span>
            </div>
          ))}

          {items.map((it, idx) => {
            const row = rowOf(idx);
            const top = row === 0 ? '6%' : '64%';
            return (
              <div
                key={it.id}
                className="absolute -translate-x-1/2"
                style={{ left: `${Math.min(98, Math.max(2, it.pct))}%`, top }}
                title={`${it.title} · ${it.sev}`}
              >
                <div
                  className={cn(
                    'flex items-center gap-1.5 px-2 py-1 rounded-md max-w-[180px]',
                    'bg-background/80 backdrop-blur-sm border',
                    'shadow-[0_2px_8px_-2px_rgba(0,0,0,0.25)]',
                    'transition-transform duration-150 hover:scale-[1.04]',
                  )}
                  style={{ borderColor: it.color }}
                >
                  <span
                    className="w-1.5 h-1.5 rounded-full shrink-0"
                    style={{ background: it.color }}
                    aria-hidden
                  />
                  <span className="text-[10px] text-foreground/90 truncate">{it.title}</span>
                </div>
                <div
                  className="mx-auto w-px"
                  style={{
                    height: row === 0 ? '24px' : '0',
                    background: it.color,
                    opacity: 0.5,
                  }}
                  aria-hidden
                />
              </div>
            );
          })}

          {/* Now cursor */}
          <div
            className="absolute top-0 bottom-0 w-px bg-[var(--brand-accent)]"
            style={{ left: `${nowPct}%` }}
            aria-hidden
          >
            <span className="absolute -top-1 -translate-x-1/2 flex">
              <span className="absolute inline-flex h-2.5 w-2.5 rounded-full bg-[var(--brand-accent)] opacity-60 animate-ping" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-[var(--brand-accent)]" />
            </span>
            <span className="absolute -bottom-5 -translate-x-1/2 text-[9px] font-mono uppercase tracking-wider text-[var(--brand-accent)]">
              now
            </span>
          </div>
        </div>

        {items.length === 0 && (
          <EmptyState
            size="sm"
            title={`No incidents in the last ${days === 1 ? '24 hours' : `${days} days`}`}
            description="System quiet"
          />
        )}
      </div>
    </Panel>
  );
}
