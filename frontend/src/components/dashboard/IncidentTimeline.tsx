'use client';

import { useMemo } from 'react';
import { cn } from '@/lib/utils';

interface TimelineIncident {
  id: string;
  title: string;
  severity: string;        // critical/high/medium/low
  detected_at: string;     // ISO
}

interface IncidentTimelineProps {
  incidents: TimelineIncident[];
  /** Days of history to show. Default 14. */
  days?: number;
}

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--danger)',
  high: 'var(--brand-accent)',
  medium: 'var(--warning)',
  low: 'var(--chart-5, #22D3EE)',
};

/**
 * IncidentTimeline — horizontal time-scrubber from image 1.
 *
 * X-axis: last N days with day-of-month ticks; current time marked by a vertical
 * cursor + pulsing dot. Incidents render as severity-coloured chips positioned
 * proportionally by detected_at.
 *
 * Rules applied: motion-meaning (pulse = "now"), color-not-only (severity also
 * in label + dot), tooltip-on-interact (title attr), large-dataset (clamp 24).
 */
export function IncidentTimeline({ incidents, days = 14 }: IncidentTimelineProps) {
  const { ticks, items, nowPct } = useMemo(() => {
    const now = Date.now();
    const start = now - days * 24 * 60 * 60 * 1000;
    const span = now - start;

    const ticksArr: { pct: number; label: string }[] = [];
    for (let i = 0; i <= days; i++) {
      const t = new Date(start + (i / days) * span);
      ticksArr.push({
        pct: (i / days) * 100,
        label: String(t.getDate()).padStart(2, '0'),
      });
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

  return (
    <div className="bg-card border border-border rounded-2xl overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 sm:px-5 py-3 border-b border-border">
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-muted-foreground">
            Incident Timeline
          </span>
          <span className="text-[10px] font-mono text-muted-foreground/50">
            · last {days}d
          </span>
        </div>
        <div className="flex items-center gap-3">
          {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
            <span key={s} className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground/70">
              <span className="w-1.5 h-1.5 rounded-full" style={{ background: SEV_COLOR[s] }} aria-hidden />
              {s}
            </span>
          ))}
        </div>
      </div>

      {/* Track */}
      <div className="relative px-4 sm:px-6 py-6">
        {/* Background grid line */}
        <div className="absolute left-4 right-4 top-1/2 h-px bg-border" aria-hidden />

        {/* Day ticks */}
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

          {/* Incident chips */}
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
                  <span className="text-[10px] text-foreground/90 truncate">
                    {it.title}
                  </span>
                </div>
                {/* Connector */}
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
          <div className="text-center py-2">
            <span className="text-[11px] text-muted-foreground/60">
              No incidents in the last {days} days · system quiet
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
