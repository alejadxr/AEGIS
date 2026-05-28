'use client';

import { useMemo } from 'react';

interface LoginAttemptsHeatmapProps {
  /** Honeypot interactions with timestamps. */
  interactions: Array<{ timestamp: string; source_ip?: string }>;
  /** Hours of history to render. Default 24. */
  hours?: number;
  /** Grid columns. Default 12 (so rows = hours/cols * scale). */
  columns?: number;
}

/**
 * LoginAttemptsHeatmap — dot grid honeypot intensity matching image 1.
 *
 * Buckets interactions into time slots of (hours*60 / cells) minutes. Each cell's
 * orange intensity scales with bucket density. CSS grid of divs (no svg).
 *
 * Rules: color-not-only (also size scale), chart-loading skeleton n/a (cheap),
 * tooltip-on-interact via title attr.
 */
export function LoginAttemptsHeatmap({
  interactions,
  hours = 24,
  columns = 12,
}: LoginAttemptsHeatmapProps) {
  const ROWS = 8;
  const cells = columns * ROWS;

  const { matrix, total } = useMemo(() => {
    const now = Date.now();
    const start = now - hours * 60 * 60 * 1000;
    const slotMs = (hours * 60 * 60 * 1000) / cells;
    const counts = new Array<number>(cells).fill(0);
    let totalIn = 0;
    for (const i of interactions) {
      const t = new Date(i.timestamp).getTime();
      if (Number.isNaN(t) || t < start || t > now) continue;
      const idx = Math.min(cells - 1, Math.floor((t - start) / slotMs));
      counts[idx]++;
      totalIn++;
    }
    return { matrix: counts, total: totalIn };
  }, [interactions, hours, cells]);

  const peak = Math.max(1, ...matrix);

  return (
    <div className="bg-card border border-border rounded-2xl overflow-hidden h-full flex flex-col">
      <div className="flex items-center justify-between px-4 sm:px-5 py-3 border-b border-border">
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-muted-foreground">
            Login Attempts
          </span>
          <span className="text-[10px] font-mono text-muted-foreground/50">· {hours}h</span>
        </div>
        <span className="text-[14px] font-semibold tabular-nums text-foreground">
          {total}
        </span>
      </div>

      <div
        className="flex-1 p-4 sm:p-5 flex items-center justify-center"
        role="img"
        aria-label={`Login attempts heatmap, ${total} attempts in the last ${hours} hours.`}
      >
        <div
          className="grid gap-1.5 w-full"
          style={{
            gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))`,
            gridTemplateRows: `repeat(${ROWS}, 1fr)`,
          }}
        >
          {matrix.map((c, idx) => {
            const intensity = c / peak; // 0..1
            // Use both opacity AND scale so colorblind users still see hot cells.
            const size = 0.55 + intensity * 0.45;
            const op = c === 0 ? 0.08 : 0.25 + intensity * 0.75;
            return (
              <div
                key={idx}
                className="aspect-square rounded-sm flex items-center justify-center"
                title={c > 0 ? `${c} attempts` : '—'}
              >
                <span
                  className="rounded-sm transition-transform duration-200"
                  style={{
                    width: `${size * 100}%`,
                    height: `${size * 100}%`,
                    background:
                      c === 0
                        ? 'var(--border)'
                        : `rgba(249, 115, 22, ${op})`,
                  }}
                  aria-hidden
                />
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
