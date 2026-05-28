'use client';

import { useMemo } from 'react';
import { Panel, SectionHeader } from '@/components/aegis';

interface LoginAttemptsHeatmapProps {
  interactions: Array<{ timestamp: string; source_ip?: string }>;
  hours?: number;
  columns?: number;
}

/**
 * LoginAttemptsHeatmap — dot grid honeypot intensity.
 * Refactored to use <Panel> + <SectionHeader>.
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

  const action = (
    <span className="text-[14px] font-semibold tabular-nums text-foreground">{total}</span>
  );

  return (
    <Panel className="h-full flex flex-col">
      <SectionHeader title="Login Attempts" subtitle={`· ${hours}h`} action={action} />

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
    </Panel>
  );
}
