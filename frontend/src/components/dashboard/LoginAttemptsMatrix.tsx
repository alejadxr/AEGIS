'use client';

import { useMemo } from 'react';
import { Panel, SectionHeader } from '@/components/aegis';
import { cn } from '@/lib/utils';

// ─── Design constants ──────────────────────────────────────────────────────

const MONTH_ABBR = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
];

const SVG_H        = 220;
const COL_COUNT    = 6;
const MAX_DOTS     = 25;
const DOT_R        = 2.5;                                 // radius ≈ 5 px diameter
const DOT_Y_BOTTOM = SVG_H - 24;                          // 196 – baseline row
const DOT_Y_TOP    = 28;                                   // ceiling row
const DOT_AREA_H   = DOT_Y_BOTTOM - DOT_Y_TOP;            // 168 px
const DOT_SLOT     = DOT_AREA_H / MAX_DOTS;               // 6.72 px per slot

// ─── Pure helpers ──────────────────────────────────────────────────────────

/** Horizontal fraction [0–1] of column ci's centre */
const colFrac = (ci: number) => (ci + 0.5) / COL_COUNT;

/**
 * Deterministic horizontal jitter in [-9, 9] px.
 * Uses only integer arithmetic — no Math.random.
 */
const dotJitter = (di: number, ci: number): number =>
  ((di * 7 + ci * 13) % 19) - 9;

/** y-centre of dot row di (0 = bottommost row) */
const dotCy = (di: number): number =>
  DOT_Y_BOTTOM - (di + 0.5) * DOT_SLOT;

/** Scale count → [1, MAX_DOTS]; returns 0 only when count === 0 */
const scaleDots = (count: number, peak: number): number =>
  count === 0 ? 0 : Math.max(1, Math.round((count / peak) * MAX_DOTS));

// ─── Static background-grid data (module-level, computed once) ────────────

const GRID_X_FRACS = Array.from({ length: 14 }, (_, i) => (i + 0.5) / 14);
const GRID_Y_POS = Array.from(
  { length: Math.ceil((DOT_Y_BOTTOM - DOT_Y_TOP - 8) / 20) },
  (_, j) => DOT_Y_TOP + 4 + j * 20,
);

// ─── Props ─────────────────────────────────────────────────────────────────

export interface LoginAttemptsMatrixProps {
  /** Array of monthly totals. `month` format: "YYYY-MM". */
  data: Array<{ month: string; count: number }>;
  /** Aggregate total displayed in the header action slot. */
  total: number;
  /**
   * Optional "YYYY-MM" key to highlight in orange.
   * Auto-detected as the highest-count month when omitted.
   */
  peak_month?: string;
  className?: string;
}

// ─── Component ─────────────────────────────────────────────────────────────

export function LoginAttemptsMatrix({
  data,
  total,
  peak_month,
  className,
}: LoginAttemptsMatrixProps) {
  /** 6-month window ending at the current calendar month */
  const months = useMemo(() => {
    const now = new Date();
    return Array.from({ length: COL_COUNT }, (_, i) => {
      const d = new Date(now.getFullYear(), now.getMonth() - (COL_COUNT - 1 - i), 1);
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
      const found = data.find((x) => x.month === key);
      return {
        month: key,
        abbr: MONTH_ABBR[d.getMonth()],
        count: found?.count ?? 0,
      };
    });
  }, [data]);

  const peakMonth = useMemo(() => {
    if (peak_month) return peak_month;
    const maxVal = Math.max(...months.map((m) => m.count));
    if (maxVal === 0) return '';
    return months.find((m) => m.count === maxVal)?.month ?? '';
  }, [months, peak_month]);

  const peakCount = useMemo(
    () => Math.max(...months.map((m) => m.count), 1),
    [months],
  );

  return (
    <Panel className={cn('h-full flex flex-col', className)}>
      <SectionHeader
        title="Login Attempts"
        subtitle="· 6mo"
        action={
          <span className="text-[14px] font-semibold tabular-nums text-foreground font-mono">
            {total}
          </span>
        }
      />

      <div
        className="flex-1 px-2 pt-2 pb-3 min-h-[220px]"
        role="img"
        aria-label={`Login attempts — last 6 months. Total: ${total}.`}
      >
        <svg
          width="100%"
          height={SVG_H}
          aria-hidden="true"
          style={{ display: 'block' }}
        >
          {/* Subtle dotted background grid */}
          <g className="opacity-[0.12] dark:opacity-[0.28]">
            {GRID_X_FRACS.map((xf, gi) =>
              GRID_Y_POS.map((gy, gj) => (
                <circle
                  key={`g-${gi}-${gj}`}
                  cx={`${(xf * 100).toFixed(1)}%`}
                  cy={gy}
                  r={0.8}
                  fill="var(--muted-foreground)"
                />
              )),
            )}
          </g>

          {/* One column per month */}
          {months.map((col, ci) => {
            const xPct   = `${(colFrac(ci) * 100).toFixed(1)}%`;
            const isPeak = col.month === peakMonth && col.count > 0;
            const fill   = isPeak ? '#F97316' : '#3F3F46';
            const nDots  = scaleDots(col.count, peakCount);
            // y-centre of the topmost active dot (used to position the count label)
            const topCy  = nDots > 0 ? dotCy(nDots - 1) : 0;

            return (
              <g key={col.month}>
                {/* Ghost column — zero-count months get 25 faint dots */}
                {col.count === 0 &&
                  Array.from({ length: MAX_DOTS }, (_, di) => (
                    <circle
                      key={di}
                      cx={xPct}
                      cy={dotCy(di)}
                      r={DOT_R}
                      transform={`translate(${dotJitter(di, ci)}, 0)`}
                      fill="var(--muted-foreground)"
                      opacity={0.12}
                    />
                  ))}

                {/* Active dots — bottom-anchored, grow upward */}
                {col.count > 0 &&
                  Array.from({ length: nDots }, (_, di) => (
                    <circle
                      key={di}
                      cx={xPct}
                      cy={dotCy(di)}
                      r={DOT_R}
                      transform={`translate(${dotJitter(di, ci)}, 0)`}
                      fill={fill}
                      opacity={isPeak ? 1 : 0.7}
                    />
                  ))}

                {/* Monthly count label — just above the column top */}
                {col.count > 0 && (
                  <text
                    x={xPct}
                    y={topCy - DOT_R - 4}
                    textAnchor="middle"
                    fontSize={10}
                    fontFamily="'Azeret Mono', monospace"
                    fill="var(--foreground)"
                    opacity={0.85}
                  >
                    {col.count}
                  </text>
                )}

                {/* Month abbreviation below the dot area */}
                <text
                  x={xPct}
                  y={SVG_H - 5}
                  textAnchor="middle"
                  fontSize={9}
                  fontFamily="'Azeret Mono', monospace"
                  fill="var(--muted-foreground)"
                  opacity={0.5}
                >
                  {col.abbr}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </Panel>
  );
}
