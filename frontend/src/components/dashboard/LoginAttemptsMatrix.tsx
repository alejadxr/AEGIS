'use client';

import { useMemo, useState } from 'react';
import { Panel, SectionHeader } from '@/components/aegis';
import { cn } from '@/lib/utils';

// ─── Design constants ──────────────────────────────────────────────────────

const MONTH_ABBR = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
];

const SVG_H          = 280;
const COL_COUNT      = 6;
const MAX_DOTS       = 18;
const DOT_R          = 4.5;                              // radius (9 px diameter)
const COUNT_ZONE_H   = 32;                               // top zone reserved for count label
const MONTH_ZONE_H   = 26;                               // bottom zone for month label
const DOT_AREA_H     = SVG_H - COUNT_ZONE_H - MONTH_ZONE_H; // 222 px
const DOT_Y_TOP      = COUNT_ZONE_H;                     // 32
const DOT_Y_BOTTOM   = SVG_H - MONTH_ZONE_H;            // 254
const DOT_SLOT       = DOT_AREA_H / MAX_DOTS;            // ~12.33 px per row

// Colors
const COL_PEAK         = '#F97316';  // orange  — peak month
const COL_ACTIVE       = '#FBBF24';  // amber   — non-zero, non-peak
const COL_ACTIVE_HOVER = '#FDE68A';  // amber-lighter on hover
const COL_PEAK_HOVER   = '#FB923C';  // orange-lighter on hover
const COL_MUTED        = '#3F3F46';  // zinc-700 — zero months

// Pre-computed column geometry
const COL_WIDTH_PCT = `${(100 / COL_COUNT).toFixed(2)}%`;

// ─── Pure helpers (all SSR-safe — no Math.random, no Date.now) ────────────

const colCenterPct = (ci: number): string =>
  `${(((ci + 0.5) / COL_COUNT) * 100).toFixed(2)}%`;

const colLeftPct = (ci: number): string =>
  `${((ci / COL_COUNT) * 100).toFixed(2)}%`;

/** y-centre of dot row di (di=0 → bottommost row) */
const dotCy = (di: number): number =>
  DOT_Y_BOTTOM - (di + 0.5) * DOT_SLOT;

/**
 * Deterministic horizontal jitter in [-5, 5] px.
 * Integer-only arithmetic — produces stable output on server and client.
 */
const dotJitter = (di: number, ci: number): number =>
  ((di * 7 + ci * 13) % 11) - 5;

/** Scale count → [1, MAX_DOTS]; returns 0 only when count === 0 */
const scaleDots = (count: number, peak: number): number =>
  count === 0 ? 0 : Math.max(1, Math.round((count / peak) * MAX_DOTS));

// ─── Props ─────────────────────────────────────────────────────────────────

export interface LoginAttemptsMatrixProps {
  /** Monthly totals. `month` format: "YYYY-MM". */
  data: Array<{ month: string; count: number }>;
  /** Aggregate total displayed prominently in the header. */
  total: number;
  /**
   * "YYYY-MM" key to highlight in orange.
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
  const [hoveredCol, setHoveredCol] = useState<number | null>(null);

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
        subtitle="Â· 6mo"
        action={
          <span className="text-3xl font-mono font-bold tabular-nums leading-none text-foreground">
            {total.toLocaleString()}
          </span>
        }
      />

      <div
        className="flex-1 px-1 pt-2 pb-2 min-h-[260px]"
        role="img"
        aria-label={`Login attempts — last 6 months. Total: ${total}.`}
      >
        <svg
          width="100%"
          height={SVG_H}
          overflow="visible"
          aria-hidden="true"
          style={{ display: 'block' }}
        >
          {months.map((col, ci) => {
            const isPeak    = col.month === peakMonth && col.count > 0;
            const isHovered = hoveredCol === ci;
            const nDots     = scaleDots(col.count, peakCount);
            const cx        = colCenterPct(ci);

            // Fill color per dot state
            const baseFill = isPeak ? COL_PEAK : col.count > 0 ? COL_ACTIVE : COL_MUTED;
            const hoverFill = isPeak ? COL_PEAK_HOVER : COL_ACTIVE_HOVER;
            const activeFill = isHovered && col.count > 0 ? hoverFill : baseFill;

            // Label color
            const labelFill = col.count > 0 ? baseFill : COL_MUTED;
            const labelOpacity =
              col.count > 0
                ? isHovered ? 1 : 0.85
                : isHovered ? 0.6 : 0.35;

            return (
              <g
                key={col.month}
                onMouseEnter={() => setHoveredCol(ci)}
                onMouseLeave={() => setHoveredCol(null)}
                style={{
                  transform: isHovered ? 'translateY(-3px)' : 'translateY(0px)',
                  transition: 'transform 0.15s ease',
                  cursor: 'default',
                }}
              >
                {/* Per-column background track — grid shows ONLY behind each column */}
                <rect
                  x={colLeftPct(ci)}
                  y={DOT_Y_TOP}
                  width={COL_WIDTH_PCT}
                  height={DOT_AREA_H}
                  rx={6}
                  fill={
                    isHovered
                      ? 'rgba(255,255,255,0.06)'
                      : 'rgba(255,255,255,0.025)'
                  }
                  style={{ transition: 'fill 0.15s ease' }}
                />

                {/* Count label above the dot column */}
                <text
                  x={cx}
                  y={COUNT_ZONE_H - 8}
                  textAnchor="middle"
                  fontSize={isHovered ? 12 : 11}
                  fontWeight={isPeak || isHovered ? 'bold' : 'normal'}
                  fontFamily="'Azeret Mono', monospace"
                  fill={labelFill}
                  opacity={labelOpacity}
                  style={{ transition: 'opacity 0.15s ease' }}
                >
                  {col.count}
                </text>

                {/* Ghost dots — zero-count month placeholder */}
                {col.count === 0 &&
                  Array.from({ length: MAX_DOTS }, (_, di) => (
                    <circle
                      key={di}
                      cx={cx}
                      cy={dotCy(di)}
                      r={DOT_R}
                      transform={`translate(${dotJitter(di, ci)}, 0)`}
                      fill={COL_MUTED}
                      opacity={isHovered ? 0.28 : 0.14}
                    />
                  ))}

                {/* Active dots — bottom-anchored, growing upward */}
                {col.count > 0 &&
                  Array.from({ length: nDots }, (_, di) => (
                    <circle
                      key={di}
                      cx={cx}
                      cy={dotCy(di)}
                      r={DOT_R}
                      transform={`translate(${dotJitter(di, ci)}, 0)`}
                      fill={activeFill}
                      opacity={isHovered ? 1 : 0.88}
                    />
                  ))}

                {/* Month abbreviation below the dot area */}
                <text
                  x={cx}
                  y={SVG_H - 6}
                  textAnchor="middle"
                  fontSize={10}
                  fontFamily="'Azeret Mono', monospace"
                  fill={isHovered ? activeFill : 'var(--muted-foreground)'}
                  opacity={isHovered ? 0.95 : 0.55}
                  style={{ transition: 'fill 0.15s ease, opacity 0.15s ease' }}
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
