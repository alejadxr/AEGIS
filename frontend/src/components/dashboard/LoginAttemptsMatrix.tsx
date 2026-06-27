'use client';

import { useMemo } from 'react';
import { Panel, SectionHeader } from '@/components/aegis';

const MONTH_ABBR = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
];

export interface LoginAttemptsMatrixProps {
  data: Array<{ month: string; count: number }>;
  total: number;
  peak_month?: string;
  className?: string;
}

// Diamond / fountain cluster — fill bottom-up, widest at base.
// Row widths from bottom: 5,5,5,5,4,4,3,3,2,1 = 35 max dots, shape matches
// the operator-supplied mockup (Aug peak cluster ≈ 25-30 dense dots).
const CLUSTER_POSITIONS: Array<[number, number]> = (() => {
  const ROW_WIDTHS = [5, 5, 5, 5, 4, 4, 3, 3, 2, 1];
  const out: Array<[number, number]> = [];
  for (let r = 0; r < ROW_WIDTHS.length; r++) {
    const w = ROW_WIDTHS[r];
    const startCol = -(w - 1) / 2;
    for (let i = 0; i < w; i++) out.push([startCol + i, r]);
  }
  return out;
})();

const MAX_DOTS = CLUSTER_POSITIONS.length;

const DOT_R = 6;
const COL_GAP_X = 14;
const COL_GAP_Y = 14;
const COL_WIDTH = 96;
const BASE_Y = 196;
const TOP_PAD = 20;
const SVG_H = 240;

export function LoginAttemptsMatrix({ data, total, peak_month, className }: LoginAttemptsMatrixProps) {
  const columns = useMemo(() => {
    const filled = data.slice(-6);
    while (filled.length < 6) filled.unshift({ month: '', count: 0 });
    return filled;
  }, [data]);

  const peakCount = useMemo(
    () => columns.reduce((m, c) => Math.max(m, c.count), 0) || 1,
    [columns]
  );

  const peakIdx = useMemo(() => {
    if (peak_month) {
      const i = columns.findIndex((c) => c.month === peak_month);
      if (i >= 0) return i;
    }
    let best = -1;
    let bestVal = 0;
    columns.forEach((c, i) => {
      if (c.count > bestVal) { bestVal = c.count; best = i; }
    });
    return best;
  }, [columns, peak_month]);

  const svgW = COL_WIDTH * columns.length;

  return (
    <Panel className={`h-full flex flex-col ${className || ''}`}>
      <SectionHeader
        title="Login Attempts"
        subtitle="· 6mo"
        action={
          <span className="text-[22px] font-semibold tabular-nums font-mono text-foreground leading-none">
            {total.toLocaleString()}
          </span>
        }
      />

      <div className="flex-1 px-2 pt-2 pb-2 flex items-center justify-center overflow-hidden">
        <svg
          viewBox={`0 0 ${svgW} ${SVG_H}`}
          className="w-full h-full block"
          preserveAspectRatio="xMidYMid meet"
          role="img"
          aria-label={`Login attempts over the last 6 months. Total ${total.toLocaleString()}.`}
        >
          {columns.map((col, ci) => {
            const cx = COL_WIDTH * ci + COL_WIDTH / 2;
            const isPeak = ci === peakIdx && col.count > 0;
            const ratio = col.count / peakCount;
            const numDots = col.count === 0 ? 0 : Math.max(1, Math.round(ratio * MAX_DOTS));

            const fill = isPeak ? '#F97316' : col.count > 0 ? '#5A6172' : '#3F3F46';
            const opacity = col.count === 0 ? 0.18 : 1;

            let monthLabel = '';
            if (col.month) {
              const m = parseInt(col.month.split('-')[1] || '0', 10);
              if (m >= 1 && m <= 12) monthLabel = MONTH_ABBR[m - 1];
            }

            return (
              <g key={`${col.month || ci}`}>
                {CLUSTER_POSITIONS.slice(0, numDots).map(([dx, dy], di) => {
                  const oddRow = dy % 2 === 1;
                  const x = cx + dx * COL_GAP_X + (oddRow ? COL_GAP_X / 2 : 0);
                  const y = BASE_Y - dy * COL_GAP_Y;
                  return (
                    <circle key={di} cx={x} cy={y} r={DOT_R} fill={fill} opacity={opacity} />
                  );
                })}

                {col.count > 0 && (
                  <text
                    x={cx}
                    y={Math.max(TOP_PAD, BASE_Y - Math.ceil(numDots / 4) * COL_GAP_Y - 14)}
                    textAnchor="middle"
                    fontSize={11}
                    fontFamily="Azeret Mono, ui-monospace, monospace"
                    fontWeight={isPeak ? 700 : 500}
                    fill={isPeak ? '#F97316' : 'rgba(255,255,255,0.55)'}
                  >
                    {col.count.toLocaleString()}
                  </text>
                )}

                <text
                  x={cx}
                  y={SVG_H - 6}
                  textAnchor="middle"
                  fontSize={11}
                  fontFamily="Azeret Mono, ui-monospace, monospace"
                  fontWeight={500}
                  fill={isPeak ? 'rgba(249,115,22,0.85)' : 'rgba(255,255,255,0.5)'}
                  letterSpacing="0.06em"
                >
                  {monthLabel}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </Panel>
  );
}

export default LoginAttemptsMatrix;
