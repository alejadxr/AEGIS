'use client';

import { useMemo } from 'react';
import {
  Area,
  AreaChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Panel, SectionHeader } from '@/components/aegis';

interface ThreatDetectionChartProps {
  incidents: Array<{ detected_at: string; severity: string }>;
  days?: number;
}

/**
 * ThreatDetectionChart — gradient area chart.
 * Refactored to use <Panel> + <SectionHeader>.
 */
export function ThreatDetectionChart({ incidents, days = 7 }: ThreatDetectionChartProps) {
  const { data, peak, total } = useMemo(() => {
    const now = new Date();
    const bins: { day: string; count: number; ts: number }[] = [];
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      d.setHours(0, 0, 0, 0);
      bins.push({
        day: `${String(d.getMonth() + 1).padStart(2, '0')}/${String(d.getDate()).padStart(2, '0')}`,
        count: 0,
        ts: d.getTime(),
      });
    }
    let totalIn = 0;
    for (const inc of incidents) {
      const t = new Date(inc.detected_at).getTime();
      if (Number.isNaN(t)) continue;
      const dayStart = new Date(t);
      dayStart.setHours(0, 0, 0, 0);
      const bin = bins.find((b) => b.ts === dayStart.getTime());
      if (bin) {
        bin.count++;
        totalIn++;
      }
    }
    const peakVal = bins.reduce((m, b) => Math.max(m, b.count), 0);
    return { data: bins, peak: peakVal, total: totalIn };
  }, [incidents, days]);

  const action = (
    <div className="flex items-center gap-3">
      <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground/70">
        total
      </span>
      <span className="text-[14px] font-semibold tabular-nums text-foreground">{total}</span>
      {peak > 0 && (
        <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--brand-accent)]">
          peak {peak}
        </span>
      )}
    </div>
  );

  return (
    <Panel className="h-full flex flex-col">
      <SectionHeader title="Threat Detection" subtitle={`· ${days}d`} action={action} />

      <div
        className="flex-1 px-2 pt-2 pb-2 min-h-[180px]"
        role="img"
        aria-label={`Threat detection chart, ${total} incidents over the last ${days} days, peak ${peak}.`}
      >
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 12, right: 12, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="threatGradient" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor="#22D3EE" stopOpacity={0.7} />
                <stop offset="55%" stopColor="#F59E0B" stopOpacity={0.85} />
                <stop offset="100%" stopColor="#F97316" stopOpacity={0.95} />
              </linearGradient>
              <linearGradient id="threatFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#F97316" stopOpacity={0.35} />
                <stop offset="100%" stopColor="#F97316" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <XAxis
              dataKey="day"
              tick={{ fill: 'var(--muted-foreground)', fontSize: 10, fontFamily: 'monospace' }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              hide
              domain={[0, (dataMax: number) => Math.max(4, Math.ceil(dataMax * 1.25))]}
            />
            <Tooltip
              contentStyle={{
                background: 'var(--card)',
                border: '1px solid var(--border)',
                borderRadius: 8,
                fontSize: 11,
                fontFamily: 'monospace',
              }}
              labelStyle={{ color: 'var(--muted-foreground)' }}
              itemStyle={{ color: 'var(--foreground)' }}
              formatter={(v) => [String(v), 'incidents']}
            />
            <Area
              type="monotone"
              dataKey="count"
              stroke="url(#threatGradient)"
              strokeWidth={2.5}
              fill="url(#threatFill)"
              isAnimationActive
              animationDuration={400}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Panel>
  );
}
