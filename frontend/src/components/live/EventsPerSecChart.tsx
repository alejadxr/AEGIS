'use client';

import { useEffect, useState } from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts';
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from '@/components/ui/chart';
import { subscribeTopic } from '@/lib/ws';

interface Point {
  t: number;
  events: number;
  label: string;
}

const WINDOW_SECONDS = 60;

const chartConfig = {
  events: {
    label: 'Events',
    color: 'var(--chart-1)',
  },
} satisfies ChartConfig;

export function EventsPerSecChart() {
  const [points, setPoints] = useState<Point[]>(() => {
    const now = Math.floor(Date.now() / 1000);
    return Array.from({ length: WINDOW_SECONDS }, (_, i) => {
      const t = now - (WINDOW_SECONDS - 1 - i);
      const d = new Date(t * 1000);
      return {
        t,
        events: 0,
        label: `${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`,
      };
    });
  });
  const [current, setCurrent] = useState(0);
  const [peak, setPeak] = useState(0);

  useEffect(() => {
    let accum = 0;

    const offEvent = subscribeTopic('*', () => {
      accum += 1;
    });

    const offMetric = subscribeTopic('metrics.events_per_sec', (data) => {
      const val = typeof data === 'number'
        ? data
        : (data && typeof data === 'object' && 'value' in data
          ? Number((data as Record<string, unknown>).value)
          : null);
      if (val !== null && !Number.isNaN(val)) {
        accum = Math.max(accum, val);
      }
    });

    const timer = window.setInterval(() => {
      const now = Math.floor(Date.now() / 1000);
      const d = new Date(now * 1000);
      const label = `${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
      const eps = accum;
      accum = 0;
      setCurrent(eps);
      setPeak((p) => Math.max(p, eps));
      setPoints((prev) => {
        const next = [...prev.slice(1), { t: now, events: eps, label }];
        return next;
      });
    }, 1000);

    return () => {
      offEvent();
      offMetric();
      window.clearInterval(timer);
    };
  }, []);

  return (
    <div className="aegis-card overflow-hidden flex flex-col h-full">
      <div className="aegis-section-header shrink-0">
        <div className="flex items-center gap-2.5">
          <span className="text-[13px] font-semibold text-foreground tracking-tight">Events / Second</span>
        </div>
        <div className="flex items-center gap-5">
          <div className="flex flex-col items-end gap-0.5">
            <span className="text-label-xs">now</span>
            <span className="text-[18px] text-primary font-mono font-bold tabular-nums leading-none">{current}</span>
          </div>
          <div className="w-px h-6 bg-border" />
          <div className="flex flex-col items-end gap-0.5">
            <span className="text-label-xs">peak</span>
            <span className="text-[18px] text-foreground font-mono font-bold tabular-nums leading-none">{peak}</span>
          </div>
        </div>
      </div>
      <div className="flex-1 p-3">
        <ChartContainer config={chartConfig} className="h-full w-full aspect-auto">
          <LineChart data={points}>
            <CartesianGrid vertical={false} />
            <XAxis
              dataKey="label"
              tick={{ fontSize: 9, fontFamily: 'Azeret Mono' }}
              axisLine={false}
              tickLine={false}
              interval={9}
            />
            <YAxis
              tick={{ fontSize: 9, fontFamily: 'Azeret Mono' }}
              axisLine={false}
              tickLine={false}
              width={26}
            />
            <ChartTooltip
              cursor={{ stroke: 'rgba(34,211,238,0.2)' }}
              content={<ChartTooltipContent indicator="line" />}
            />
            <Line
              type="monotone"
              dataKey="events"
              stroke="var(--color-events)"
              strokeWidth={1.5}
              dot={false}
              isAnimationActive={false}
            />
          </LineChart>
        </ChartContainer>
      </div>
    </div>
  );
}
