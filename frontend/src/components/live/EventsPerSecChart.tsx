'use client';

import { useEffect, useState } from 'react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';
import { subscribeTopic } from '@/lib/ws';

interface Point {
  t: number;
  events: number;
  label: string;
}

const WINDOW_SECONDS = 60;

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
  const [isDark, setIsDark] = useState(false);

  useEffect(() => {
    const check = () => {
      setIsDark(document.documentElement.getAttribute('data-theme') === 'dark' || document.documentElement.classList.contains('dark'));
    };
    check();
    const obs = new MutationObserver(check);
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme', 'class'] });
    return () => obs.disconnect();
  }, []);

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

  const gridColor = isDark ? 'rgba(255,255,255,0.03)' : 'rgba(0,0,0,0.05)';
  const tickColor = isDark ? '#6B7280' : '#9CA3AF';
  const tooltipBg = isDark ? '#18181B' : '#FFFFFF';
  const tooltipBorder = isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.08)';
  const tooltipText = isDark ? '#FAFAFA' : '#18181B';

  return (
    <div className="bg-card border border-border rounded-2xl overflow-hidden flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border shrink-0">
        <div className="flex items-center gap-2.5">
          <span className="text-[13px] font-semibold text-foreground tracking-tight">Events / Second</span>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex flex-col items-end">
            <span className="text-[9px] text-muted-foreground/60 font-mono uppercase tracking-widest">now</span>
            <span className="text-[14px] text-primary font-mono tabular-nums leading-none">{current}</span>
          </div>
          <div className="flex flex-col items-end">
            <span className="text-[9px] text-muted-foreground/60 font-mono uppercase tracking-widest">peak</span>
            <span className="text-[14px] text-muted-foreground font-mono tabular-nums leading-none">{peak}</span>
          </div>
        </div>
      </div>
      <div className="flex-1 p-3">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={points}>
            <defs>
              <linearGradient id="lineGradCyan" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#22D3EE" stopOpacity={0.5} />
                <stop offset="100%" stopColor="#22D3EE" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke={gridColor} vertical={false} />
            <XAxis
              dataKey="label"
              tick={{ fill: tickColor, fontSize: 9, fontFamily: 'Azeret Mono' }}
              axisLine={false}
              tickLine={false}
              interval={9}
            />
            <YAxis
              tick={{ fill: tickColor, fontSize: 9, fontFamily: 'Azeret Mono' }}
              axisLine={false}
              tickLine={false}
              width={26}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: tooltipBg,
                border: `1px solid ${tooltipBorder}`,
                borderRadius: '8px',
                color: tooltipText,
                fontSize: '11px',
                fontFamily: 'Azeret Mono, monospace',
                padding: '6px 10px',
              }}
              cursor={{ stroke: 'rgba(34,211,238,0.2)' }}
            />
            <Line
              type="monotone"
              dataKey="events"
              stroke="#22D3EE"
              strokeWidth={1.5}
              dot={false}
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
