'use client';

import { useEffect, useState, useRef } from 'react';
import { subscribeTopic } from '@/lib/ws';

interface Metrics {
  eventsPerSec: number;
  blockedPerMin: number;
  aiDecisionsPerMin: number;
  incidentsOpen: number;
  honeypotHits: number;
}

const EMPTY: Metrics = {
  eventsPerSec: 0,
  blockedPerMin: 0,
  aiDecisionsPerMin: 0,
  incidentsOpen: 0,
  honeypotHits: 0,
};

interface Props {
  external?: Partial<Metrics>;
}

export function MetricsSummaryBar({ external }: Props) {
  const [m, setM] = useState<Metrics>(EMPTY);
  const counters = useRef({
    eventsWindow: 0,
    blockedWindow: 0,
    decisionsWindow: 0,
  });

  useEffect(() => {
    const off1 = subscribeTopic('*', () => {
      counters.current.eventsWindow += 1;
    });
    const off2 = subscribeTopic('action_executed', () => {
      counters.current.blockedWindow += 1;
    });
    const off3 = subscribeTopic('actions.new', () => {
      counters.current.blockedWindow += 1;
    });
    const off4 = subscribeTopic('ai_decision', () => {
      counters.current.decisionsWindow += 1;
    });
    const off5 = subscribeTopic('alert_processed', () => {
      counters.current.decisionsWindow += 1;
    });

    const tick = window.setInterval(() => {
      setM((prev) => ({
        ...prev,
        eventsPerSec: counters.current.eventsWindow,
      }));
      counters.current.eventsWindow = 0;
    }, 1000);

    const minTick = window.setInterval(() => {
      setM((prev) => ({
        ...prev,
        blockedPerMin: counters.current.blockedWindow,
        aiDecisionsPerMin: counters.current.decisionsWindow,
      }));
      counters.current.blockedWindow = 0;
      counters.current.decisionsWindow = 0;
    }, 60_000);

    return () => {
      off1();
      off2();
      off3();
      off4();
      off5();
      window.clearInterval(tick);
      window.clearInterval(minTick);
    };
  }, []);

  // Spread external only if value is a valid number — avoids undefined overrides.
  const clean: Partial<Metrics> = {};
  if (external) {
    (Object.keys(external) as (keyof Metrics)[]).forEach((k) => {
      const v = external[k];
      if (typeof v === 'number' && Number.isFinite(v)) clean[k] = v;
    });
  }
  const merged: Metrics = { ...m, ...clean };
  const num = (v: number) => Number.isFinite(v) ? v : 0;

  const cells = [
    { label: 'EVENTS / SEC',       value: num(merged.eventsPerSec),       color: 'var(--brand)' },
    { label: 'BLOCKED / MIN',      value: num(merged.blockedPerMin),      color: 'var(--brand-accent)' },
    { label: 'AI DECISIONS / MIN', value: num(merged.aiDecisionsPerMin),  color: 'var(--chart-5)' },
    { label: 'INCIDENTS OPEN',     value: num(merged.incidentsOpen),      color: 'var(--danger)' },
    { label: 'HONEYPOT HITS',      value: num(merged.honeypotHits),       color: 'var(--success)' },
  ];

  return (
    <div className="aegis-card overflow-hidden flex items-stretch">
      {cells.map((c, i) => (
        <div
          key={c.label}
          className={`flex-1 flex flex-col items-center justify-center px-4 py-3.5 ${i > 0 ? 'border-l border-border' : ''}`}
        >
          <span
            className="text-[22px] font-mono tabular-nums leading-none font-bold"
            style={{ color: c.color }}
          >
            {c.value.toLocaleString()}
          </span>
          <span className="text-label-xs mt-2">{c.label}</span>
        </div>
      ))}
    </div>
  );
}
