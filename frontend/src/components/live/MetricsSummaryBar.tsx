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

  const merged: Metrics = { ...m, ...external };

  const cells = [
    { label: 'EVENTS / SEC', value: merged.eventsPerSec, color: '#22D3EE' },
    { label: 'BLOCKED / MIN', value: merged.blockedPerMin, color: '#F97316' },
    { label: 'AI DECISIONS / MIN', value: merged.aiDecisionsPerMin, color: '#A855F7' },
    { label: 'INCIDENTS OPEN', value: merged.incidentsOpen, color: '#EF4444' },
    { label: 'HONEYPOT HITS', value: merged.honeypotHits, color: '#22C55E' },
  ];

  return (
    <div className="bg-card border border-border rounded-2xl overflow-hidden flex items-stretch">
      {cells.map((c, i) => (
        <div
          key={c.label}
          className={`flex-1 flex flex-col items-center justify-center px-4 py-3 ${i > 0 ? 'border-l border-border' : ''}`}
        >
          <span
            className="text-[20px] font-mono tabular-nums leading-none"
            style={{ color: c.color, textShadow: `0 0 12px ${c.color}30` }}
          >
            {c.value.toLocaleString()}
          </span>
          <span className="text-[9px] text-muted-foreground/60 font-mono uppercase tracking-widest mt-1.5">
            {c.label}
          </span>
        </div>
      ))}
    </div>
  );
}
