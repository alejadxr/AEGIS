'use client';

import { useEffect, useState, useRef } from 'react';
import { subscribeTopic } from '@/lib/ws';
import { cn } from '@/lib/utils';

interface AttackEvent {
  id: string;
  title: string;
  severity: string;
  source_ip?: string;
  mitre_technique?: string;
  detected_at?: string;
  module?: string;
}

const MAX_EVENTS = 50;

const severityDot: Record<string, string> = {
  critical: 'bg-[#EF4444] shadow-[0_0_8px_rgba(239,68,68,0.8)]',
  high: 'bg-[#F97316] shadow-[0_0_8px_rgba(249,115,22,0.8)]',
  medium: 'bg-[#F59E0B]',
  low: 'bg-[#3B82F6]',
  info: 'bg-zinc-600',
};

const severityBadge: Record<string, string> = {
  critical: 'bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/30',
  high: 'bg-[#F97316]/10 text-[#F97316] border-[#F97316]/30',
  medium: 'bg-[#F59E0B]/10 text-[#F59E0B] border-[#F59E0B]/30',
  low: 'bg-[#3B82F6]/10 text-[#3B82F6] border-[#3B82F6]/30',
  info: 'bg-zinc-700/30 text-zinc-500 border-zinc-700',
};

function shortTime(ts?: string): string {
  const d = ts ? new Date(ts) : new Date();
  const h = String(d.getHours()).padStart(2, '0');
  const m = String(d.getMinutes()).padStart(2, '0');
  const s = String(d.getSeconds()).padStart(2, '0');
  return `${h}:${m}:${s}`;
}

function normalize(raw: unknown): AttackEvent | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  return {
    id: String(r.id ?? r.incident_id ?? r.event_id ?? Math.random().toString(36).slice(2)),
    title: String(r.title ?? r.incident_title ?? r.message ?? 'Incident detected'),
    severity: String(r.severity ?? r.incident_severity ?? 'info').toLowerCase(),
    source_ip: r.source_ip ? String(r.source_ip) : undefined,
    mitre_technique: r.mitre_technique ? String(r.mitre_technique) : undefined,
    detected_at: r.detected_at ? String(r.detected_at) : new Date().toISOString(),
    module: r.module ? String(r.module) : undefined,
  };
}

export function AttackFeed() {
  const [events, setEvents] = useState<AttackEvent[]>([]);
  const countRef = useRef(0);

  useEffect(() => {
    const off1 = subscribeTopic('incidents.new', (data) => {
      const ev = normalize(data);
      if (!ev) return;
      countRef.current += 1;
      setEvents((prev) => [ev, ...prev].slice(0, MAX_EVENTS));
    });
    // Compatibility with old-style event names
    const off2 = subscribeTopic('alert_processed', (data) => {
      const ev = normalize(data);
      if (!ev) return;
      countRef.current += 1;
      setEvents((prev) => [ev, ...prev].slice(0, MAX_EVENTS));
    });
    return () => {
      off1();
      off2();
    };
  }, []);

  return (
    <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl overflow-hidden flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06] shrink-0">
        <div className="flex items-center gap-2.5">
          <span className="w-1.5 h-1.5 rounded-full bg-[#22D3EE] shadow-[0_0_6px_rgba(34,211,238,0.8)] animate-pulse" />
          <span className="text-[13px] font-semibold text-white tracking-tight">Live Attack Feed</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-zinc-600 font-mono uppercase tracking-widest">total</span>
          <span className="text-[11px] text-zinc-300 font-mono tabular-nums">{countRef.current}</span>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {events.length === 0 ? (
          <div className="h-full flex items-center justify-center py-8">
            <p className="text-zinc-600 text-[12px] font-mono">Awaiting incidents…</p>
          </div>
        ) : (
          events.map((ev, i) => (
            <div
              key={ev.id}
              className={cn(
                'flex items-start gap-3 px-4 py-2.5 border-b border-white/[0.03] hover:bg-white/[0.02] transition-colors',
                i === 0 && 'animate-[slide-in_0.3s_ease-out]'
              )}
              style={i === 0 ? { animation: 'fade-in 0.3s ease-out' } : undefined}
            >
              <div className="mt-1 shrink-0">
                <span className={cn('block w-2 h-2 rounded-full', severityDot[ev.severity] ?? 'bg-zinc-600')} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-start justify-between gap-3">
                  <p className="text-[12px] text-zinc-100 font-medium truncate">{ev.title}</p>
                  <span className="shrink-0 text-[10px] text-zinc-600 font-mono tabular-nums">
                    {shortTime(ev.detected_at)}
                  </span>
                </div>
                <div className="flex items-center gap-2 mt-1">
                  <span
                    className={cn(
                      'text-[9px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded border',
                      severityBadge[ev.severity] ?? severityBadge.info
                    )}
                  >
                    {ev.severity}
                  </span>
                  {ev.source_ip && (
                    <span className="text-[10px] text-zinc-500 font-mono tabular-nums">{ev.source_ip}</span>
                  )}
                  {ev.mitre_technique && (
                    <span className="text-[10px] text-[#22D3EE] font-mono">{ev.mitre_technique}</span>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
