'use client';

import { useEffect, useState, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { subscribeTopic } from '@/lib/ws';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';

interface AttackEvent {
  id: string;
  title: string;
  severity: string;
  source_ip?: string;
  mitre_technique?: string;
  detected_at?: string;
  module?: string;
  status?: string;
}

const MAX_EVENTS = 50;

const severityDot: Record<string, string> = {
  critical: 'bg-[#EF4444] shadow-[0_0_8px_rgba(239,68,68,0.8)]',
  high: 'bg-[#F97316] shadow-[0_0_8px_rgba(249,115,22,0.8)]',
  medium: 'bg-[#F59E0B]',
  low: 'bg-[#3B82F6]',
  info: 'bg-muted-foreground/40',
};

const severityBadge: Record<string, string> = {
  critical: 'bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/30',
  high: 'bg-[#F97316]/10 text-[#F97316] border-[#F97316]/30',
  medium: 'bg-[#F59E0B]/10 text-[#F59E0B] border-[#F59E0B]/30',
  low: 'bg-[#3B82F6]/10 text-[#3B82F6] border-[#3B82F6]/30',
  info: 'bg-muted text-muted-foreground border-border',
};

function shortTime(ts?: string): string {
  const d = ts ? new Date(ts) : new Date();
  const h = String(d.getHours()).padStart(2, '0');
  const m = String(d.getMinutes()).padStart(2, '0');
  const s = String(d.getSeconds()).padStart(2, '0');
  return `${h}:${m}:${s}`;
}

function normalizeWS(raw: unknown): AttackEvent | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  const title = String(r.incident_title ?? r.title ?? r.message ?? '').trim();
  if (!title) return null;
  return {
    id: String(r.incident_id ?? r.id ?? r.event_id ?? Math.random().toString(36).slice(2)),
    title,
    severity: String(r.incident_severity ?? r.severity ?? 'info').toLowerCase(),
    source_ip: r.source_ip ? String(r.source_ip) : undefined,
    mitre_technique: r.mitre_technique ? String(r.mitre_technique) : undefined,
    detected_at: r.detected_at ? String(r.detected_at) : new Date().toISOString(),
    module: r.module ? String(r.module) : r.source ? String(r.source) : undefined,
    status: r.incident_status ? String(r.incident_status) : 'investigating',
  };
}

export function AttackFeed() {
  const [events, setEvents] = useState<AttackEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const seenIds = useRef(new Set<string>());
  const router = useRouter();

  // Load recent incidents from API on mount
  useEffect(() => {
    async function loadRecent() {
      try {
        const incidents = await api.response.incidents();
        const mapped: AttackEvent[] = incidents.slice(0, MAX_EVENTS).map((inc) => ({
          id: inc.id,
          title: inc.title,
          severity: inc.severity,
          source_ip: inc.source_ip ?? undefined,
          mitre_technique: inc.mitre_technique ?? undefined,
          detected_at: inc.detected_at,
          module: inc.source,
          status: inc.status,
        }));
        mapped.forEach((e) => seenIds.current.add(e.id));
        setEvents(mapped);
      } catch {
        // API might be down — just show empty feed
      } finally {
        setLoading(false);
      }
    }
    loadRecent();
  }, []);

  // Subscribe to real-time incidents via WebSocket
  useEffect(() => {
    const off1 = subscribeTopic('incidents.new', (data) => {
      const ev = normalizeWS(data);
      if (!ev || seenIds.current.has(ev.id)) return;
      seenIds.current.add(ev.id);
      setEvents((prev) => [ev, ...prev].slice(0, MAX_EVENTS));
    });
    const off2 = subscribeTopic('alert_processed', (data) => {
      const ev = normalizeWS(data);
      if (!ev || seenIds.current.has(ev.id)) return;
      seenIds.current.add(ev.id);
      setEvents((prev) => [ev, ...prev].slice(0, MAX_EVENTS));
    });
    return () => {
      off1();
      off2();
    };
  }, []);

  function handleClick(ev: AttackEvent) {
    router.push(`/dashboard/response?incident=${ev.id}`);
  }

  return (
    <div className="bg-card border border-border rounded-2xl overflow-hidden flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border shrink-0">
        <div className="flex items-center gap-2.5">
          <span className="w-1.5 h-1.5 rounded-full bg-primary shadow-[0_0_6px_rgba(34,211,238,0.8)] animate-pulse" />
          <span className="text-[13px] font-semibold text-foreground tracking-tight">Live Attack Feed</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-muted-foreground/60 font-mono uppercase tracking-widest">total</span>
          <span className="text-[11px] text-muted-foreground font-mono tabular-nums">{events.length}</span>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <div className="h-full flex items-center justify-center py-8">
            <p className="text-muted-foreground/60 text-[12px] font-mono">Loading incidents…</p>
          </div>
        ) : events.length === 0 ? (
          <div className="h-full flex items-center justify-center py-8">
            <p className="text-muted-foreground/60 text-[12px] font-mono">No incidents detected</p>
          </div>
        ) : (
          events.map((ev, i) => (
            <div
              key={ev.id}
              onClick={() => handleClick(ev)}
              className={cn(
                'flex items-start gap-3 px-4 py-2.5 border-b border-border/50 hover:bg-muted/50 transition-colors cursor-pointer',
                i === 0 && 'animate-[slide-in_0.3s_ease-out]'
              )}
              style={i === 0 ? { animation: 'fade-in 0.3s ease-out' } : undefined}
            >
              <div className="mt-1 shrink-0">
                <span className={cn('block w-2 h-2 rounded-full', severityDot[ev.severity] ?? 'bg-muted-foreground/40')} />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-start justify-between gap-3">
                  <p className="text-[12px] text-foreground font-medium truncate">{ev.title}</p>
                  <span className="shrink-0 text-[10px] text-muted-foreground/60 font-mono tabular-nums">
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
                    <span className="text-[10px] text-muted-foreground font-mono tabular-nums">{ev.source_ip}</span>
                  )}
                  {ev.mitre_technique && (
                    <span className="text-[10px] text-primary font-mono">{ev.mitre_technique}</span>
                  )}
                  {ev.status && (
                    <span className={cn(
                      'text-[9px] font-mono uppercase tracking-wider',
                      ev.status === 'resolved' ? 'text-[#22C55E]' :
                      ev.status === 'investigating' ? 'text-[#F59E0B]' :
                      'text-muted-foreground/60'
                    )}>
                      {ev.status}
                    </span>
                  )}
                </div>
              </div>
              <div className="mt-1 shrink-0">
                <svg className="w-3.5 h-3.5 text-muted-foreground/40" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                </svg>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
