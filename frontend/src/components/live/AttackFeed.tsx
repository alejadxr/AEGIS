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
  critical: 'bg-[var(--danger)] shadow-[0_0_10px_color-mix(in_oklab,var(--danger)_70%,transparent)]',
  high:     'bg-[var(--brand-accent)] shadow-[0_0_10px_color-mix(in_oklab,var(--brand-accent)_70%,transparent)]',
  medium:   'bg-[var(--warning)]',
  low:      'bg-[var(--info)]',
  info:     'bg-muted-foreground/40',
};

const severityPill: Record<string, string> = {
  critical: 'pill pill-danger',
  high:     'pill pill-warning',
  medium:   'pill pill-warning',
  low:      'pill pill-info',
  info:     'pill pill-muted',
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

  const statusColor = (status?: string) => {
    if (!status) return 'text-muted-foreground/60';
    if (status === 'resolved' || status === 'auto_responded') return 'text-[var(--success)]';
    if (status === 'investigating') return 'text-[var(--warning)]';
    return 'text-muted-foreground/60';
  };

  return (
    <div className="aegis-card overflow-hidden flex flex-col h-full">
      <div className="aegis-section-header shrink-0">
        <div className="flex items-center gap-2.5">
          <span className="relative flex h-1.5 w-1.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75" />
            <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-primary" />
          </span>
          <span className="text-[13px] font-semibold text-foreground tracking-tight">Live Attack Feed</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-label-xs">total</span>
          <span className="text-[11px] text-foreground font-mono tabular-nums">{events.length}</span>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <div className="h-full flex items-center justify-center py-12">
            <p className="text-muted-foreground/60 text-[12px] font-mono">Loading incidents…</p>
          </div>
        ) : events.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center py-12 gap-2">
            <span className="w-8 h-8 rounded-full bg-muted/60 flex items-center justify-center">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--success)]" />
            </span>
            <p className="text-muted-foreground/70 text-[12px] font-mono">All quiet · 0 incidents</p>
          </div>
        ) : (
          events.slice(0, 8).map((ev, i) => (
            <div
              key={ev.id}
              onClick={() => handleClick(ev)}
              className={cn(
                'group flex items-center gap-3 px-4 py-2.5 border-b border-border/50 last:border-b-0',
                'hover:bg-muted/50 transition-colors duration-150 cursor-pointer',
                i === 0 && 'animate-fade-in'
              )}
            >
              <span className={cn('shrink-0 block w-2 h-2 rounded-full', severityDot[ev.severity] ?? severityDot.info)} />

              <div className="flex-1 min-w-0">
                <p className="text-[12.5px] text-foreground font-medium truncate leading-tight">{ev.title}</p>
                <div className="flex items-center gap-2 mt-1">
                  <span className={cn(severityPill[ev.severity] ?? severityPill.info, '!py-0 !px-1.5 !text-[9px]')}>
                    {ev.severity}
                  </span>
                  {ev.source_ip && (
                    <span className="text-[10px] text-muted-foreground font-mono tabular-nums">{ev.source_ip}</span>
                  )}
                  {ev.mitre_technique && (
                    <span className="text-[10px] text-primary font-mono">{ev.mitre_technique}</span>
                  )}
                  {ev.status && (
                    <span className={cn('text-[9px] font-mono uppercase tracking-widest', statusColor(ev.status))}>
                      {ev.status === 'auto_responded' ? 'blocked' : ev.status}
                    </span>
                  )}
                </div>
              </div>

              <span className="shrink-0 text-[10px] text-muted-foreground/50 font-mono tabular-nums">
                {shortTime(ev.detected_at)}
              </span>
              <svg className="w-3.5 h-3.5 text-muted-foreground/30 group-hover:text-muted-foreground/70 shrink-0 transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
              </svg>
            </div>
          ))
        )}
      </div>

      {events.length > 8 && (
        <div
          onClick={() => router.push('/dashboard/response')}
          className="px-4 py-2.5 border-t border-border shrink-0 flex items-center justify-center gap-2 cursor-pointer hover:bg-primary/5 transition-colors group"
        >
          <span className="text-[12px] text-primary font-semibold tracking-tight">
            View all {events.length} incidents
          </span>
          <svg className="w-3.5 h-3.5 text-primary group-hover:translate-x-0.5 transition-transform" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
          </svg>
        </div>
      )}
    </div>
  );
}
