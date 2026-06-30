'use client';

import { useState, useEffect } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { cn, formatDate } from '@/lib/utils';

interface RansomwareEvent {
  id: string;
  rule_id: string;
  rule_name: string;
  host: string;
  severity: string;
  triggered_at: string;
  process?: string;
  details?: string;
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'text-[var(--danger)] bg-[var(--danger)]/10 border-[var(--danger)]/20',
  high: 'text-[var(--warning)] bg-[var(--warning)]/10 border-[var(--warning)]/20',
  medium: 'text-[var(--info)] bg-[var(--info)]/10 border-[var(--info)]/20',
  low: 'text-muted-foreground bg-white/[0.04] border-border',
};

interface RecentEventsTableProps {
  onSelectEvent?: (event: RansomwareEvent) => void;
}

export function RecentEventsTable({ onSelectEvent }: RecentEventsTableProps) {
  const [events, setEvents] = useState<RansomwareEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  async function load() {
    setLoading(true);
    setError(false);
    try {
      const apiKey = typeof window !== 'undefined' ? localStorage.getItem('aegis_api_key') : null;
      const res = await fetch('/api/v1/threats/events?type=ransomware&limit=50', {
        headers: apiKey ? { 'X-API-Key': apiKey } : {},
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      const items = Array.isArray(json) ? json : (json.events ?? json.items ?? []);
      setEvents(items);
    } catch {
      setEvents([]);
      setError(true);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-6 space-y-3 animate-pulse">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="h-10 bg-white/[0.04] rounded-lg" />
        ))}
      </div>
    );
  }

  return (
    <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl overflow-hidden">
      <div className="flex items-center justify-between px-5 py-4 border-b border-white/[0.06]">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-[var(--warning)]" />
          <span className="text-[13px] font-semibold text-foreground">Recent Ransomware Events</span>
          {events.length > 0 && (
            <span className="text-[10px] font-mono text-muted-foreground/60 bg-white/[0.04] px-2 py-0.5 rounded-md">
              {events.length}
            </span>
          )}
        </div>
        <button
          onClick={load}
          className="p-1.5 rounded-lg text-muted-foreground/60 hover:text-foreground hover:bg-white/[0.06] transition-colors"
          title="Refresh"
        >
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
      </div>

      {events.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 px-6 text-center">
          <div className="w-10 h-10 rounded-xl bg-white/[0.04] flex items-center justify-center mb-3">
            <AlertTriangle className="w-5 h-5 text-muted-foreground/40" />
          </div>
          <p className="text-[13px] text-muted-foreground">
            {error ? 'Could not reach the events endpoint.' : 'No ransomware events in the last 24h.'}
          </p>
          {error && (
            <p className="text-[11px] text-muted-foreground/60 mt-1">
              Endpoint: <span className="font-mono">/api/v1/threats/events?type=ransomware</span>
            </p>
          )}
        </div>
      ) : (
        <div className="divide-y divide-white/[0.04]">
          {events.map((event) => (
            <button
              key={event.id}
              onClick={() => onSelectEvent?.(event)}
              className="w-full flex items-start gap-3 px-5 py-3.5 hover:bg-white/[0.03] transition-colors text-left group"
            >
              <span
                className={cn(
                  'inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-semibold uppercase tracking-wide border shrink-0 mt-0.5',
                  SEVERITY_STYLES[event.severity?.toLowerCase()] ?? SEVERITY_STYLES.low
                )}
              >
                {event.severity ?? 'unknown'}
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-[12px] font-medium text-foreground/90 truncate group-hover:text-foreground transition-colors">
                  {event.rule_name ?? event.rule_id}
                </p>
                <div className="flex items-center gap-2 mt-0.5">
                  {event.host && (
                    <span className="text-[11px] font-mono text-muted-foreground/70 truncate">{event.host}</span>
                  )}
                  {event.process && (
                    <>
                      <span className="text-muted-foreground/30">·</span>
                      <span className="text-[11px] font-mono text-muted-foreground/50 truncate">{event.process}</span>
                    </>
                  )}
                </div>
              </div>
              <span className="text-[10px] font-mono text-muted-foreground/50 shrink-0 mt-0.5">
                {formatDate(event.triggered_at)}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
