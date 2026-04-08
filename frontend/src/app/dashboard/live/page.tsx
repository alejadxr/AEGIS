'use client';

import { useEffect, useState } from 'react';
import { getLiveWS, subscribeTopic, type WSStatus } from '@/lib/ws';
import { AttackFeed } from '@/components/live/AttackFeed';
import { EventsPerSecChart } from '@/components/live/EventsPerSecChart';
import { Top10Table, type Top10Row } from '@/components/live/Top10Table';
import { RawLogStream } from '@/components/live/RawLogStream';
import { NodeHeartbeatGrid } from '@/components/live/NodeHeartbeatGrid';
import { MetricsSummaryBar } from '@/components/live/MetricsSummaryBar';
import { GlobalThreatMap, type ThreatMapEntry } from '@/components/shared/GlobalThreatMap';
import { cn } from '@/lib/utils';

interface LiveMetricsResponse {
  top_attackers: Top10Row[];
  top_targets: Top10Row[];
  top_attack_types: Top10Row[];
  incidents_open: number;
  honeypot_hits_24h: number;
  blocked_actions_24h: number;
  ai_decisions_24h: number;
  generated_at: string;
}

const COUNTRY_BY_SHORT: Record<string, string> = {
  china: 'CN', russia: 'RU', 'united states': 'US', brazil: 'BR', iran: 'IR',
  'north korea': 'KP', india: 'IN', germany: 'DE', netherlands: 'NL',
  'south korea': 'KR', 'united kingdom': 'GB', france: 'FR', ukraine: 'UA',
  turkey: 'TR', vietnam: 'VN', thailand: 'TH', pakistan: 'PK', nigeria: 'NG',
  'south africa': 'ZA', mexico: 'MX', 'hong kong': 'HK', japan: 'JP',
  australia: 'AU', canada: 'CA',
};

function apiBase(): string {
  return (
    (typeof window !== 'undefined' && localStorage.getItem('aegis_api_url')) ||
    process.env.NEXT_PUBLIC_API_URL ||
    'http://localhost:8000/api/v1'
  );
}

async function fetchLiveMetrics(): Promise<LiveMetricsResponse | null> {
  try {
    const apiKey = typeof window !== 'undefined' ? localStorage.getItem('aegis_api_key') : null;
    const token = typeof window !== 'undefined' ? localStorage.getItem('aegis_jwt_token') : null;
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    else if (apiKey) headers['X-API-Key'] = apiKey;
    const r = await fetch(`${apiBase()}/dashboard/live-metrics`, { headers, cache: 'no-store' });
    if (!r.ok) return null;
    return await r.json();
  } catch {
    return null;
  }
}

async function fetchThreatMap(): Promise<ThreatMapEntry[]> {
  try {
    const apiKey = typeof window !== 'undefined' ? localStorage.getItem('aegis_api_key') : null;
    const token = typeof window !== 'undefined' ? localStorage.getItem('aegis_jwt_token') : null;
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    else if (apiKey) headers['X-API-Key'] = apiKey;
    const r = await fetch(`${apiBase()}/dashboard/threat-map`, { headers, cache: 'no-store' });
    if (!r.ok) return [];
    const raw = await r.json();
    return Array.isArray(raw)
      ? raw.map((e: Record<string, unknown>) => ({
          country: String(e.country ?? e.source_ip ?? 'Unknown'),
          country_code: String(
            e.country_code ?? COUNTRY_BY_SHORT[String(e.country ?? '').toLowerCase()] ?? ''
          ),
          count: Number(e.count ?? 0),
        }))
      : [];
  } catch {
    return [];
  }
}

function StatusPill({ status }: { status: WSStatus }) {
  const cfg: Record<WSStatus, { label: string; color: string; dot: string }> = {
    idle: { label: 'IDLE', color: 'text-zinc-500', dot: 'bg-zinc-600' },
    connecting: { label: 'CONNECTING', color: 'text-[#F59E0B]', dot: 'bg-[#F59E0B] animate-pulse' },
    open: { label: 'LIVE', color: 'text-[#22C55E]', dot: 'bg-[#22C55E] shadow-[0_0_6px_rgba(34,197,94,0.8)] animate-pulse' },
    closed: { label: 'DISCONNECTED', color: 'text-[#EF4444]', dot: 'bg-[#EF4444]' },
    error: { label: 'ERROR', color: 'text-[#EF4444]', dot: 'bg-[#EF4444] animate-pulse' },
  };
  const c = cfg[status];
  return (
    <div className="flex items-center gap-2 px-2.5 py-1 rounded-lg bg-white/[0.03] border border-white/[0.06]">
      <span className={cn('w-1.5 h-1.5 rounded-full', c.dot)} />
      <span className={cn('text-[10px] font-mono uppercase tracking-widest', c.color)}>
        {c.label}
      </span>
    </div>
  );
}

export default function LiveDashboardPage() {
  const [wsStatus, setWsStatus] = useState<WSStatus>('idle');
  const [metrics, setMetrics] = useState<LiveMetricsResponse | null>(null);
  const [threatMap, setThreatMap] = useState<ThreatMapEntry[]>([]);
  const [now, setNow] = useState(new Date());

  useEffect(() => {
    const ws = getLiveWS();
    const off = ws.onStatus(setWsStatus);
    // Subscribe to every topic we care about up-front so the backend is informed.
    const topics = [
      'incidents.new',
      'attackers.geo',
      'metrics.events_per_sec',
      'metrics.top_attackers',
      'metrics.top_targets',
      'metrics.top_attack_types',
      'logs.stream',
      'nodes.status',
      'honeypot.interactions',
      'actions.new',
    ];
    const offs = topics.map((t) => subscribeTopic(t, () => { /* routed per-widget */ }));
    return () => {
      off();
      offs.forEach((f) => f());
    };
  }, []);

  useEffect(() => {
    let mounted = true;
    async function load() {
      const [m, tm] = await Promise.all([fetchLiveMetrics(), fetchThreatMap()]);
      if (!mounted) return;
      if (m) setMetrics(m);
      setThreatMap(tm);
    }
    load();
    const interval = window.setInterval(load, 2000);
    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    const t = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(t);
  }, []);

  // Live-push new threat-map entries when attackers.geo fires
  useEffect(() => {
    const off = subscribeTopic('attackers.geo', (data) => {
      if (!data || typeof data !== 'object') return;
      const r = data as Record<string, unknown>;
      const cc = String(r.country_code ?? '').toUpperCase();
      if (!cc) return;
      setThreatMap((prev) => {
        const idx = prev.findIndex((e) => e.country_code === cc);
        if (idx < 0) {
          return [...prev, { country: String(r.country ?? cc), country_code: cc, count: 1 }];
        }
        const next = [...prev];
        next[idx] = { ...next[idx], count: next[idx].count + 1 };
        return next;
      });
    });
    return () => {
      off();
    };
  }, []);

  const externalMetrics = metrics
    ? {
        incidentsOpen: metrics.incidents_open,
        honeypotHits: metrics.honeypot_hits_24h,
      }
    : undefined;

  return (
    <div className="flex flex-col h-[calc(100vh-7rem)] gap-3 animate-fade-in">
      {/* Header bar */}
      <div className="flex items-center justify-between shrink-0">
        <div>
          <h1 className="text-[18px] font-bold text-white tracking-tight leading-none flex items-center gap-3">
            LIVE SOC
            <span className="text-[10px] text-zinc-600 font-mono uppercase tracking-widest">
              real-time operations
            </span>
          </h1>
          <p className="text-[11px] text-zinc-500 mt-1 font-mono tabular-nums">
            {now.toISOString().replace('T', ' ').slice(0, 19)} UTC
          </p>
        </div>
        <div className="flex items-center gap-2">
          <StatusPill status={wsStatus} />
        </div>
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-12 gap-3 flex-1 min-h-0">
        {/* Attack Feed — top-left, spans rows for density */}
        <div className="col-span-12 md:col-span-4 row-span-2 min-h-0">
          <AttackFeed />
        </div>

        {/* Threat map — top-middle */}
        <div className="col-span-12 md:col-span-5 row-span-2 min-h-0 bg-[#18181B] border border-white/[0.06] rounded-2xl overflow-hidden flex flex-col">
          <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06] shrink-0">
            <span className="text-[13px] font-semibold text-white tracking-tight">Global Threat Map</span>
            <span className="text-[10px] text-zinc-600 font-mono">
              {threatMap.length} sources
            </span>
          </div>
          <div className="flex-1 min-h-0">
            <GlobalThreatMap data={threatMap} />
          </div>
        </div>

        {/* Raw log stream — right column */}
        <div className="col-span-12 md:col-span-3 row-span-3 min-h-0">
          <RawLogStream />
        </div>

        {/* Events/sec — bottom-left of upper row */}
        <div className="col-span-12 md:col-span-4 min-h-0 h-52">
          <EventsPerSecChart />
        </div>

        {/* Top-10 tables row */}
        <div className="col-span-12 md:col-span-3 min-h-0 h-52">
          <Top10Table
            title="Top Attackers"
            rows={metrics?.top_attackers ?? []}
            accent="#EF4444"
            monoLabel
          />
        </div>
        <div className="col-span-12 md:col-span-3 min-h-0 h-52">
          <Top10Table
            title="Top Targets"
            rows={metrics?.top_targets ?? []}
            accent="#F97316"
          />
        </div>
        <div className="col-span-12 md:col-span-2 min-h-0 h-52">
          <Top10Table
            title="Attack Types"
            rows={metrics?.top_attack_types ?? []}
            accent="#A855F7"
          />
        </div>
      </div>

      {/* Bottom row: heartbeats + metrics */}
      <div className="grid grid-cols-12 gap-3 shrink-0">
        <div className="col-span-12 md:col-span-4 h-24">
          <NodeHeartbeatGrid />
        </div>
        <div className="col-span-12 md:col-span-8 h-24">
          <MetricsSummaryBar external={externalMetrics} />
        </div>
      </div>
    </div>
  );
}
