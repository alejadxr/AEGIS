'use client';

import { useState, useEffect } from 'react';
import { Bug01Icon, SecurityCheckIcon, Radar01Icon } from 'hugeicons-react';
import { Server, Ghost } from 'lucide-react';
import { StatCard } from '@/components/shared/StatCard';
import { LoadingState } from '@/components/shared/LoadingState';
import { GlobalThreatMap, type ThreatMapEntry } from '@/components/shared/GlobalThreatMap';
import { AttackFeed } from '@/components/live/AttackFeed';
import { EventsPerSecChart } from '@/components/live/EventsPerSecChart';
import { Top10Table, type Top10Row } from '@/components/live/Top10Table';
import { RawLogStream } from '@/components/live/RawLogStream';
import { NodeHeartbeatGrid } from '@/components/live/NodeHeartbeatGrid';
import { MetricsSummaryBar } from '@/components/live/MetricsSummaryBar';
import { getLiveWS, subscribeTopic, type WSStatus } from '@/lib/ws';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';

interface Overview {
  total_assets: number;
  open_vulnerabilities: number;
  active_incidents: number;
  honeypot_interactions: number;
  assets_trend: number;
  vulns_trend: number;
  incidents_trend: number;
  interactions_trend: number;
}

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

const EMPTY_OVERVIEW: Overview = {
  total_assets: 0,
  open_vulnerabilities: 0,
  active_incidents: 0,
  honeypot_interactions: 0,
  assets_trend: 0,
  vulns_trend: 0,
  incidents_trend: 0,
  interactions_trend: 0,
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

function StatusPill({ status }: { status: WSStatus }) {
  const cfg: Record<WSStatus, { label: string; color: string; dot: string }> = {
    idle: { label: 'IDLE', color: 'text-white/30', dot: 'bg-white/20' },
    connecting: { label: 'SYNC', color: 'text-[#F59E0B]/70', dot: 'bg-[#F59E0B] animate-pulse' },
    open: { label: 'LIVE', color: 'text-[#22C55E]/70', dot: 'bg-[#22C55E]' },
    closed: { label: 'OFFLINE', color: 'text-[#EF4444]/70', dot: 'bg-[#EF4444]' },
    error: { label: 'ERROR', color: 'text-[#EF4444]/70', dot: 'bg-[#EF4444] animate-pulse' },
  };
  const c = cfg[status];
  return (
    <div className="flex items-center gap-1.5">
      <span className={cn('w-1.5 h-1.5 rounded-full', c.dot)} />
      <span className={cn('text-[10px] font-mono uppercase tracking-widest', c.color)}>
        {c.label}
      </span>
    </div>
  );
}

/* Section header — consistent across all dashboard widgets */
function SectionHeader({ title, icon: Icon, right }: {
  title: string;
  icon?: React.ComponentType<{ className?: string; size?: number }>;
  right?: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.04]">
      <div className="flex items-center gap-2">
        {Icon && <Icon className="text-white/20" size={14} />}
        <span className="text-[12px] font-medium text-white/50">{title}</span>
      </div>
      {right}
    </div>
  );
}

export default function DashboardPage() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [threatMap, setThreatMap] = useState<ThreatMapEntry[]>([]);
  const [metrics, setMetrics] = useState<LiveMetricsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [wsStatus, setWsStatus] = useState<WSStatus>('idle');

  useEffect(() => {
    async function load() {
      try {
        const [ov, tm] = await Promise.allSettled([
          api.dashboard.overview(),
          api.dashboard.threatMap(),
        ]);
        setOverview(ov.status === 'fulfilled' ? ov.value : null);
        setThreatMap(tm.status === 'fulfilled' ? tm.value : []);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  useEffect(() => {
    const ws = getLiveWS();
    const offStatus = ws.onStatus(setWsStatus);
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
    const offs = topics.map((t) => subscribeTopic(t, () => {}));
    return () => {
      offStatus();
      offs.forEach((f) => f());
    };
  }, []);

  useEffect(() => {
    let mounted = true;
    async function poll() {
      const [m, tm] = await Promise.all([fetchLiveMetrics(), api.dashboard.threatMap().catch(() => [] as ThreatMapEntry[])]);
      if (!mounted) return;
      if (m) setMetrics(m);
      if (tm && tm.length > 0) setThreatMap(tm);
    }
    poll();
    const interval = window.setInterval(poll, 2000);
    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, []);

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
    return off;
  }, []);

  if (loading) return <LoadingState message="Loading dashboard..." />;
  const stats = overview || EMPTY_OVERVIEW;

  const externalMetrics = metrics
    ? { incidentsOpen: metrics.incidents_open, honeypotHits: metrics.honeypot_hits_24h }
    : undefined;

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[20px] sm:text-[24px] font-semibold text-white tracking-tight">
            Security Overview
          </h1>
          <p className="text-[12px] text-white/30 mt-0.5">
            Real-time monitoring and threat intelligence
          </p>
        </div>
        <StatusPill status={wsStatus} />
      </div>

      {/* Stat Cards — 4 clean cards with big monospace numbers */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 stagger-children">
        <StatCard title="Total Assets" value={stats.total_assets} trend={stats.assets_trend || 0} icon={Server} color="accent" />
        <StatCard title="Vulnerabilities" value={stats.open_vulnerabilities} trend={stats.vulns_trend || 0} icon={Bug01Icon} color="warning" />
        <StatCard title="Active Incidents" value={stats.active_incidents} trend={stats.incidents_trend || 0} icon={SecurityCheckIcon} color="danger" />
        <StatCard title="Honeypot Hits" value={stats.honeypot_interactions} trend={stats.interactions_trend || 0} icon={Ghost} color="orange" />
      </div>

      {/* Attack Feed (60%) + Global Threat Map (40%) */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-3">
        <div className="lg:col-span-3 min-h-[380px]">
          <AttackFeed />
        </div>

        <div className="lg:col-span-2 bg-[var(--c6-surface)] border border-white/[0.04] rounded-xl overflow-hidden">
          <SectionHeader
            title="Global Threat Map"
            icon={Radar01Icon}
            right={threatMap.length > 0 ? (
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-[#22D3EE]" />
                <span className="text-[10px] text-white/30 font-mono">{threatMap.length} sources</span>
              </div>
            ) : undefined}
          />
          <div className="relative h-[280px] sm:h-[340px]">
            <GlobalThreatMap data={threatMap} />
          </div>
        </div>
      </div>

      {/* Events/sec chart — full width */}
      <div className="h-52">
        <EventsPerSecChart />
      </div>

      {/* Top-10 Tables — compact horizontal */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="h-52">
          <Top10Table
            title="Top Attackers"
            rows={metrics?.top_attackers ?? []}
            accent="#EF4444"
            monoLabel
          />
        </div>
        <div className="h-52">
          <Top10Table
            title="Top Targets"
            rows={metrics?.top_targets ?? []}
            accent="#F97316"
          />
        </div>
        <div className="h-52">
          <Top10Table
            title="Attack Types"
            rows={metrics?.top_attack_types ?? []}
            accent="#A855F7"
          />
        </div>
      </div>

      {/* Raw Logs + Node Heartbeats + Metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3">
        <div className="lg:col-span-5 h-60">
          <RawLogStream />
        </div>
        <div className="lg:col-span-3 h-60">
          <NodeHeartbeatGrid />
        </div>
        <div className="lg:col-span-4 h-60">
          <MetricsSummaryBar external={externalMetrics} />
        </div>
      </div>
    </div>
  );
}
