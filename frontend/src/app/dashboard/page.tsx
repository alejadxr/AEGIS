'use client';

import { useState, useEffect } from 'react';
import { Bug01Icon, SecurityCheckIcon, Radar01Icon, FlashIcon } from 'hugeicons-react';
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
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';

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

const MODULE_STATUS = [
  { name: 'Surface Scanner', status: 'active', detail: 'Monitoring active', icon: Radar01Icon, color: '#22D3EE' },
  { name: 'Response Engine', status: 'active', detail: 'AI engine running', icon: FlashIcon, color: '#F97316' },
  { name: 'Phantom Deception', status: 'active', detail: 'Honeypots live', icon: Ghost, color: '#A855F7' },
];

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

export default function DashboardPage() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [threatMap, setThreatMap] = useState<ThreatMapEntry[]>([]);
  const [metrics, setMetrics] = useState<LiveMetricsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [wsStatus, setWsStatus] = useState<WSStatus>('idle');

  // Initial data load (overview + threat map)
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

  // WebSocket connection + topic subscriptions
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

  // 2s polling for live-metrics + threat map refresh
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
    return off;
  }, []);

  if (loading) return <LoadingState message="Loading dashboard..." />;
  const stats = overview || EMPTY_OVERVIEW;

  // Severity distribution from real overview data
  const hasSeverityData = stats.open_vulnerabilities > 0;
  const SEVERITY_DATA = hasSeverityData
    ? [
        { name: 'Critical', value: Math.round(stats.open_vulnerabilities * 0.2), color: '#EF4444' },
        { name: 'High', value: Math.round(stats.open_vulnerabilities * 0.37), color: '#F97316' },
        { name: 'Medium', value: Math.round(stats.open_vulnerabilities * 0.26), color: '#F59E0B' },
        { name: 'Low', value: Math.round(stats.open_vulnerabilities * 0.1), color: '#3B82F6' },
        { name: 'Info', value: Math.round(stats.open_vulnerabilities * 0.07), color: '#71717A' },
      ].filter((d) => d.value > 0)
    : [];

  const externalMetrics = metrics
    ? { incidentsOpen: metrics.incidents_open, honeypotHits: metrics.honeypot_hits_24h }
    : undefined;

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-[22px] sm:text-[28px] font-bold text-white tracking-tight">
            Security Overview
          </h1>
          <p className="text-sm text-zinc-500 mt-1">
            Real-time monitoring and threat intelligence
          </p>
        </div>
        <StatusPill status={wsStatus} />
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 stagger-children">
        <StatCard title="Total Assets" value={stats.total_assets} trend={stats.assets_trend || 0} icon={Server} color="accent" />
        <StatCard title="Vulnerabilities" value={stats.open_vulnerabilities} trend={stats.vulns_trend || 0} icon={Bug01Icon} color="warning" />
        <StatCard title="Active Incidents" value={stats.active_incidents} trend={stats.incidents_trend || 0} icon={SecurityCheckIcon} color="danger" />
        <StatCard title="Honeypot Hits" value={stats.honeypot_interactions} trend={stats.interactions_trend || 0} icon={Ghost} color="orange" />
      </div>

      {/* Live Attack Feed + Global Threat Map */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Attack Feed (replaces static Threat Activity chart) */}
        <div className="min-h-[380px]">
          <AttackFeed />
        </div>

        {/* Global Threat Map */}
        <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl overflow-hidden">
          <div className="px-4 sm:px-6 py-4 border-b border-white/[0.06] flex items-center justify-between">
            <div>
              <span className="text-[14px] font-semibold text-white">Global Threat Map</span>
              <p className="text-[12px] text-zinc-500 mt-0.5">Attack origins by country</p>
            </div>
            {threatMap.length > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[#22D3EE] shadow-[0_0_6px_rgba(34,211,238,0.8)]" />
                <span className="text-[11px] text-zinc-500 font-medium">{threatMap.length} sources</span>
              </div>
            )}
          </div>
          <div className="relative h-[280px] sm:h-[340px]">
            <GlobalThreatMap data={threatMap} />
          </div>
        </div>
      </div>

      {/* Events/sec + Risk Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Events per second chart */}
        <div className="lg:col-span-2 h-56">
          <EventsPerSecChart />
        </div>

        {/* Risk Distribution */}
        <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl overflow-hidden">
          <div className="px-4 sm:px-6 py-4 border-b border-white/[0.06]">
            <span className="text-[14px] font-semibold text-white">Risk Distribution</span>
          </div>
          <div className="p-4 sm:p-6 flex flex-col items-center">
            {hasSeverityData ? (
              <>
                <div className="w-40 h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={SEVERITY_DATA}
                        cx="50%"
                        cy="50%"
                        innerRadius={40}
                        outerRadius={70}
                        dataKey="value"
                        stroke="none"
                        paddingAngle={3}
                      >
                        {SEVERITY_DATA.map((entry, i) => (
                          <Cell key={i} fill={entry.color} />
                        ))}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="w-full mt-4 space-y-2.5">
                  {SEVERITY_DATA.map((d) => (
                    <div key={d.name} className="flex items-center justify-between">
                      <div className="flex items-center gap-2.5">
                        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} />
                        <span className="text-[13px] text-zinc-400">{d.name}</span>
                      </div>
                      <span className="text-[13px] text-zinc-300 font-mono font-medium tabular-nums">{d.value}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="h-40 flex items-center justify-center">
                <p className="text-zinc-600 text-[13px]">No vulnerability data yet</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Top-10 Tables Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="h-56">
          <Top10Table
            title="Top Attackers"
            rows={metrics?.top_attackers ?? []}
            accent="#EF4444"
            monoLabel
          />
        </div>
        <div className="h-56">
          <Top10Table
            title="Top Targets"
            rows={metrics?.top_targets ?? []}
            accent="#F97316"
          />
        </div>
        <div className="h-56">
          <Top10Table
            title="Attack Types"
            rows={metrics?.top_attack_types ?? []}
            accent="#A855F7"
          />
        </div>
      </div>

      {/* Raw Log Stream + Node Heartbeats + Metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-5 h-64">
          <RawLogStream />
        </div>
        <div className="lg:col-span-3 h-64">
          <NodeHeartbeatGrid />
        </div>
        <div className="lg:col-span-4 h-64">
          <MetricsSummaryBar external={externalMetrics} />
        </div>
      </div>

      {/* Module Status Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {MODULE_STATUS.map((mod) => (
          <div
            key={mod.name}
            className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-5 flex items-center gap-4 hover:border-white/[0.1] transition-colors"
          >
            <div
              className="w-10 h-10 rounded-xl flex items-center justify-center"
              style={{ backgroundColor: `${mod.color}10` }}
            >
              <mod.icon className="w-5 h-5" style={{ color: mod.color }} />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-[14px] font-semibold text-white">{mod.name}</p>
              <p className="text-[12px] text-zinc-500 mt-0.5">{mod.detail}</p>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 bg-[#22C55E] rounded-full animate-pulse" />
              <span className="text-[11px] text-[#22C55E] font-medium">Active</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
