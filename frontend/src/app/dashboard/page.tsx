'use client';

import { useEffect, useMemo, useState } from 'react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { Download, Radar } from 'lucide-react';
import { LoadingState } from '@/components/shared/LoadingState';
import { KPITile } from '@/components/dashboard/KPITile';
import { IncidentTimeline } from '@/components/dashboard/IncidentTimeline';
import { AISuggestedActions } from '@/components/dashboard/AISuggestedActions';
import { ThreatDetectionChart } from '@/components/dashboard/ThreatDetectionChart';
import { LoginAttemptsHeatmap } from '@/components/dashboard/LoginAttemptsHeatmap';
import { AssetRiskTable, type AssetRiskRow } from '@/components/dashboard/AssetRiskTable';
import { Panel, SectionHeader } from '@/components/aegis';
import { api } from '@/lib/api';
import { getLiveWS, subscribeTopic, type WSStatus } from '@/lib/ws';
import { cn } from '@/lib/utils';
import { mitreLabel, mitreInfo } from '@/lib/mitre';

// Lazy-load the (heavy) world map for CLS budget
const GlobalThreatMap = dynamic(
  () => import('@/components/shared/GlobalThreatMap').then((m) => m.GlobalThreatMap),
  {
    ssr: false,
    loading: () => (
      <div className="h-[360px] grid place-items-center text-[11px] text-muted-foreground/60">
        Loading global map…
      </div>
    ),
  },
);

type Incident = {
  id: string;
  title: string;
  severity: string;
  status: string;
  source_ip: string | null;
  mitre_technique: string | null;
  ai_analysis: Record<string, unknown> | null;
  detected_at: string;
  source: string;
};
type Action = {
  id: string;
  incident_id: string;
  action_type: string;
  target: string;
  status: string;
  requires_approval: boolean;
  ai_reasoning: string | null;
  created_at: string;
};
type Interaction = { id: string; timestamp: string; source_ip: string };
type ThreatMapEntry = { country: string; country_code: string; count: number };

const MONITORED_APPS = ['sable', 'wilabia-frontend', 'wilabia-backend', 'sid-wilab', 'landing-wilab'];

function StatusPill({ status }: { status: WSStatus }) {
  const cfg: Record<WSStatus, { label: string; pill: string }> = {
    idle:       { label: 'IDLE',    pill: 'pill pill-muted' },
    connecting: { label: 'SYNC',    pill: 'pill pill-warning' },
    open:       { label: 'LIVE',    pill: 'pill pill-success' },
    closed:     { label: 'OFFLINE', pill: 'pill pill-danger' },
    error:      { label: 'ERROR',   pill: 'pill pill-danger' },
  };
  const c = cfg[status];
  const pulsing = status === 'connecting' || status === 'open' || status === 'error';
  return (
    <div className={c.pill}>
      <span className={cn('pill-dot', pulsing && 'animate-pulse')} style={{ background: 'currentColor' }} />
      {c.label}
    </div>
  );
}

function shortId(id: string): string {
  // Render an incident id as a short uppercase token (#INC-2050 style)
  const m = id.match(/(\d+)/);
  if (m) return m[1].slice(-4).padStart(4, '0');
  return id.slice(0, 6).toUpperCase();
}

function severityBadgeColor(sev?: string): string {
  switch ((sev || '').toLowerCase()) {
    case 'critical': return 'var(--danger)';
    case 'high':     return 'var(--brand-accent)';
    case 'medium':   return 'var(--warning)';
    case 'low':      return 'var(--chart-5, #22D3EE)';
    default:         return 'var(--muted-foreground)';
  }
}

function relativeTime(iso?: string): string {
  if (!iso) return '—';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '—';
  const diff = (Date.now() - t) / 1000;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function DashboardPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [actions, setActions] = useState<Action[]>([]);
  const [interactions, setInteractions] = useState<Interaction[]>([]);
  const [threatMap, setThreatMap] = useState<ThreatMapEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [wsStatus, setWsStatus] = useState<WSStatus>('idle');
  const [refreshKey, setRefreshKey] = useState(0);

  // Initial load
  useEffect(() => {
    let mounted = true;
    async function load() {
      const [inc, act, ints, tm] = await Promise.allSettled([
        api.response.incidents(),
        api.response.actions(),
        api.phantom.interactions({ limit: '200' }),
        api.dashboard.threatMap(),
      ]);
      if (!mounted) return;
      if (inc.status === 'fulfilled') setIncidents(inc.value as Incident[]);
      if (act.status === 'fulfilled') setActions(act.value as Action[]);
      if (ints.status === 'fulfilled') setInteractions(ints.value as Interaction[]);
      if (tm.status === 'fulfilled') setThreatMap(tm.value as ThreatMapEntry[]);
      setLoading(false);
    }
    load();
    return () => { mounted = false; };
  }, [refreshKey]);

  // Live WS status + soft re-pull on incident/action events
  useEffect(() => {
    const ws = getLiveWS();
    const offStatus = ws.onStatus(setWsStatus);
    const offIncidents = subscribeTopic('incidents.new', () => setRefreshKey((k) => k + 1));
    const offActions = subscribeTopic('actions.new', () => setRefreshKey((k) => k + 1));
    const offHoneypot = subscribeTopic('honeypot.interactions', () => setRefreshKey((k) => k + 1));
    return () => {
      offStatus();
      offIncidents();
      offActions();
      offHoneypot();
    };
  }, []);

  // Derived
  const openIncidents = useMemo(
    () => incidents.filter((i) => (i.status || '').toLowerCase() !== 'resolved'),
    [incidents],
  );

  const latest = openIncidents[0]; // backend already returns newest-first
  const pendingActions = useMemo(
    () => actions.filter((a) => (a.status || '').toLowerCase() === 'pending').slice(0, 5),
    [actions],
  );

  const assetRows: AssetRiskRow[] = useMemo(() => {
    const rows: AssetRiskRow[] = MONITORED_APPS.map((app) => {
      const appIncs = incidents.filter((i) => {
        const hay = `${i.source} ${i.title}`.toLowerCase();
        return hay.includes(app);
      });
      const resolved = appIncs.filter((i) => (i.status || '').toLowerCase() === 'resolved').length;
      const open = appIncs.length - resolved;
      // Risk: weight open critical/high heavily
      const crit = appIncs.filter((i) => i.severity?.toLowerCase() === 'critical').length;
      const high = appIncs.filter((i) => i.severity?.toLowerCase() === 'high').length;
      const score = Math.min(10, crit * 3 + high * 1.5 + open * 0.4);
      return {
        asset: app,
        account: 'aegis-monitored',
        totalThreats: appIncs.length,
        resolved,
        riskScore: score,
      };
    });
    return rows.sort((a, b) => b.riskScore - a.riskScore);
  }, [incidents]);

  // Hero KPIs
  const latestIp = latest?.source_ip ?? incidents.find((i) => !!i.source_ip)?.source_ip ?? '—';
  const mitre = latest?.mitre_technique ?? '—';
  const affectedAsset = useMemo(() => {
    if (!latest) return '—';
    const hay = `${latest.source} ${latest.title}`.toLowerCase();
    return MONITORED_APPS.find((a) => hay.includes(a)) ?? (latest.source || 'unknown');
  }, [latest]);
  const confidence = useMemo(() => {
    if (!latest?.ai_analysis) return '—';
    const c = (latest.ai_analysis as Record<string, unknown>).confidence;
    if (typeof c === 'number') return `${Math.round(c * (c <= 1 ? 100 : 1))}%`;
    return '—';
  }, [latest]);

  if (loading) return <LoadingState message="Loading dashboard..." />;

  return (
    <div className="space-y-4 animate-fade-in pb-6">
      {/* HERO greeting + status + download */}
      <div className="flex items-start justify-between gap-4 pt-1">
        <div className="min-w-0">
          <p className="text-[11px] uppercase tracking-[0.18em] text-muted-foreground/60 font-mono mb-2">
            AEGIS Command · {new Date().toLocaleDateString(undefined, { weekday: 'long', month: 'short', day: 'numeric' })}
          </p>
          <h1 className="text-[26px] sm:text-[34px] lg:text-[40px] font-semibold tracking-[-0.025em] leading-none text-foreground">
            {latest ? (
              <>
                <span className="text-muted-foreground/70">Hello,</span>{' '}
                <Link
                  href={`/dashboard/response`}
                  className="inline-flex items-center gap-2 text-[var(--brand-accent)] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand-accent)]/60 rounded-md"
                >
                  #INC-{shortId(latest.id)}
                </Link>
              </>
            ) : (
              <>
                <span className="text-muted-foreground/70">All</span>{' '}
                <span className="text-foreground">quiet</span>
              </>
            )}
          </h1>
          <div className="flex items-center gap-3 mt-3 text-[12px] text-muted-foreground">
            {latest ? (
              <>
                <span className="inline-flex items-center gap-1.5">
                  <span
                    className="w-1.5 h-1.5 rounded-full"
                    style={{ background: severityBadgeColor(latest.severity) }}
                    aria-hidden
                  />
                  <span className="uppercase tracking-wider text-[10px] font-mono"
                    style={{ color: severityBadgeColor(latest.severity) }}>
                    {latest.severity}
                  </span>
                </span>
                <span className="text-muted-foreground/40">·</span>
                <span className="truncate max-w-[60ch]">{latest.title}</span>
                <span className="text-muted-foreground/40">·</span>
                <span className="font-mono text-[11px]">{relativeTime(latest.detected_at)}</span>
              </>
            ) : (
              <span>No open incidents · last attack {relativeTime(incidents[0]?.detected_at)}</span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <StatusPill status={wsStatus} />
          <button
            type="button"
            className={cn(
              'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md',
              'bg-card border border-border text-[12px] text-foreground/90',
              'hover:bg-white/[0.04] hover:border-white/[0.12]',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand-accent)]/60 focus-visible:ring-offset-2 focus-visible:ring-offset-background',
              'transition-colors',
            )}
            onClick={() => {
              // Navigate to reports page for now (export center)
              window.location.href = '/dashboard/reports';
            }}
            aria-label="Download report"
          >
            <Download size={13} />
            <span>Download</span>
          </button>
        </div>
      </div>

      {/* KPI TILES */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 stagger-children">
        <KPITile
          label="Affected Asset"
          value={affectedAsset}
          sub={latest ? `source: ${latest.source}` : 'no active incidents'}
          tone={latest ? 'accent' : 'neutral'}
          warm
        />
        <KPITile
          label="MITRE Technique"
          value={mitre}
          sub={latest?.mitre_technique ? (mitreInfo(latest.mitre_technique)?.plain ?? 'view campaign cluster') : '—'}
          href="/dashboard/threats/campaigns"
          tone={latest?.mitre_technique ? 'warning' : 'neutral'}
        />
        <KPITile
          label="Source IP"
          value={latestIp}
          sub={latestIp !== '—' ? 'click for IP intel' : '—'}
          href={latestIp !== '—' ? `/dashboard/ip-intel?ip=${encodeURIComponent(latestIp)}` : undefined}
          tone={latestIp !== '—' ? 'danger' : 'neutral'}
          warm
        />
        <KPITile
          label="Confidence"
          value={confidence}
          sub={`${openIncidents.length} open · ${pendingActions.length} pending`}
          tone={confidence !== '—' ? 'success' : 'neutral'}
        />
      </div>

      {/* INCIDENT TIMELINE — signature feature */}
      <IncidentTimeline incidents={openIncidents.length > 0 ? openIncidents : incidents} days={14} />

      {/* Row: AI Actions (2/3) + Login Attempts (1/3 narrow) + Threat Detection (1/3) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3">
        <div className="lg:col-span-5">
          <AISuggestedActions
            actions={pendingActions}
            onChanged={() => setRefreshKey((k) => k + 1)}
          />
        </div>
        <div className="lg:col-span-3">
          <LoginAttemptsHeatmap interactions={interactions} hours={24} columns={10} />
        </div>
        <div className="lg:col-span-4">
          <ThreatDetectionChart incidents={incidents} days={7} />
        </div>
      </div>

      {/* Row: Asset Risk Table + Global Threat Map */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3">
        <div className="lg:col-span-8">
          <AssetRiskTable rows={assetRows} />
        </div>
        <div className="lg:col-span-4">
          <Panel className="h-full flex flex-col">
            <SectionHeader
              title="Global Threat Map"
              icon={<Radar size={13} />}
              count={`${threatMap.length} sources`}
            />
            <div className="flex-1 min-h-[360px] relative">
              <GlobalThreatMap data={threatMap} />
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
