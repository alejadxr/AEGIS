'use client';

import { useCallback, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent, MouseEvent } from 'react';
import {
  ChevronDown,
  Zap,
  Radio,
  RefreshCw,
  Terminal,
  Cpu,
  Layers,
  ShieldCheck,
  Crosshair,
  Sparkles,
  Filter,
  Search,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  Clock,
  ArrowUpRight,
  Shield,
  Activity,
} from 'lucide-react';
import { StatusBadge } from '@/components/aegis';
import type { StatusVariant } from '@/components/aegis';
import { IncidentDossier } from '@/components/dashboard/IncidentDossier';
import { api } from '@/lib/api';
import { cn, formatRelativeTime } from '@/lib/utils';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface TriageIncident {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: string;
  source: string | null;
  source_ip: string | null;
  mitre_technique: string | null;
  mitre_tactic: string | null;
  detected_at: string;
}

export interface TriagePendingAction {
  id: string;
  incident_id: string;
  action_type: string;
  target: string | null;
  status: string;
  created_at: string;
}

export interface TriageQueueProps {
  incidents: TriageIncident[];
  pendingActions: TriagePendingAction[];
  onApprove: (actionId: string) => Promise<void>;
  onReject: (actionId: string, reason?: string) => Promise<void>;
  loading?: boolean;
  error?: boolean;
  totalAssets?: number;
  monitoredApps?: number;
  onRetry?: () => void;
}

// ---------------------------------------------------------------------------
// Severity configuration (No left vertical spines!)
// ---------------------------------------------------------------------------

type SeverityKey = 'critical' | 'high' | 'medium' | 'low' | 'info';

const SEVERITY_CHIP: Record<
  SeverityKey,
  {
    label: string;
    bg: string;
    text: string;
    border: string;
    dot: string;
  }
> = {
  critical: {
    label: 'CRITICAL',
    bg: 'bg-red-500/10',
    text: 'text-red-400',
    border: 'border-red-500/30',
    dot: 'bg-red-400',
  },
  high: {
    label: 'HIGH',
    bg: 'bg-orange-500/10',
    text: 'text-orange-400',
    border: 'border-orange-500/30',
    dot: 'bg-orange-400',
  },
  medium: {
    label: 'MEDIUM',
    bg: 'bg-amber-500/10',
    text: 'text-amber-400',
    border: 'border-amber-500/30',
    dot: 'bg-amber-400',
  },
  low: {
    label: 'LOW',
    bg: 'bg-cyan-500/10',
    text: 'text-cyan-400',
    border: 'border-cyan-500/30',
    dot: 'bg-cyan-400',
  },
  info: {
    label: 'INFO',
    bg: 'bg-zinc-500/10',
    text: 'text-zinc-400',
    border: 'border-zinc-500/30',
    dot: 'bg-zinc-400',
  },
};

const SEVERITY_RANK: Record<SeverityKey, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function severityKey(severity: string | null | undefined): SeverityKey {
  const s = (severity ?? '').toLowerCase();
  if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low' || s === 'info') return s;
  return 'info';
}

type ActionUiState = { status: 'applying' | 'error'; message?: string };

// ---------------------------------------------------------------------------
// Pinned "awaiting your approval" region
// ---------------------------------------------------------------------------

function PendingActionsBlock({
  actions,
  actionState,
  onApprove,
  onReject,
}: {
  actions: TriagePendingAction[];
  actionState: Record<string, ActionUiState>;
  onApprove: (id: string) => void;
  onReject: (id: string) => void;
}) {
  return (
    <div className="border-b border-amber-500/25 bg-[#14120D] p-4 relative overflow-hidden">
      <div className="flex items-center justify-between gap-3 mb-3">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-amber-500" />
          </span>
          <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-amber-400">
            AWAITING OPERATOR APPROVAL
          </span>
        </div>
        <span className="font-mono text-[10px] text-amber-300 bg-amber-500/15 px-2.5 py-0.5 rounded border border-amber-500/30 font-bold">
          {actions.length} {actions.length === 1 ? 'ACTION REQUIRED' : 'ACTIONS REQUIRED'}
        </span>
      </div>

      <div className="flex flex-col gap-2">
        {actions.map((a) => {
          const state = actionState[a.id];
          const isBusy = state?.status === 'applying';
          return (
            <div
              key={a.id}
              className="flex items-center justify-between gap-4 p-3 rounded-lg bg-[#191712] border border-amber-500/20 hover:border-amber-500/40 transition-all flex-wrap"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-xs font-bold text-white uppercase tracking-tight">
                    {a.action_type}
                  </span>
                  {a.target && (
                    <span className="font-mono text-[11px] text-cyan-300 bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded">
                      {a.target}
                    </span>
                  )}
                </div>
                <p className="mt-1 font-mono text-[10px] text-zinc-400">
                  {isBusy ? (
                    <span className="text-amber-400 animate-pulse">Applying action...</span>
                  ) : (
                    <span>Requested {formatRelativeTime(a.created_at)}</span>
                  )}
                </p>
                {state?.status === 'error' && state.message && (
                  <p role="alert" className="mt-1 font-mono text-[11px] text-red-400">
                    {state.message}
                  </p>
                )}
              </div>

              <div className="shrink-0 flex items-center gap-2">
                <button
                  type="button"
                  disabled={isBusy}
                  onClick={() => onApprove(a.id)}
                  className="px-3.5 py-1.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/30 transition-all disabled:opacity-50 cursor-pointer shadow-[0_0_10px_rgba(16,185,129,0.15)]"
                >
                  Approve
                </button>
                <button
                  type="button"
                  disabled={isBusy}
                  onClick={() => onReject(a.id)}
                  className="px-3.5 py-1.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase bg-rose-500/10 border border-rose-500/30 text-rose-400 hover:bg-rose-500/20 transition-all disabled:opacity-50 cursor-pointer"
                >
                  Reject
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Clean Incident Row Component (No left vertical spines!)
// ---------------------------------------------------------------------------

function IncidentCard({
  incident,
  isOpen,
  isPendingApproval,
  onToggle,
  onApprove,
  onReject,
  onMutated,
}: {
  incident: TriageIncident;
  isOpen: boolean;
  isPendingApproval: boolean;
  onToggle: () => void;
  onApprove: (actionId: string) => Promise<void>;
  onReject: (actionId: string, reason?: string) => Promise<void>;
  onMutated: () => void;
}) {
  const sevKey = severityKey(incident.severity);
  const chipCfg = SEVERITY_CHIP[sevKey];
  const dossierId = `dossier-${incident.id}`;
  const dossierBodyRef = useRef<HTMLDivElement | null>(null);

  const statusChip: { variant: StatusVariant; label: string } = isPendingApproval
    ? { variant: 'info', label: 'AWAITING YOU' }
    : incident.status.toLowerCase() === 'investigating'
      ? { variant: 'warning', label: 'INVESTIGATING' }
      : { variant: 'muted', label: incident.status.toUpperCase() || 'OPEN' };

  const handleKeyDown = (e: KeyboardEvent<HTMLElement>) => {
    if (e.target !== e.currentTarget) return;
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onToggle();
    }
  };

  const handleClick = (e: MouseEvent<HTMLElement>) => {
    if (dossierBodyRef.current && dossierBodyRef.current.contains(e.target as Node)) return;
    onToggle();
  };

  return (
    <article
      role="button"
      tabIndex={0}
      aria-expanded={isOpen}
      aria-controls={dossierId}
      aria-label={incident.title}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      className={cn(
        'border-b border-white/[0.06] p-4 transition-colors duration-150 cursor-pointer group relative',
        isOpen ? 'bg-[#14141D]' : 'hover:bg-white/[0.02]',
      )}
    >
      <div className="flex items-start justify-between gap-4">
        {/* Left / Center Information block */}
        <div className="min-w-0 flex-1 space-y-1.5">
          <div className="flex items-center gap-2 flex-wrap">
            {/* Severity Pill with dot indicator */}
            <span
              className={cn(
                'inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider border',
                chipCfg.bg,
                chipCfg.text,
                chipCfg.border,
              )}
            >
              <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', chipCfg.dot)} />
              {chipCfg.label}
            </span>

            {/* MITRE Technique */}
            {incident.mitre_technique && (
              <span className="font-mono text-[10px] font-medium text-cyan-300 bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded">
                [{incident.mitre_technique}]
              </span>
            )}

            {/* MITRE Tactic */}
            {incident.mitre_tactic && (
              <span className="font-mono text-[10px] font-medium text-purple-300 bg-purple-500/10 border border-purple-500/20 px-2 py-0.5 rounded uppercase">
                {incident.mitre_tactic}
              </span>
            )}

            {/* Source IP */}
            {incident.source_ip && (
              <span className="font-mono text-[10px] text-zinc-300 bg-white/5 border border-white/10 px-2 py-0.5 rounded flex items-center gap-1">
                <Terminal className="w-3 h-3 text-cyan-400" />
                {incident.source_ip}
              </span>
            )}

            {/* Source Module */}
            {incident.source && (
              <span className="font-mono text-[10px] text-zinc-400 bg-white/[0.03] px-2 py-0.5 rounded">
                src: {incident.source}
              </span>
            )}
          </div>

          {/* Incident Title */}
          <h3 className="text-[15px] font-bold tracking-tight text-white group-hover:text-cyan-300 transition-colors">
            {incident.title}
          </h3>

          <div className="flex items-center gap-3 font-mono text-[11px] text-zinc-400 pt-0.5">
            <span className="flex items-center gap-1 text-zinc-400">
              <Clock className="w-3 h-3 text-zinc-500" />
              Detected {formatRelativeTime(incident.detected_at)}
            </span>
          </div>
        </div>

        {/* Right Status & Expand icon */}
        <div className="shrink-0 flex items-center gap-3">
          <StatusBadge size="sm" variant={statusChip.variant}>
            {statusChip.label}
          </StatusBadge>

          <ChevronDown
            className={cn(
              'w-4 h-4 text-zinc-400 transition-transform duration-200',
              isOpen && 'rotate-180 text-cyan-400',
            )}
          />
        </div>
      </div>

      {/* Expanded Accordion Body */}
      <div
        aria-hidden={!isOpen}
        className={cn(
          'grid transition-[grid-template-rows,opacity] duration-200 ease-out',
          isOpen ? 'grid-rows-[1fr] opacity-100 mt-4 pt-4 border-t border-white/10' : 'grid-rows-[0fr] opacity-0',
        )}
      >
        <div className="overflow-hidden min-h-0">
          <div ref={dossierBodyRef}>
            {isOpen && (
              <IncidentDossier
                incidentId={incident.id}
                title={incident.title}
                severity={sevKey}
                onApprove={onApprove}
                onReject={onReject}
                onMutated={onMutated}
              />
            )}
          </div>
        </div>
      </div>
    </article>
  );
}

// ---------------------------------------------------------------------------
// Zero-Incident Tactical Radar Empty State
// ---------------------------------------------------------------------------

function TriageEmptyBlock({
  totalAssets,
  monitoredApps,
}: {
  totalAssets?: number;
  monitoredApps?: number;
}) {
  const [scan, setScan] = useState<{ status: 'idle' | 'running' | 'done' | 'error'; message?: string }>({
    status: 'idle',
  });

  const handleScan = useCallback(async () => {
    setScan({ status: 'running' });
    try {
      const target = typeof window !== 'undefined' ? window.location.hostname : '';
      if (!target) throw new Error('No scan target available in this environment.');
      await api.surface.scan(target, 'discovery');
      setScan({ status: 'done', message: `Discovery scan started for ${target}.` });
    } catch (err) {
      setScan({ status: 'error', message: err instanceof Error ? err.message : 'Could not start scan.' });
    }
  }, []);

  return (
    <div className="p-8 flex flex-col items-center justify-center text-center relative overflow-hidden bg-[#0B0B0F] my-0">
      {/* Background crosshair grid pattern */}
      <div className="absolute inset-0 opacity-10 pointer-events-none bg-[radial-gradient(#38bdf8_1px,transparent_1px)] [background-size:24px_24px]" />

      <div className="relative z-10 flex flex-col items-center">
        <div className="p-3.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 mb-3 shadow-[0_0_20px_rgba(16,185,129,0.15)]">
          <ShieldCheck className="w-7 h-7" />
        </div>

        <h3 className="font-mono text-sm font-bold tracking-widest text-white uppercase">
          PERIMETER SECURE // ZERO OPEN INCIDENTS
        </h3>

        <p className="mt-1.5 max-w-md text-xs font-mono text-zinc-400 leading-relaxed">
          Continuous SIGMA correlation, honeypots, and surface scanners are running. No threat events require operator triage at this time.
        </p>

        {/* Tactical Telemetry Metrics */}
        <div className="mt-6 flex items-center justify-center gap-6 border-t border-b border-white/10 py-3.5 px-6 w-full max-w-lg font-mono text-xs flex-wrap">
          <div className="flex items-center gap-2">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-zinc-400">ASSETS:</span>
            <span className="font-bold text-white">{totalAssets ?? 45}</span>
          </div>

          <div className="flex items-center gap-2">
            <Layers className="w-3.5 h-3.5 text-purple-400" />
            <span className="text-zinc-400">APPS:</span>
            <span className="font-bold text-white">{monitoredApps ?? 12}</span>
          </div>

          <div className="flex items-center gap-2">
            <Crosshair className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-zinc-400">SIGMA:</span>
            <span className="font-bold text-emerald-400 uppercase">122 ARMED</span>
          </div>
        </div>

        <div className="mt-6 flex flex-col items-center gap-2">
          <button
            type="button"
            onClick={handleScan}
            disabled={scan.status === 'running'}
            className="flex items-center gap-2 px-4 py-2 rounded text-xs font-mono font-bold uppercase tracking-wider bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 hover:border-cyan-500/50 transition-all disabled:opacity-50 cursor-pointer shadow-[0_0_12px_rgba(6,182,212,0.15)]"
          >
            {scan.status === 'running' ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>STARTING SCAN...</span>
              </>
            ) : (
              <>
                <Radio className="w-3.5 h-3.5 text-cyan-400" />
                <span>TRIGGER DISCOVERY SCAN</span>
              </>
            )}
          </button>

          {scan.status === 'done' && (
            <p className="font-mono text-xs text-emerald-400 mt-1">{scan.message}</p>
          )}
          {scan.status === 'error' && (
            <p role="alert" className="font-mono text-xs text-red-400 mt-1">
              {scan.message}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Root Triage Queue Component
// ---------------------------------------------------------------------------

export function TriageQueue({
  incidents,
  pendingActions,
  onApprove,
  onReject,
  loading = false,
  error = false,
  totalAssets,
  monitoredApps,
  onRetry,
}: TriageQueueProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [actionState, setActionState] = useState<Record<string, ActionUiState>>({});
  const [visibleCount, setVisibleCount] = useState(8);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');

  const handleToggle = useCallback((id: string) => {
    setExpandedId((cur) => (cur === id ? null : id));
  }, []);

  const runApprove = useCallback(
    async (id: string) => {
      setActionState((s) => ({ ...s, [id]: { status: 'applying' } }));
      try {
        await onApprove(id);
        setActionState((s) => {
          const next = { ...s };
          delete next[id];
          return next;
        });
      } catch (err) {
        setActionState((s) => ({
          ...s,
          [id]: { status: 'error', message: err instanceof Error ? err.message : 'Could not approve this action.' },
        }));
      }
    },
    [onApprove],
  );

  const runReject = useCallback(
    async (id: string) => {
      setActionState((s) => ({ ...s, [id]: { status: 'applying' } }));
      try {
        await onReject(id);
        setActionState((s) => {
          const next = { ...s };
          delete next[id];
          return next;
        });
      } catch (err) {
        setActionState((s) => ({
          ...s,
          [id]: { status: 'error', message: err instanceof Error ? err.message : 'Could not reject this action.' },
        }));
      }
    },
    [onReject],
  );

  const handleRetry = useCallback(() => {
    if (onRetry) onRetry();
    else if (typeof window !== 'undefined') window.location.reload();
  }, [onRetry]);

  const handleMutated = useCallback(() => {
    onRetry?.();
  }, [onRetry]);

  // Compute filtered & sorted incidents
  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      const sevMatch =
        selectedSeverity === 'all' || severityKey(inc.severity) === selectedSeverity;
      const searchLower = searchQuery.toLowerCase();
      const textMatch =
        !searchQuery ||
        inc.title.toLowerCase().includes(searchLower) ||
        (inc.source_ip && inc.source_ip.toLowerCase().includes(searchLower)) ||
        (inc.mitre_technique && inc.mitre_technique.toLowerCase().includes(searchLower));
      return sevMatch && textMatch;
    });
  }, [incidents, selectedSeverity, searchQuery]);

  const sortedIncidents = useMemo(() => {
    return [...filteredIncidents].sort((a, b) => {
      const rankDiff = SEVERITY_RANK[severityKey(a.severity)] - SEVERITY_RANK[severityKey(b.severity)];
      if (rankDiff !== 0) return rankDiff;
      return new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime();
    });
  }, [filteredIncidents]);

  const pendingIncidentIds = new Set(pendingActions.map((a) => a.incident_id));
  const isEmpty = !loading && !error && incidents.length === 0 && pendingActions.length === 0;
  const visibleIncidents = sortedIncidents.slice(0, visibleCount);
  const remainingCount = sortedIncidents.length - visibleIncidents.length;

  // Severity counts
  const critCount = incidents.filter((i) => severityKey(i.severity) === 'critical').length;
  const highCount = incidents.filter((i) => severityKey(i.severity) === 'high').length;
  const medCount = incidents.filter((i) => severityKey(i.severity) === 'medium').length;
  const lowCount = incidents.filter((i) => severityKey(i.severity) === 'low').length;

  return (
    <section
      aria-label="Triage queue"
      aria-busy={loading}
      className="col-span-12 lg:col-span-8 flex flex-col border border-border/80 bg-[color-mix(in_oklab,var(--card)_95%,transparent)] backdrop-blur-md relative rounded-2xl group transition-all duration-300 hover:border-cyan-500/20 overflow-hidden"
    >
      {loading && (
        <span className="sr-only" role="status">
          Loading triage queue.
        </span>
      )}

      {/* Cyber SOC Header */}
      <div className="border-b border-border/80 bg-card/60 p-4 px-5 shrink-0 flex flex-col gap-3">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500" />
            </span>
            <div className="flex items-baseline gap-2.5">
              <h2 className="text-xs font-mono font-bold uppercase tracking-[0.18em] text-foreground">
                TRIAGE QUEUE
              </h2>
              {!loading && !error && (
                <span className="px-2 py-0.5 rounded font-mono text-[10px] font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                  {incidents.length} EVENTS
                </span>
              )}
            </div>
          </div>

          {/* Quick Search Input */}
          {!isEmpty && (
            <div className="relative w-48 sm:w-64">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-400 pointer-events-none" />
              <input
                type="text"
                placeholder="Filter by title, IP, MITRE..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-[#121217] border border-white/10 rounded-lg pl-8 pr-3 py-1 text-xs font-mono text-zinc-200 placeholder:text-zinc-500 focus:outline-none focus:border-cyan-500/40 transition-colors"
              />
            </div>
          )}
        </div>

        {/* Severity Distribution & Filter Chips */}
        {!isEmpty && (
          <div className="flex items-center gap-1.5 font-mono text-[10px] flex-wrap">
            <button
              type="button"
              onClick={() => setSelectedSeverity('all')}
              className={cn(
                'px-2.5 py-1 rounded font-bold transition-all cursor-pointer border',
                selectedSeverity === 'all'
                  ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                  : 'bg-white/5 text-zinc-400 border-white/10 hover:text-white',
              )}
            >
              ALL ({incidents.length})
            </button>
            <button
              type="button"
              onClick={() => setSelectedSeverity('critical')}
              className={cn(
                'px-2.5 py-1 rounded font-bold transition-all cursor-pointer border',
                selectedSeverity === 'critical'
                  ? 'bg-red-500/25 text-red-300 border-red-500/50'
                  : critCount > 0
                    ? 'bg-red-500/10 text-red-400 border-red-500/20 hover:bg-red-500/20'
                    : 'text-zinc-500 border-white/5 opacity-50',
              )}
            >
              {critCount} CRIT
            </button>
            <button
              type="button"
              onClick={() => setSelectedSeverity('high')}
              className={cn(
                'px-2.5 py-1 rounded font-bold transition-all cursor-pointer border',
                selectedSeverity === 'high'
                  ? 'bg-orange-500/25 text-orange-300 border-orange-500/50'
                  : highCount > 0
                    ? 'bg-orange-500/10 text-orange-400 border-orange-500/20 hover:bg-orange-500/20'
                    : 'text-zinc-500 border-white/5 opacity-50',
              )}
            >
              {highCount} HIGH
            </button>
            <button
              type="button"
              onClick={() => setSelectedSeverity('medium')}
              className={cn(
                'px-2.5 py-1 rounded font-bold transition-all cursor-pointer border',
                selectedSeverity === 'medium'
                  ? 'bg-amber-500/25 text-amber-300 border-amber-500/50'
                  : medCount > 0
                    ? 'bg-amber-500/10 text-amber-400 border-amber-500/20 hover:bg-amber-500/20'
                    : 'text-zinc-500 border-white/5 opacity-50',
              )}
            >
              {medCount} MED
            </button>
            <button
              type="button"
              onClick={() => setSelectedSeverity('low')}
              className={cn(
                'px-2.5 py-1 rounded font-bold transition-all cursor-pointer border',
                selectedSeverity === 'low'
                  ? 'bg-cyan-500/25 text-cyan-300 border-cyan-500/50'
                  : lowCount > 0
                    ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20 hover:bg-cyan-500/20'
                    : 'text-zinc-500 border-white/5 opacity-50',
              )}
            >
              {lowCount} LOW
            </button>
          </div>
        )}
      </div>

      <div className="flex flex-col">
        {error ? (
          <div className="p-6 text-center rounded-xl bg-red-500/5 border border-red-500/20 m-4">
            <p className="font-mono text-sm font-bold text-red-400">COULD NOT LOAD INCIDENTS</p>
            <p className="mt-1 text-xs text-zinc-400">
              The detection engine API did not respond. Detection is unaffected.
            </p>
            <button
              type="button"
              onClick={handleRetry}
              className="mt-3 px-3 py-1.5 rounded text-xs font-mono font-bold text-cyan-400 bg-cyan-500/10 border border-cyan-500/30 hover:bg-cyan-500/20 cursor-pointer"
            >
              RETRY FETCH
            </button>
          </div>
        ) : loading ? (
          <div aria-hidden="true" className="p-4 flex flex-col gap-2">
            {[0, 1, 2].map((i) => (
              <div key={i} className="h-16 rounded bg-white/5 animate-pulse border border-white/5" />
            ))}
          </div>
        ) : isEmpty ? (
          <TriageEmptyBlock totalAssets={totalAssets} monitoredApps={monitoredApps} />
        ) : (
          <>
            {pendingActions.length > 0 && (
              <PendingActionsBlock
                actions={pendingActions}
                actionState={actionState}
                onApprove={runApprove}
                onReject={runReject}
              />
            )}

            <div className="flex flex-col">
              {visibleIncidents.length === 0 ? (
                <div className="p-8 text-center text-zinc-500 font-mono text-xs">
                  No incidents match the active search or filter criteria.
                </div>
              ) : (
                visibleIncidents.map((incident) => (
                  <IncidentCard
                    key={incident.id}
                    incident={incident}
                    isOpen={expandedId === incident.id}
                    isPendingApproval={pendingIncidentIds.has(incident.id)}
                    onToggle={() => handleToggle(incident.id)}
                    onApprove={onApprove}
                    onReject={onReject}
                    onMutated={handleMutated}
                  />
                ))
              )}
            </div>

            {remainingCount > 0 && (
              <button
                type="button"
                onClick={() => setVisibleCount((n) => n + 20)}
                className="p-3 w-full border-t border-white/10 font-mono text-[11px] uppercase tracking-wider text-cyan-400 hover:bg-white/[0.03] transition-all cursor-pointer text-center"
              >
                SHOW {remainingCount} MORE INCIDENTS
              </button>
            )}
          </>
        )}
      </div>
    </section>
  );
}

export default TriageQueue;
