'use client';

import { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { ArrowLeft02Icon } from 'hugeicons-react';
import {
  RefreshCw, Send, Globe, Hash, Link as LinkIcon, Monitor,
  Share2, Database, Users, AlertTriangle, CheckCircle2,
} from 'lucide-react';
import { Panel } from '@/components/aegis/Panel';
import { SectionHeader } from '@/components/aegis/SectionHeader';
import { EmptyState } from '@/components/aegis/EmptyState';
import { KPI } from '@/components/aegis/KPI';
import { StatusBadge } from '@/components/aegis/StatusBadge';
import { LoadingState } from '@/components/shared/LoadingState';
import { api } from '@/lib/api';
import { cn, formatDate } from '@/lib/utils';

// ─── Types ────────────────────────────────────────────────────────────────────

interface SharingStats {
  iocs_submitted: number;
  iocs_received: number;
  last_sync: string | null;
  unique_contributors: number;
  sync_errors: number;
  sharing_enabled: boolean;
  share_mode: string;
  is_hub: boolean;
  hub_url: string;
}

interface SharingConfig {
  intel_sharing_enabled: boolean;
  share_mode: string;
  hub_url: string;
  auto_submit: boolean;
  min_confidence: number;
}

interface CommunityIOC {
  id: string;
  ioc_type: string;
  ioc_value: string;
  threat_type: string;
  confidence: number;
  mitre_techniques: string[];
  source_hash: string;
  report_count: number;
  verified: boolean;
  first_seen: string | null;
  last_seen: string | null;
  expires_at: string | null;
}

const IOC_TYPES = ['ip', 'domain', 'hash', 'url'] as const;

const THREAT_TYPES = [
  'brute_force', 'c2', 'botnet_c2', 'phishing', 'malware',
  'ransomware', 'scan', 'port_scan', 'tor_exit', 'abusive_ip', 'other',
];

const iocTypeIcon: Record<string, typeof Monitor> = {
  ip: Monitor,
  domain: Globe,
  hash: Hash,
  url: LinkIcon,
};

const iocTypeColor: Record<string, string> = {
  ip: 'text-[var(--brand-accent)] bg-[var(--brand-accent)]/10',
  domain: 'text-[var(--chart-5,#a78bfa)] bg-[color-mix(in_oklab,var(--chart-5,#a78bfa)_10%,transparent)]',
  hash: 'text-[var(--warning)] bg-[var(--warning)]/10',
  url: 'text-[var(--info,#38bdf8)] bg-[var(--info,#38bdf8)]/10',
};

// ─── Component ────────────────────────────────────────────────────────────────

export default function ThreatSharingPage() {
  const [stats, setStats] = useState<SharingStats | null>(null);
  const [config, setConfig] = useState<SharingConfig | null>(null);
  const [iocs, setIocs] = useState<CommunityIOC[]>([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState<string | null>(null);
  const [submitLoading, setSubmitLoading] = useState(false);
  const [submitMsg, setSubmitMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [togglingEnabled, setTogglingEnabled] = useState(false);

  const [form, setForm] = useState({
    ioc_type: 'ip' as typeof IOC_TYPES[number],
    ioc_value: '',
    threat_type: 'brute_force',
    confidence: 0.75,
    mitre_techniques: '',
  });

  // ── Data fetch ─────────────────────────────────────────────────────────────

  const loadAll = useCallback(async () => {
    try {
      const [statsData, configData, iocsData] = await Promise.allSettled([
        api.get<SharingStats>('/intel/community/stats'),
        api.get<SharingConfig>('/intel/sharing/config'),
        api.get<{ iocs: CommunityIOC[]; total: number; page: number; per_page: number; pages: number }>('/intel/community?per_page=50'),
      ]);
      if (statsData.status === 'fulfilled') setStats(statsData.value);
      if (configData.status === 'fulfilled') setConfig(configData.value);
      if (iocsData.status === 'fulfilled') setIocs(iocsData.value.iocs);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  // ── Actions ────────────────────────────────────────────────────────────────

  const handleToggleEnabled = async () => {
    if (!config) return;
    setTogglingEnabled(true);
    try {
      const next = !config.intel_sharing_enabled;
      const updated = await api.put<SharingConfig>('/intel/sharing/config', {
        intel_sharing_enabled: next,
      });
      setConfig(updated);
      // Refresh stats too
      const s = await api.get<SharingStats>('/intel/community/stats');
      setStats(s);
    } catch {
      // silently surface nothing; the toggle reverts on next load
    } finally {
      setTogglingEnabled(false);
    }
  };

  const handleSync = async () => {
    setSyncing(true);
    setSyncMsg(null);
    try {
      const result = await api.post<{ status: string; new: number; updated: number; decayed: number; errors: number; message?: string }>('/intel/sync');
      if (result.status === 'disabled') {
        setSyncMsg('Sharing is disabled — enable it first.');
      } else {
        setSyncMsg(`Sync complete: +${result.new} new, ${result.updated} updated, ${result.decayed} decayed.`);
        await loadAll();
      }
    } catch (e) {
      setSyncMsg(`Sync failed: ${(e as Error).message}`);
    } finally {
      setSyncing(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.ioc_value.trim()) return;
    setSubmitLoading(true);
    setSubmitMsg(null);
    try {
      const mitres = form.mitre_techniques
        .split(',').map((s) => s.trim()).filter(Boolean);
      await api.post('/intel/share', {
        ioc_type: form.ioc_type,
        ioc_value: form.ioc_value.trim(),
        threat_type: form.threat_type,
        confidence: form.confidence,
        mitre_techniques: mitres,
      });
      setSubmitMsg({ ok: true, text: `IOC submitted: ${form.ioc_type}:${form.ioc_value.trim()}` });
      setForm((f) => ({ ...f, ioc_value: '', mitre_techniques: '' }));
      await loadAll();
    } catch (e) {
      const msg = (e as Error).message || 'Submission failed';
      setSubmitMsg({ ok: false, text: msg });
    } finally {
      setSubmitLoading(false);
    }
  };

  // ── Render ─────────────────────────────────────────────────────────────────

  if (loading) return <LoadingState message="Loading threat sharing..." />;

  const sharingEnabled = config?.intel_sharing_enabled ?? false;
  const isHub = stats?.is_hub ?? true;

  return (
    <div className="space-y-5 animate-fade-in">

      {/* Page header */}
      <header className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <div className="flex items-center gap-2 text-[11px] text-muted-foreground mb-1">
            <Link
              href="/dashboard/threats"
              className="hover:text-foreground flex items-center gap-1 focus:outline-none focus:ring-2 focus:ring-[var(--brand-accent)]/60 rounded"
            >
              <ArrowLeft02Icon size={12} aria-hidden /> Threats
            </Link>
            <span>/</span>
            <span>Sharing</span>
          </div>
          <h1 className="text-2xl font-semibold text-foreground flex items-center gap-2">
            <Share2 size={22} className="text-[var(--brand-accent)]" aria-hidden />
            Threat Sharing
          </h1>
          <p className="text-[13px] text-muted-foreground mt-1 max-w-[68ch]">
            Community IOC sharing — anonymized indicators propagate to all AEGIS deployments. More instances = stronger collective defense.
          </p>
        </div>
      </header>

      {/* Status banner */}
      {isHub ? (
        <Panel variant="default" padding="sm" as="div">
          <p className="text-[12px] text-[var(--brand-accent)] font-medium flex items-center gap-2">
            <CheckCircle2 size={14} aria-hidden />
            Hub mode — this instance is the community hub. IOCs submitted here are served to all AEGIS clients.
          </p>
        </Panel>
      ) : (
        <Panel variant="default" padding="sm" as="div">
          <p className="text-[12px] text-muted-foreground flex items-center gap-2">
            <Globe size={14} aria-hidden />
            Client mode — sharing to hub at <span className="font-mono">{stats?.hub_url}</span>.
          </p>
        </Panel>
      )}

      {/* KPI tiles */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <KPI
          label="IOCs Submitted"
          value={stats?.iocs_submitted ?? 0}
          tone="accent"
          warm
        />
        <KPI
          label="IOCs Received"
          value={stats?.iocs_received ?? 0}
          tone="success"
        />
        <KPI
          label="Contributors"
          value={stats?.unique_contributors ?? 0}
          tone="neutral"
        />
        <KPI
          label="Sync Errors"
          value={stats?.sync_errors ?? 0}
          tone={stats?.sync_errors ? 'danger' : 'neutral'}
        />
      </div>

      {/* Config panel */}
      <Panel padding="none" as="div">
        <SectionHeader
          title="Sharing Configuration"
          icon={<Database size={14} />}
          action={
            <button
              onClick={handleSync}
              disabled={syncing || !sharingEnabled}
              className="flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground hover:text-foreground disabled:opacity-40 disabled:cursor-not-allowed transition-colors px-2 py-1 rounded-lg hover:bg-white/[0.05]"
              title={!sharingEnabled ? 'Enable sharing first' : 'Manual sync'}
            >
              <RefreshCw size={12} className={cn(syncing && 'animate-spin')} />
              {syncing ? 'Syncing…' : 'Sync now'}
            </button>
          }
        />
        <div className="p-4 sm:p-5 space-y-4">
          {syncMsg && (
            <p className={cn('text-[12px] font-mono', syncMsg.includes('fail') ? 'text-[var(--danger)]' : 'text-[var(--success)]')}>
              {syncMsg}
            </p>
          )}

          {/* Master toggle */}
          <div className="flex items-center justify-between gap-4 rounded-xl border border-border p-3 sm:p-4">
            <div>
              <p className="text-[13px] font-medium text-foreground">Intel Sharing</p>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                Enable to submit IOCs to the community and receive shared indicators.
                IOCs are anonymized before transmission — no identifying data leaves this instance.
              </p>
            </div>
            <button
              role="switch"
              aria-checked={sharingEnabled}
              aria-label="Toggle intel sharing"
              onClick={handleToggleEnabled}
              disabled={togglingEnabled}
              className={cn(
                'relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors duration-200',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand-accent)]/60 focus-visible:ring-offset-2 focus-visible:ring-offset-background',
                'disabled:opacity-50 disabled:cursor-not-allowed',
                sharingEnabled ? 'bg-[var(--brand-accent)]' : 'bg-white/[0.1]',
              )}
            >
              <span
                className={cn(
                  'pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow-sm transition-transform duration-200',
                  sharingEnabled ? 'translate-x-5' : 'translate-x-0',
                )}
              />
            </button>
          </div>

          {/* Config summary */}
          {config && (
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-[12px]">
              <div className="rounded-xl border border-border p-3">
                <p className="text-muted-foreground uppercase tracking-wider text-[10px] mb-1">Mode</p>
                <p className="font-mono text-foreground">{config.share_mode}</p>
              </div>
              <div className="rounded-xl border border-border p-3">
                <p className="text-muted-foreground uppercase tracking-wider text-[10px] mb-1">Auto Submit</p>
                <p className="font-mono text-foreground">{config.auto_submit ? 'enabled' : 'disabled'}</p>
              </div>
              <div className="rounded-xl border border-border p-3">
                <p className="text-muted-foreground uppercase tracking-wider text-[10px] mb-1">Min Confidence</p>
                <p className="font-mono text-foreground">{Math.round(config.min_confidence * 100)}%</p>
              </div>
            </div>
          )}

          {/* Last sync */}
          {stats?.last_sync && (
            <p className="text-[11px] text-muted-foreground">
              Last sync: <span className="font-mono">{formatDate(stats.last_sync)}</span>
            </p>
          )}
        </div>
      </Panel>

      {/* Submit IOC form */}
      <Panel padding="none" as="div">
        <SectionHeader
          title="Submit IOC"
          icon={<Send size={14} />}
        />
        <form onSubmit={handleSubmit} className="p-4 sm:p-5 space-y-4">
          {!sharingEnabled && (
            <Panel variant="warning" padding="sm" as="div">
              <p className="text-[12px] text-[var(--warning)] flex items-center gap-2">
                <AlertTriangle size={13} aria-hidden />
                Intel sharing is disabled. Enable it above to submit IOCs to the community.
              </p>
            </Panel>
          )}

          {submitMsg && (
            <p className={cn('text-[12px] font-mono', submitMsg.ok ? 'text-[var(--success)]' : 'text-[var(--danger)]')}>
              {submitMsg.text}
            </p>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {/* IOC Type */}
            <div>
              <label className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block mb-1.5">
                IOC Type
              </label>
              <select
                value={form.ioc_type}
                onChange={(e) => setForm({ ...form, ioc_type: e.target.value as typeof IOC_TYPES[number] })}
                className="w-full bg-background border border-border rounded-xl px-3 py-2.5 text-sm text-foreground focus:outline-none focus:border-[var(--brand-accent)]/30"
              >
                {IOC_TYPES.map((t) => (
                  <option key={t} value={t}>{t.toUpperCase()}</option>
                ))}
              </select>
            </div>

            {/* Threat Type */}
            <div>
              <label className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block mb-1.5">
                Threat Type
              </label>
              <select
                value={form.threat_type}
                onChange={(e) => setForm({ ...form, threat_type: e.target.value })}
                className="w-full bg-background border border-border rounded-xl px-3 py-2.5 text-sm text-foreground focus:outline-none focus:border-[var(--brand-accent)]/30"
              >
                {THREAT_TYPES.map((t) => (
                  <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
                ))}
              </select>
            </div>
          </div>

          {/* IOC Value */}
          <div>
            <label className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block mb-1.5">
              Indicator Value
            </label>
            <input
              type="text"
              value={form.ioc_value}
              onChange={(e) => setForm({ ...form, ioc_value: e.target.value })}
              placeholder="e.g. 192.168.1.1 / evil.com / d41d8cd98f00b204..."
              required
              className="w-full bg-background border border-border rounded-xl px-4 py-2.5 text-sm text-foreground font-mono placeholder:text-muted-foreground/60 focus:outline-none focus:border-[var(--brand-accent)]/30"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {/* Confidence */}
            <div>
              <label className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block mb-1.5">
                Confidence: <span className="font-mono">{Math.round(form.confidence * 100)}%</span>
              </label>
              <input
                type="range"
                min={0}
                max={1}
                step={0.05}
                value={form.confidence}
                onChange={(e) => setForm({ ...form, confidence: parseFloat(e.target.value) })}
                className="w-full accent-[var(--brand-accent)]"
              />
              <div className="flex justify-between text-[10px] text-muted-foreground/50 mt-0.5">
                <span>0%</span><span>50%</span><span>100%</span>
              </div>
            </div>

            {/* MITRE Techniques */}
            <div>
              <label className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block mb-1.5">
                MITRE Techniques <span className="normal-case font-normal">(comma-separated, optional)</span>
              </label>
              <input
                type="text"
                value={form.mitre_techniques}
                onChange={(e) => setForm({ ...form, mitre_techniques: e.target.value })}
                placeholder="T1078, T1110"
                className="w-full bg-background border border-border rounded-xl px-4 py-2.5 text-sm text-foreground font-mono placeholder:text-muted-foreground/60 focus:outline-none focus:border-[var(--brand-accent)]/30"
              />
            </div>
          </div>

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={submitLoading || !form.ioc_value.trim() || !sharingEnabled}
              title={!sharingEnabled ? 'Enable sharing first' : !form.ioc_value.trim() ? 'Enter an indicator value' : undefined}
              className="flex items-center gap-2 bg-[var(--brand-accent)] hover:opacity-90 text-background font-semibold px-5 py-2.5 rounded-xl transition-opacity text-[13px] disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <Send size={14} />
              {submitLoading ? 'Submitting…' : 'Submit IOC'}
            </button>
          </div>
        </form>
      </Panel>

      {/* Community IOCs table */}
      <Panel padding="none" as="div">
        <SectionHeader
          title="Community IOCs"
          icon={<Users size={14} />}
          count={`${iocs.length} indicators`}
        />

        {iocs.length === 0 ? (
          <EmptyState
            icon={<Users size={28} aria-hidden />}
            title="No community IOCs yet"
            description={
              sharingEnabled
                ? 'IOCs from other AEGIS instances will appear here after the next sync cycle (every 15 min).'
                : 'Enable intel sharing above and sync to receive community indicators.'
            }
            size="md"
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[12px]" aria-label="Community IOCs">
              <thead>
                <tr className="border-b border-border text-muted-foreground">
                  <th className="text-left px-4 sm:px-5 py-3 font-medium uppercase tracking-wider text-[10px]">Type</th>
                  <th className="text-left px-3 py-3 font-medium uppercase tracking-wider text-[10px]">Value</th>
                  <th className="text-left px-3 py-3 font-medium uppercase tracking-wider text-[10px]">Threat</th>
                  <th className="text-left px-3 py-3 font-medium uppercase tracking-wider text-[10px]">Confidence</th>
                  <th className="text-left px-3 py-3 font-medium uppercase tracking-wider text-[10px]">Reports</th>
                  <th className="text-left px-3 py-3 font-medium uppercase tracking-wider text-[10px]">Verified</th>
                  <th className="text-left px-3 py-3 font-medium uppercase tracking-wider text-[10px]">Last Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {iocs.map((ioc) => {
                  const Icon = iocTypeIcon[ioc.ioc_type] || Monitor;
                  const colorClass = iocTypeColor[ioc.ioc_type] || 'text-muted-foreground bg-white/[0.05]';
                  const pct = Math.round(ioc.confidence * 100);
                  return (
                    <tr key={ioc.id} className="hover:bg-white/[0.02] transition-colors">
                      <td className="px-4 sm:px-5 py-3">
                        <div className={cn('inline-flex items-center gap-1.5 rounded-lg px-2 py-1', colorClass.split(' ')[1])}>
                          <Icon size={11} className={colorClass.split(' ')[0]} aria-hidden />
                          <span className={cn('text-[10px] font-semibold uppercase', colorClass.split(' ')[0])}>
                            {ioc.ioc_type}
                          </span>
                        </div>
                      </td>
                      <td className="px-3 py-3">
                        <span className="font-mono text-foreground truncate max-w-[180px] inline-block" title={ioc.ioc_value}>
                          {ioc.ioc_value}
                        </span>
                      </td>
                      <td className="px-3 py-3 text-muted-foreground capitalize">
                        {ioc.threat_type.replace(/_/g, ' ')}
                      </td>
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-12 h-1 bg-white/[0.06] rounded-full overflow-hidden">
                            <div
                              className={cn(
                                'h-full rounded-full',
                                pct >= 80 ? 'bg-[var(--success)]' : pct >= 60 ? 'bg-[var(--warning)]' : 'bg-[var(--danger)]'
                              )}
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                          <span className="font-mono text-muted-foreground text-[10px]">{pct}%</span>
                        </div>
                      </td>
                      <td className="px-3 py-3 font-mono text-muted-foreground">{ioc.report_count}</td>
                      <td className="px-3 py-3">
                        <StatusBadge
                          variant={ioc.verified ? 'success' : 'muted'}
                          size="sm"
                        >
                          {ioc.verified ? 'verified' : 'pending'}
                        </StatusBadge>
                      </td>
                      <td className="px-3 py-3 text-muted-foreground font-mono text-[10px]">
                        {ioc.last_seen ? formatDate(ioc.last_seen) : '—'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

    </div>
  );
}
