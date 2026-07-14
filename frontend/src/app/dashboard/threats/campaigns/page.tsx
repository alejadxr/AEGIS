'use client';

import { Suspense, useCallback, useEffect, useMemo, useState } from 'react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { Target02Icon, ArrowLeft02Icon } from 'hugeicons-react';
import { LoadingState } from '@/components/shared/LoadingState';
import { EmptyState, Panel } from '@/components/aegis';
import { api } from '@/lib/api';
import { CampaignFilters, type FilterState } from '@/components/threats/CampaignFilters';
import { KPIStrip, type CampaignSummary } from '@/components/threats/KPIStrip';
import { CampaignCard } from '@/components/threats/CampaignCard';
import { resolveTactic } from '@/components/threats/mitreTactics';

interface Campaign extends CampaignSummary {
  ttp_fingerprint: string;
  first_seen: string | null;
  sample_ips: string[];
  window_hours: number;
}

const MitreMatrix = dynamic(() => import('@/components/threats/MitreMatrix'), {
  ssr: false,
  loading: () => (
    <Panel padding="md">
      <div className="h-[180px] animate-pulse bg-[color-mix(in_oklab,var(--brand-accent)_4%,transparent)] rounded-lg" />
    </Panel>
  ),
});

function CampaignsPageInner() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const initialFilters: FilterState = useMemo(
    () => ({
      // Default to the full 30-day retention window so historical, IP-rotating
      // campaigns (whose last activity may be weeks old) render on first load.
      windowHours: Number(searchParams.get('window')) || 720,
      minIps: Number(searchParams.get('min_ips')) || 2,
      tactic: searchParams.get('tactic') || '',
      severity: searchParams.get('severity') || 'all',
    }),
    // initial only
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  const [filters, setFilters] = useState<FilterState>(initialFilters);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Persist filters to URL (debounced via micro-deferral)
  useEffect(() => {
    const params = new URLSearchParams();
    params.set('window', String(filters.windowHours));
    params.set('min_ips', String(filters.minIps));
    if (filters.tactic) params.set('tactic', filters.tactic);
    if (filters.severity !== 'all') params.set('severity', filters.severity);
    const url = `/dashboard/threats/campaigns?${params.toString()}`;
    router.replace(url, { scroll: false });
  }, [filters, router]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.threats.campaigns({
        window_hours: filters.windowHours,
        min_distinct_ips: filters.minIps,
        limit: 50,
      });
      setCampaigns(data.campaigns as Campaign[]);
    } catch (e) {
      setError((e as Error).message || 'Failed to load campaigns');
      setCampaigns([]);
    } finally {
      setLoading(false);
    }
  }, [filters.windowHours, filters.minIps]);

  useEffect(() => {
    load();
  }, [load]);

  const visibleCampaigns = useMemo(() => {
    return campaigns.filter((c) => {
      if (filters.tactic) {
        const t = resolveTactic(c.mitre_tactic);
        if (!t || t.id !== filters.tactic) return false;
      }
      // Severity filter is best-effort; the list endpoint doesn't expose
      // per-campaign severity. Keep filter neutral here — drill-down has it.
      return true;
    });
  }, [campaigns, filters.tactic]);

  const handleExportCsv = useCallback(() => {
    const rows = [
      ['cluster_id', 'tactic', 'technique', 'distinct_ips', 'total_incidents', 'first_seen', 'last_seen'],
      ...visibleCampaigns.map((c) => [
        c.cluster_id,
        c.mitre_tactic || '',
        c.mitre_technique || '',
        String(c.distinct_ips),
        String(c.total_incidents),
        c.first_seen || '',
        c.last_seen || '',
      ]),
    ];
    const csv = rows.map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis-campaigns-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [visibleCampaigns]);

  return (
    <div className="p-4 sm:p-6 space-y-5">
      {/* Hero */}
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
            <span>Campaigns</span>
          </div>
          <h1 className="text-2xl font-semibold text-foreground flex items-center gap-2">
            <Target02Icon size={22} className="text-[var(--brand-accent)]" aria-hidden />
            Threat Campaigns
          </h1>
          <p className="text-[13px] text-muted-foreground mt-1 max-w-[68ch]">
            Recurring MITRE ATT&amp;CK patterns across distinct attacker IPs. Surfaces IP-rotating actors
            (Tor, VPN, botnets). No auto-block — human triage only.
          </p>
        </div>
      </header>

      {/* KPI strip */}
      <KPIStrip campaigns={campaigns} />

      {/* Filters */}
      <CampaignFilters
        value={filters}
        onChange={setFilters}
        onRefresh={load}
        onExportCsv={handleExportCsv}
        loading={loading}
      />

      {/* MITRE matrix */}
      <MitreMatrix
        campaigns={campaigns}
        selectedTactic={filters.tactic}
        onSelectTactic={(id) => setFilters({ ...filters, tactic: id })}
      />

      {/* List */}
      {error && (
        <Panel padding="md" variant="warning">
          <p className="text-[13px] text-[var(--warning)]">{error}</p>
        </Panel>
      )}

      {loading ? (
        <LoadingState />
      ) : visibleCampaigns.length === 0 ? (
        <Panel padding="lg">
          <EmptyState
            icon={<Target02Icon size={28} aria-hidden />}
            title="No campaigns matched"
            description={`AEGIS detects clusters when ≥ ${filters.minIps} distinct IPs trigger the same MITRE technique within the time window. Loosen filters or wait for more data.`}
            size="md"
          />
        </Panel>
      ) : (
        <div className="space-y-2.5">
          {visibleCampaigns.map((c) => (
            <CampaignCard key={c.cluster_id} campaign={c} />
          ))}
        </div>
      )}
    </div>
  );
}

export default function CampaignsPage() {
  return (
    <Suspense fallback={<LoadingState />}>
      <CampaignsPageInner />
    </Suspense>
  );
}
