'use client';

import * as React from 'react';
import { KPI } from '@/components/aegis';
import { resolveTactic } from './mitreTactics';

export interface CampaignSummary {
  cluster_id: string;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  distinct_ips: number;
  total_incidents: number;
  last_seen: string | null;
}

export function KPIStrip({ campaigns }: { campaigns: CampaignSummary[] }) {
  const stats = React.useMemo(() => {
    const total = campaigns.length;
    const now = Date.now();
    const activeCount = campaigns.filter(
      (c) => c.last_seen && now - new Date(c.last_seen).getTime() <= 24 * 3600 * 1000,
    ).length;
    const ipUnion = new Set<string>();
    for (const c of campaigns) ipUnion.add(`${c.cluster_id}:${c.distinct_ips}`);
    const distinctIPs = campaigns.reduce((acc, c) => acc + (c.distinct_ips || 0), 0);
    const tacticCounts = new Map<string, number>();
    for (const c of campaigns) {
      const t = resolveTactic(c.mitre_tactic);
      if (!t) continue;
      tacticCounts.set(t.label, (tacticCounts.get(t.label) || 0) + 1);
    }
    let topTactic = '—';
    let topCount = 0;
    for (const [label, count] of tacticCounts) {
      if (count > topCount) {
        topTactic = label;
        topCount = count;
      }
    }
    return { total, activeCount, distinctIPs, topTactic };
  }, [campaigns]);

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
      <KPI
        label="Total campaigns"
        value={stats.total}
        sub={stats.total === 0 ? 'No clusters in window' : `clusters in window`}
        tone="neutral"
        warm
      />
      <KPI
        label="Active (24h)"
        value={stats.activeCount}
        sub={stats.activeCount > 0 ? 'Incidents in last 24h' : 'Dormant'}
        tone={stats.activeCount > 0 ? 'danger' : 'neutral'}
      />
      <KPI
        label="Attacker IPs"
        value={stats.distinctIPs}
        sub="Aggregate distinct sources"
        tone="warning"
      />
      <KPI
        label="Top tactic"
        value={<span className="text-[16px] sm:text-[18px] lg:text-[20px]">{stats.topTactic}</span>}
        sub={stats.topTactic === '—' ? 'No MITRE-tagged data' : 'Most-seen MITRE tactic'}
        tone="accent"
      />
    </div>
  );
}
