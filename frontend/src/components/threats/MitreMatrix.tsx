'use client';

import * as React from 'react';
import { Panel, SectionHeader } from '@/components/aegis';
import { LayoutGrid } from 'lucide-react';
import { MITRE_TACTICS, resolveTactic, tacticHeatColor } from './mitreTactics';
import { mitreLabel } from '@/lib/mitre';

export interface MatrixCampaign {
  cluster_id: string;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  total_incidents: number;
  distinct_ips: number;
}

interface CellData {
  tacticId: string;
  technique: string;
  campaigns: MatrixCampaign[];
  totalIncidents: number;
}

export interface MitreMatrixProps {
  campaigns: MatrixCampaign[];
  selectedTactic: string;
  onSelectTactic: (id: string) => void;
}

export default function MitreMatrix({ campaigns, selectedTactic, onSelectTactic }: MitreMatrixProps) {
  const { byTactic, maxIncidents } = React.useMemo(() => {
    const map: Record<string, CellData[]> = {};
    let max = 1;
    for (const c of campaigns) {
      const t = resolveTactic(c.mitre_tactic);
      if (!t) continue;
      const tech = c.mitre_technique || '(unspecified)';
      const bucket = (map[t.id] ||= []);
      let cell = bucket.find((b) => b.technique === tech);
      if (!cell) {
        cell = { tacticId: t.id, technique: tech, campaigns: [], totalIncidents: 0 };
        bucket.push(cell);
      }
      cell.campaigns.push(c);
      cell.totalIncidents += c.total_incidents || 0;
      if (cell.totalIncidents > max) max = cell.totalIncidents;
    }
    return { byTactic: map, maxIncidents: max };
  }, [campaigns]);

  const hasData = campaigns.length > 0;

  return (
    <Panel padding="md" className="space-y-4">
      <SectionHeader
        title="MITRE ATT&CK matrix"
        subtitle={hasData ? 'Heat = incident volume per technique. Click a tactic column to filter the list below.' : 'No campaigns yet — the matrix lights up as clusters form.'}
        icon={<LayoutGrid size={16} className="text-[var(--brand-accent)]" aria-hidden />}
      />

      <div className="overflow-x-auto -mx-1 px-1">
        <div className="min-w-[760px]">
          <div
            className="grid gap-1.5"
            style={{ gridTemplateColumns: `repeat(${MITRE_TACTICS.length}, minmax(56px, 1fr))` }}
            role="grid"
            aria-label="MITRE ATT&CK tactic heat map"
          >
            {MITRE_TACTICS.map((t) => {
              const active = selectedTactic === t.id;
              const has = (byTactic[t.id]?.length || 0) > 0;
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => onSelectTactic(active ? '' : t.id)}
                  aria-pressed={active}
                  className={`group rounded-lg px-1.5 py-2 text-left transition-colors focus:outline-none focus:ring-2 focus:ring-[var(--brand-accent)]/60 ${
                    active
                      ? 'bg-[color-mix(in_oklab,var(--brand-accent)_22%,transparent)] ring-1 ring-[var(--brand-accent)]/40'
                      : has
                      ? 'bg-card hover:bg-[color-mix(in_oklab,var(--brand-accent)_10%,transparent)]'
                      : 'bg-card/60 opacity-50'
                  }`}
                  title={t.label}
                >
                  <div className="text-[10px] font-medium uppercase tracking-[0.1em] text-muted-foreground truncate">
                    {t.short}
                  </div>
                  <div className="text-[14px] tabular-nums text-foreground mt-0.5">
                    {byTactic[t.id]?.length || 0}
                  </div>
                </button>
              );
            })}
          </div>

          {/* Technique cells under each tactic */}
          <div
            className="grid gap-1.5 mt-2"
            style={{ gridTemplateColumns: `repeat(${MITRE_TACTICS.length}, minmax(56px, 1fr))` }}
          >
            {MITRE_TACTICS.map((t) => {
              const cells = byTactic[t.id] || [];
              return (
                <div key={t.id} className="flex flex-col gap-1">
                  {cells.length === 0 ? (
                    <div
                      className="rounded-md border border-dashed border-border h-[28px]"
                      aria-hidden
                    />
                  ) : (
                    cells.map((cell) => {
                      const intensity = cell.totalIncidents / maxIncidents;
                      return (
                        <div
                          key={`${t.id}:${cell.technique}`}
                          className="rounded-md border border-border min-h-[44px] px-2 py-1 cursor-default"
                          style={{ background: tacticHeatColor(intensity) }}
                          title={`${mitreLabel(cell.technique)} · ${cell.totalIncidents} incidents across ${cell.campaigns.length} cluster(s)`}
                          tabIndex={0}
                          role="gridcell"
                        >
                          <div className="text-[10px] font-mono text-foreground truncate">{cell.technique}</div>
                          <div className="text-[10px] tabular-nums text-muted-foreground">
                            {cell.totalIncidents} inc
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </Panel>
  );
}
