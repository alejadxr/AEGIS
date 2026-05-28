'use client';

import * as React from 'react';
import { Panel } from '@/components/aegis';
import { RefreshCw, Download } from 'lucide-react';
import { MITRE_TACTICS } from './mitreTactics';

export interface FilterState {
  windowHours: number;
  minIps: number;
  tactic: string; // tactic id, '' = all
  severity: string; // 'all' | 'critical' | 'high' | 'medium' | 'low'
}

export interface CampaignFiltersProps {
  value: FilterState;
  onChange: (next: FilterState) => void;
  onRefresh: () => void;
  onExportCsv: () => void;
  loading?: boolean;
}

const WINDOWS: { label: string; value: number }[] = [
  { label: '24h', value: 24 },
  { label: '7d', value: 168 },
  { label: '30d', value: 720 },
  { label: 'All', value: 24 * 30 }, // capped server-side; "All" approximates 30d
];

const MIN_IPS: { label: string; value: number }[] = [
  { label: '≥ 2', value: 2 },
  { label: '≥ 3', value: 3 },
  { label: '≥ 5', value: 5 },
];

export function CampaignFilters({ value, onChange, onRefresh, onExportCsv, loading }: CampaignFiltersProps) {
  return (
    <Panel padding="md" className="flex flex-wrap items-end gap-3">
      <FilterGroup label="Window">
        <SegmentedGroup
          ariaLabel="Window selector"
          options={WINDOWS.map((w) => ({ label: w.label, value: w.value }))}
          value={value.windowHours}
          onChange={(v) => onChange({ ...value, windowHours: Number(v) })}
        />
      </FilterGroup>

      <FilterGroup label="Min IPs">
        <SegmentedGroup
          ariaLabel="Minimum distinct IPs"
          options={MIN_IPS}
          value={value.minIps}
          onChange={(v) => onChange({ ...value, minIps: Number(v) })}
        />
      </FilterGroup>

      <FilterGroup label="Tactic">
        <select
          value={value.tactic}
          onChange={(e) => onChange({ ...value, tactic: e.target.value })}
          className="bg-card border border-border rounded-lg px-3 py-2 text-[12px] text-foreground min-h-[36px] focus:outline-none focus:ring-2 focus:ring-[var(--brand-accent)]/60"
          aria-label="Filter by MITRE tactic"
        >
          <option value="">All tactics</option>
          {MITRE_TACTICS.map((t) => (
            <option key={t.id} value={t.id}>
              {t.label}
            </option>
          ))}
        </select>
      </FilterGroup>

      <FilterGroup label="Severity">
        <select
          value={value.severity}
          onChange={(e) => onChange({ ...value, severity: e.target.value })}
          className="bg-card border border-border rounded-lg px-3 py-2 text-[12px] text-foreground min-h-[36px] focus:outline-none focus:ring-2 focus:ring-[var(--brand-accent)]/60"
          aria-label="Filter by severity"
        >
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </FilterGroup>

      <div className="ml-auto flex items-center gap-2">
        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-[12px] text-foreground hover:border-[var(--brand-accent)]/40 transition-colors disabled:opacity-60 min-h-[36px] focus:outline-none focus:ring-2 focus:ring-[var(--brand-accent)]/60"
          aria-label="Refresh campaigns"
        >
          <RefreshCw size={14} aria-hidden />
          <span>Refresh</span>
        </button>
        <button
          type="button"
          onClick={onExportCsv}
          className="inline-flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-[12px] text-foreground hover:border-[var(--brand-accent)]/40 transition-colors min-h-[36px] focus:outline-none focus:ring-2 focus:ring-[var(--brand-accent)]/60"
          aria-label="Export campaigns to CSV"
        >
          <Download size={14} aria-hidden />
          <span>Export CSV</span>
        </button>
      </div>
    </Panel>
  );
}

function FilterGroup({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-muted-foreground">{label}</span>
      {children}
    </div>
  );
}

function SegmentedGroup({
  options,
  value,
  onChange,
  ariaLabel,
}: {
  options: { label: string; value: number | string }[];
  value: number | string;
  onChange: (v: number | string) => void;
  ariaLabel: string;
}) {
  return (
    <div role="group" aria-label={ariaLabel} className="inline-flex rounded-lg border border-border bg-card overflow-hidden min-h-[36px]">
      {options.map((opt) => {
        const active = opt.value === value;
        return (
          <button
            key={String(opt.value)}
            type="button"
            onClick={() => onChange(opt.value)}
            aria-pressed={active}
            className={`px-3 py-2 text-[12px] tabular-nums transition-colors focus:outline-none focus:ring-2 focus:ring-[var(--brand-accent)]/60 ${
              active
                ? 'bg-[color-mix(in_oklab,var(--brand-accent)_18%,transparent)] text-foreground'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}
