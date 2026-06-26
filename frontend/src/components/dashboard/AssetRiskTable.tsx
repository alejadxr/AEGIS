'use client';

import { Panel, SectionHeader, EmptyState, StatusBadge } from '@/components/aegis';

export interface AssetRiskRow {
  asset: string;
  account: string;
  totalThreats: number;
  resolved: number;     // for solving progress
  riskScore: number;    // 0-10
}

interface AssetRiskTableProps {
  rows: AssetRiskRow[];
}

function riskTone(score: number): { variant: 'danger' | 'accent' | 'warning' | 'success'; color: string; label: string } {
  if (score >= 7) return { variant: 'danger', color: 'var(--danger)', label: 'critical' };
  if (score >= 5) return { variant: 'accent', color: 'var(--brand-accent)', label: 'high' };
  if (score >= 3) return { variant: 'warning', color: 'var(--warning)', label: 'medium' };
  return { variant: 'success', color: 'var(--success)', label: 'low' };
}

/**
 * AssetRiskTable — image-2 style risk-per-app summary.
 * Refactored: uses <Panel> + <SectionHeader> + <StatusBadge> + <EmptyState>.
 */
export function AssetRiskTable({ rows }: AssetRiskTableProps) {
  return (
    <Panel>
      <SectionHeader title="View Results By Asset" count={`${rows.length} apps`} />

      <div className="overflow-x-auto">
        <table className="w-full text-[12px]">
          <thead>
            <tr className="text-[10px] font-medium uppercase tracking-[0.14em] text-muted-foreground/70">
              <th scope="col" className="text-left px-4 sm:px-5 py-2.5 font-medium">Asset</th>
              <th scope="col" className="text-right px-4 py-2.5 font-medium">Total Threats</th>
              <th scope="col" className="text-left px-4 py-2.5 font-medium">Account</th>
              <th scope="col" className="text-left px-4 py-2.5 font-medium w-[28%]">Solving Progress</th>
              <th scope="col" className="text-right px-4 sm:px-5 py-2.5 font-medium">Risk Score</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={5} className="px-5 py-8">
                  <EmptyState size="sm" title="No assets being monitored yet" />
                </td>
              </tr>
            )}
            {rows.map((r) => {
              const tone = riskTone(r.riskScore);
              const progress = r.totalThreats > 0
                ? Math.round((r.resolved / r.totalThreats) * 100)
                : 100;
              return (
                <tr
                  key={r.asset}
                  className="border-t border-border hover:bg-white/[0.02] transition-colors"
                >
                  <td className="px-4 sm:px-5 py-3">
                    <div className="flex items-center gap-2.5">
                      <div className="w-6 h-6 rounded-full bg-[var(--brand-accent)]/12 border border-[var(--brand-accent)]/30 flex items-center justify-center text-[10px] font-semibold uppercase text-[var(--brand-accent)]">
                        {r.asset.charAt(0)}
                      </div>
                      <span className="font-mono text-foreground/90">{r.asset}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums text-foreground/80">
                    {r.totalThreats}
                  </td>
                  <td className="px-4 py-3 text-muted-foreground/80">
                    {r.account}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1.5 rounded-full bg-muted/60 overflow-hidden">
                        <div
                          className="h-full rounded-full transition-[width] duration-500"
                          style={{ width: `${progress}%`, background: tone.color }}
                          aria-hidden
                        />
                      </div>
                      <span className="text-[10px] font-mono tabular-nums text-muted-foreground/70 w-9 text-right">
                        {progress}%
                      </span>
                    </div>
                  </td>
                  <td className="px-4 sm:px-5 py-3 text-right">
                    <div className="inline-flex">
                      <StatusBadge
                        variant={tone.variant}
                        size="sm"
                        aria-label={`Risk score ${r.riskScore.toFixed(1)}, ${tone.label}`}
                      >
                        <span className="tabular-nums">{r.riskScore.toFixed(1)}</span>
                      </StatusBadge>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}
