'use client';

import { cn } from '@/lib/utils';

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

function riskTone(score: number): { color: string; label: string } {
  if (score >= 7) return { color: 'var(--danger)', label: 'critical' };
  if (score >= 5) return { color: 'var(--brand-accent)', label: 'high' };
  if (score >= 3) return { color: 'var(--warning)', label: 'medium' };
  return { color: 'var(--success)', label: 'low' };
}

/**
 * AssetRiskTable — image 2 style risk-per-app summary.
 * Columns: Asset · Total Threats · Account · Solving Progress · Risk Score.
 */
export function AssetRiskTable({ rows }: AssetRiskTableProps) {
  return (
    <div className="bg-card border border-border rounded-2xl overflow-hidden">
      <div className="flex items-center justify-between px-4 sm:px-5 py-3 border-b border-border">
        <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-muted-foreground">
          View Results By Asset
        </span>
        <span className="text-[10px] font-mono text-muted-foreground/50">
          {rows.length} apps
        </span>
      </div>

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
                <td colSpan={5} className="px-5 py-8 text-center text-muted-foreground/60 text-[12px]">
                  No assets being monitored yet.
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
                      <div className="w-7 h-7 rounded-md bg-muted/40 border border-border flex items-center justify-center text-[11px] font-mono uppercase text-muted-foreground">
                        {r.asset.slice(0, 2)}
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
                          style={{
                            width: `${progress}%`,
                            background: tone.color,
                          }}
                          aria-hidden
                        />
                      </div>
                      <span className="text-[10px] font-mono tabular-nums text-muted-foreground/70 w-9 text-right">
                        {progress}%
                      </span>
                    </div>
                  </td>
                  <td className="px-4 sm:px-5 py-3 text-right">
                    <div className="inline-flex items-center gap-1.5">
                      <span
                        className={cn('w-1.5 h-1.5 rounded-full')}
                        style={{ background: tone.color }}
                        aria-hidden
                      />
                      <span
                        className="font-semibold tabular-nums"
                        style={{ color: tone.color }}
                        aria-label={`Risk score ${r.riskScore.toFixed(1)}, ${tone.label}`}
                      >
                        {r.riskScore.toFixed(1)}
                      </span>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
