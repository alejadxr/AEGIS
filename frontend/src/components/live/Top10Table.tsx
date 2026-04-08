'use client';

import { cn } from '@/lib/utils';

export interface Top10Row {
  label: string;
  count: number;
  meta?: string;
}

interface Top10TableProps {
  title: string;
  rows: Top10Row[];
  accent?: string;
  monoLabel?: boolean;
  emptyText?: string;
}

export function Top10Table({
  title,
  rows,
  accent = '#22D3EE',
  monoLabel = false,
  emptyText = 'No data yet',
}: Top10TableProps) {
  const maxCount = rows.length > 0 ? Math.max(...rows.map((r) => r.count)) : 1;

  return (
    <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl overflow-hidden flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06] shrink-0">
        <span className="text-[13px] font-semibold text-white tracking-tight">{title}</span>
        <span className="text-[10px] text-zinc-600 font-mono uppercase tracking-widest">top 10</span>
      </div>

      <div className="flex-1 overflow-y-auto">
        {rows.length === 0 ? (
          <div className="h-full flex items-center justify-center py-8">
            <p className="text-zinc-600 text-[12px] font-mono">{emptyText}</p>
          </div>
        ) : (
          rows.slice(0, 10).map((row, i) => {
            const pct = (row.count / maxCount) * 100;
            return (
              <div
                key={`${row.label}-${i}`}
                className="relative px-4 py-2 border-b border-white/[0.03] hover:bg-white/[0.02] transition-colors"
              >
                <div
                  className="absolute inset-y-0 left-0 pointer-events-none"
                  style={{
                    width: `${pct}%`,
                    background: `linear-gradient(to right, ${accent}12, transparent)`,
                  }}
                />
                <div className="relative flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className="text-[10px] text-zinc-600 font-mono tabular-nums w-4 shrink-0">
                      {String(i + 1).padStart(2, '0')}
                    </span>
                    <div className="flex flex-col min-w-0">
                      <span
                        className={cn(
                          'text-[12px] text-zinc-200 truncate leading-tight',
                          monoLabel && 'font-mono tabular-nums'
                        )}
                      >
                        {row.label}
                      </span>
                      {row.meta && (
                        <span className="text-[10px] text-zinc-600 font-mono truncate leading-tight">
                          {row.meta}
                        </span>
                      )}
                    </div>
                  </div>
                  <span
                    className="text-[12px] font-mono tabular-nums shrink-0"
                    style={{ color: accent }}
                  >
                    {row.count.toLocaleString()}
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
