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
  accent?: string; // hex or CSS var (e.g. "var(--danger)")
  monoLabel?: boolean;
  emptyText?: string;
}

function isVar(v: string) {
  return v.trim().startsWith('var(');
}

/** Wrap an accent reference so we can build alpha variations in inline style. */
function tintBg(accent: string) {
  if (isVar(accent)) {
    return `color-mix(in oklab, ${accent} 22%, transparent)`;
  }
  return `${accent}25`;
}
function tintFade(accent: string) {
  if (isVar(accent)) {
    return `color-mix(in oklab, ${accent} 8%, transparent)`;
  }
  return `${accent}08`;
}

export function Top10Table({
  title,
  rows,
  accent = 'var(--brand)',
  monoLabel = false,
  emptyText = 'No data yet',
}: Top10TableProps) {
  const maxCount = rows.length > 0 ? Math.max(...rows.map((r) => r.count)) : 1;

  return (
    <div className="aegis-card overflow-hidden flex flex-col h-full">
      <div className="aegis-section-header shrink-0">
        <span className="text-[13px] font-semibold text-foreground tracking-tight">{title}</span>
        <span className="text-label-xs">top 10</span>
      </div>

      <div className="flex-1 overflow-y-auto">
        {rows.length === 0 ? (
          <div className="h-full flex items-center justify-center py-8">
            <p className="text-muted-foreground/60 text-[12px] font-mono">{emptyText}</p>
          </div>
        ) : (
          rows.slice(0, 10).map((row, i) => {
            const pct = (row.count / maxCount) * 100;
            return (
              <div
                key={`${row.label}-${i}`}
                className="relative px-4 py-2 border-b border-border/50 last:border-b-0 hover:bg-muted/40 transition-colors"
              >
                <div
                  className="absolute inset-y-0 left-0 pointer-events-none transition-[width] duration-300"
                  style={{
                    width: `${pct}%`,
                    background: `linear-gradient(to right, ${tintBg(accent)}, ${tintFade(accent)})`,
                  }}
                />
                <div className="relative flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className="text-[10px] text-muted-foreground/60 font-mono tabular-nums font-semibold w-4 shrink-0">
                      {String(i + 1).padStart(2, '0')}
                    </span>
                    <div className="flex flex-col min-w-0">
                      <span
                        className={cn(
                          'text-[12.5px] text-foreground font-medium truncate leading-tight',
                          monoLabel && 'font-mono tabular-nums'
                        )}
                      >
                        {row.label}
                      </span>
                      {row.meta && (
                        <span className="text-[10px] text-muted-foreground/70 font-mono truncate leading-tight mt-0.5">
                          {row.meta}
                        </span>
                      )}
                    </div>
                  </div>
                  <span
                    className="text-[12.5px] font-mono tabular-nums font-semibold shrink-0"
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
