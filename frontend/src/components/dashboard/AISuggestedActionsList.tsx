'use client';

import { useState } from 'react';
import { ChevronDown } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Panel } from '@/components/aegis/Panel';
import { SectionHeader } from '@/components/aegis/SectionHeader';
import { EmptyState } from '@/components/aegis/EmptyState';

export interface SuggestedAction {
  id: string;
  title: string;
  created_at: string;
  status: string;
  target?: string;
}

export interface AISuggestedActionsListProps {
  actions: SuggestedAction[];
  onApprove: (id: string) => Promise<void>;
  onReject: (id: string) => Promise<void>;
  loading?: boolean;
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleDateString('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  });
}

export default function AISuggestedActionsList({
  actions,
  onApprove,
  onReject,
  loading = false,
}: AISuggestedActionsListProps) {
  const [pendingIds, setPendingIds] = useState<Record<string, boolean>>({});

  async function handleApprove(id: string) {
    setPendingIds((prev) => ({ ...prev, [id]: true }));
    try {
      await onApprove(id);
    } finally {
      setPendingIds((prev) => ({ ...prev, [id]: false }));
    }
  }

  async function handleReject(id: string) {
    setPendingIds((prev) => ({ ...prev, [id]: true }));
    try {
      await onReject(id);
    } finally {
      setPendingIds((prev) => ({ ...prev, [id]: false }));
    }
  }

  const weekDropdown = (
    <button
      type="button"
      aria-label="Filter by week (coming soon)"
      className={cn(
        'flex items-center gap-1 px-2.5 py-1 rounded-md',
        'border border-border/60 text-[11px] text-muted-foreground/60',
        'hover:bg-white/[0.03] transition-colors',
        'focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-white/20',
      )}
    >
      Week
      <ChevronDown size={11} aria-hidden />
    </button>
  );

  return (
    <Panel className="h-full flex flex-col">
      <SectionHeader title="AI Suggested Actions" action={weekDropdown} />

      <div className="flex-1 overflow-y-auto">
        {actions.length === 0 ? (
          <EmptyState size="md" title="No pending actions" />
        ) : (
          <ul role="list">
            {actions.map((action, idx) => {
              const isPending = !!pendingIds[action.id];
              const isLast = idx === actions.length - 1;

              return (
                <li
                  key={action.id}
                  className={cn(
                    'flex items-center justify-between gap-3 px-4 sm:px-5 py-3 min-h-[52px]',
                    'transition-opacity duration-200',
                    !isLast && 'border-b border-border/40',
                    isPending && 'opacity-50',
                  )}
                >
                  <div className="flex-1 min-w-0">
                    <p className="text-[13px] text-foreground leading-snug truncate">
                      {action.title}
                    </p>
                    <p className="text-[11px] text-muted-foreground/60 mt-0.5">
                      {formatDate(action.created_at)}
                    </p>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => handleReject(action.id)}
                      disabled={isPending || loading}
                      aria-label={`Reject: ${action.title}`}
                      className={cn(
                        'px-3 py-1.5 rounded-lg text-[11px] uppercase tracking-wider',
                        'border border-red-500/40 text-red-400',
                        'hover:bg-red-500/10 transition-colors',
                        'focus-visible:outline-none focus-visible:ring-2',
                        'focus-visible:ring-red-500/30 focus-visible:ring-offset-1',
                        'focus-visible:ring-offset-card',
                        'disabled:cursor-not-allowed',
                      )}
                    >
                      Reject
                    </button>

                    <button
                      type="button"
                      onClick={() => handleApprove(action.id)}
                      disabled={isPending || loading}
                      aria-label={`Approve: ${action.title}`}
                      className={cn(
                        'px-3 py-1.5 rounded-lg text-[11px] uppercase tracking-wider',
                        'border border-emerald-500/40 text-emerald-400',
                        'hover:bg-emerald-500/10 transition-colors',
                        'focus-visible:outline-none focus-visible:ring-2',
                        'focus-visible:ring-emerald-500/30 focus-visible:ring-offset-1',
                        'focus-visible:ring-offset-card',
                        'disabled:cursor-not-allowed',
                      )}
                    >
                      Approve
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </Panel>
  );
}
