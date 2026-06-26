'use client';

import { useState } from 'react';
import { Shield, AlertCircle, Lock, Flame } from 'lucide-react';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';
import { Panel, SectionHeader, DataRow, EmptyState } from '@/components/aegis';

interface PendingAction {
  id: string;
  incident_id: string;
  action_type: string;
  target: string;
  status: string;
  ai_reasoning: string | null;
  created_at: string;
}

interface AISuggestedActionsProps {
  actions: PendingAction[];
  onChanged?: () => void;
}

function iconFor(type: string) {
  const t = type.toLowerCase();
  if (t.includes('block')) return Shield;
  if (t.includes('quarantine') || t.includes('isolate')) return Lock;
  if (t.includes('reset') || t.includes('credential')) return Flame;
  return AlertCircle;
}

function timeAgo(iso: string): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '';
  const diff = (Date.now() - t) / 1000;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function describe(action: PendingAction): string {
  const verb = action.action_type
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
  return `${verb} · ${action.target}`;
}

export function AISuggestedActions({ actions, onChanged }: AISuggestedActionsProps) {
  const [busy, setBusy] = useState<Record<string, 'approve' | 'reject' | null>>({});
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const [toast, setToast] = useState<string | null>(null);

  const visible = actions.filter((a) => !dismissed.has(a.id));

  async function approve(id: string) {
    setBusy((b) => ({ ...b, [id]: 'approve' }));
    try {
      await api.response.approveAction(id);
      setDismissed((d) => new Set(d).add(id));
      setToast('Action approved · executing');
      onChanged?.();
    } catch (err) {
      setToast(`Approval failed: ${(err as Error).message}`);
    } finally {
      setBusy((b) => ({ ...b, [id]: null }));
      setTimeout(() => setToast(null), 3000);
    }
  }

  function reject(id: string) {
    setDismissed((d) => new Set(d).add(id));
    setToast('Action dismissed locally · pending backend reject endpoint');
    setTimeout(() => setToast(null), 3000);
    onChanged?.();
  }

  return (
    <Panel className="h-full flex flex-col">
      <SectionHeader
        title="AI Suggested Actions"
        live
        count={`${visible.length} pending`}
      />

      <div className="flex-1 overflow-y-auto">
        {visible.length === 0 && (
          <EmptyState
            size="md"
            title="No pending approvals"
            description="AEGIS is on auto-pilot"
          />
        )}

        {visible.map((a, idx) => {
          const Icon = iconFor(a.action_type);
          const state = busy[a.id];
          return (
            <DataRow
              key={a.id}
              borderless={idx === 0}
              density="compact"
              leading={
                <div className="w-8 h-8 shrink-0 rounded-md bg-[var(--brand-accent)]/10 border border-[var(--brand-accent)]/20 flex items-center justify-center text-[var(--brand-accent)]">
                  <Icon size={15} />
                </div>
              }
              trailing={
                <>
                  <button
                    type="button"
                    onClick={() => reject(a.id)}
                    disabled={!!state}
                    aria-label={`Reject ${describe(a)}`}
                    className={cn(
                      'px-3 py-1.5 rounded-md text-[11px] font-medium uppercase tracking-wider',
                      'border border-white/[0.08] text-muted-foreground',
                      'hover:bg-white/[0.04] hover:text-foreground',
                      'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/30',
                      'disabled:opacity-40 disabled:cursor-not-allowed transition-colors',
                    )}
                  >
                    Reject
                  </button>
                  <button
                    type="button"
                    onClick={() => approve(a.id)}
                    disabled={!!state}
                    aria-label={`Approve ${describe(a)}`}
                    className={cn(
                      'px-3 py-1.5 rounded-md text-[11px] font-semibold uppercase tracking-wider',
                      'bg-[var(--brand-accent)] text-black',
                      'hover:bg-[var(--brand-accent)]/90',
                      'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand-accent)]/60 focus-visible:ring-offset-2 focus-visible:ring-offset-card',
                      'disabled:opacity-50 disabled:cursor-not-allowed transition-colors',
                    )}
                  >
                    {state === 'approve' ? '...' : 'Approve'}
                  </button>
                </>
              }
            >
              <div className="flex-1 min-w-0">
                <p className="text-[13px] text-foreground truncate" title={a.ai_reasoning ?? undefined}>
                  {describe(a)}
                </p>
                <p className="text-[10.5px] text-muted-foreground/60 font-mono mt-0.5">
                  {timeAgo(a.created_at)}
                </p>
              </div>
            </DataRow>
          );
        })}
      </div>

      {toast && (
        <div
          role="status"
          aria-live="polite"
          className="px-4 py-2 border-t border-border bg-background/40 text-[11px] text-muted-foreground"
        >
          {toast}
        </div>
      )}
    </Panel>
  );
}
