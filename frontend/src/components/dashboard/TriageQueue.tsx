'use client';

import { useCallback, useRef, useState } from 'react';
import type { CSSProperties, KeyboardEvent, MouseEvent } from 'react';
import { Panel, SectionHeader, EmptyState, StatusBadge } from '@/components/aegis';
import type { StatusVariant } from '@/components/aegis';
import { IncidentDossier } from '@/components/dashboard/IncidentDossier';
import { api } from '@/lib/api';
import { cn, formatRelativeTime } from '@/lib/utils';

/**
 * TriageQueue — the hero.
 *
 * An urgency-ranked, keyboard-operable accordion of incident cards with a
 * pinned pending-approval region at the top. Absorbs FeaturedIncidentHero,
 * IncidentTimeline and AISuggestedActionsList into one honest to-do list.
 *
 * This component never fetches its own list data — `incidents` and
 * `pendingActions` arrive pre-filtered from page.tsx (FP-stripped incidents,
 * pending-only actions). It DOES mount <IncidentDossier> lazily per expanded
 * row, which fetches api.response.incident(id) itself.
 *
 * Nested-card ban (adversarial review item 17): collapsed incident rows
 * carry NO border and NO background of their own — separation comes from
 * the 3px severity spine, a 1px hairline between rows, and a background
 * tint on hover/open. <Panel> is the only bordered surface on this page.
 */

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface TriageIncident {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: string;
  source: string | null;
  source_ip: string | null;
  mitre_technique: string | null;
  mitre_tactic: string | null;
  detected_at: string;
}

export interface TriagePendingAction {
  id: string;
  incident_id: string;
  action_type: string;
  target: string | null;
  status: string;
  created_at: string;
}

export interface TriageQueueProps {
  /** ALREADY FP-filtered by page.tsx. This component must not receive [FP-] titles. */
  incidents: TriageIncident[];
  /** Already filtered to status === 'pending'. */
  pendingActions: TriagePendingAction[];
  /** Real endpoints, passed from page.tsx. Must refetch on success. */
  onApprove: (actionId: string) => Promise<void>;
  onReject: (actionId: string, reason?: string) => Promise<void>;
  loading?: boolean;
  /** True when response.incidents() rejected. */
  error?: boolean;
  /**
   * From api.dashboard.overview().total_assets — mirrors VerdictLineProps'
   * field 1:1. Optional and additive: not part of the minimum contract, but
   * needed to write the empty state's evidence line honestly instead of
   * fabricating a number. Falls back to asset-count-free copy when omitted.
   */
  totalAssets?: number;
  /** From api.dashboard.monitoredApps().count — mirrors VerdictLineProps' field 1:1. */
  monitoredApps?: number;
  /**
   * Optional: re-run whatever fetch populates `incidents` / `pendingActions`.
   * Not part of the minimum contract — additive and optional so existing
   * callers keep compiling. Wired to both the error state's Retry button and
   * as the `onMutated` signal forwarded to each <IncidentDossier> (so a
   * dossier-level approve/reject also refreshes the outer counts). Falls
   * back to a full page reload — a real, working retry, never a decorative
   * no-op button — when omitted.
   */
  onRetry?: () => void;
}

// ---------------------------------------------------------------------------
// Severity — explicit map, never template-literal interpolation. Matches
// the SEV_VAR convention already established in Ledger.tsx / OriginMap.tsx,
// with defensive `var(x, fallback)` chains (CommandBar.tsx's convention) so
// the queue still renders correctly before the --sev-* tokens land in
// globals.css.
// ---------------------------------------------------------------------------

type SeverityKey = 'critical' | 'high' | 'medium' | 'low' | 'info';

const SEV_VAR: Record<SeverityKey, string> = {
  critical: 'var(--sev-critical, var(--danger))',
  high: 'var(--sev-high, var(--brand-accent))',
  medium: 'var(--sev-medium, var(--warning))',
  low: 'var(--sev-low, var(--brand))',
  info: 'var(--sev-info, var(--muted-foreground))',
};

const SEVERITY_RANK: Record<SeverityKey, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function severityKey(severity: string | null | undefined): SeverityKey {
  const s = (severity ?? '').toLowerCase();
  if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low' || s === 'info') return s;
  return 'info';
}

type ActionUiState = { status: 'applying' | 'error'; message?: string };

// ---------------------------------------------------------------------------
// Pinned "awaiting your approval" region
// ---------------------------------------------------------------------------

function PendingActionsBlock({
  actions,
  actionState,
  onApprove,
  onReject,
}: {
  actions: TriagePendingAction[];
  actionState: Record<string, ActionUiState>;
  onApprove: (id: string) => void;
  onReject: (id: string) => void;
}) {
  return (
    <div
      className={cn(
        'mb-1 rounded-[10px] px-4 py-3.5',
        'bg-[color-mix(in_oklab,var(--brand)_7%,transparent)]',
        'border border-[color-mix(in_oklab,var(--brand)_22%,transparent)]',
      )}
    >
      <div className="flex items-center justify-between gap-3">
        <span className="text-[10px] font-semibold uppercase tracking-[0.1em] text-[var(--brand-text,var(--brand))]">
          Awaiting your approval
        </span>
        <span className="font-mono text-[11px] text-muted-foreground">{actions.length}</span>
      </div>

      <div className="mt-1 flex flex-col">
        {actions.map((a, i) => {
          const state = actionState[a.id];
          const isBusy = state?.status === 'applying';
          return (
            <div
              key={a.id}
              className={cn(
                'flex items-center justify-between gap-3 min-h-[40px] py-2',
                i > 0 && 'border-t border-border',
              )}
            >
              <div className="min-w-0">
                <p className="text-[12px] font-semibold text-foreground truncate">
                  {a.action_type}
                  <span className="font-mono text-[11px] font-normal text-muted-foreground">
                    {' → '}
                    {a.target ?? '—'}
                  </span>
                </p>
                <p className="mt-0.5 font-mono text-[10px] text-muted-foreground/70">
                  {isBusy ? 'Applying…' : formatRelativeTime(a.created_at)}
                </p>
                {state?.status === 'error' && state.message && (
                  <p role="alert" className="mt-0.5 text-[11px] text-[var(--danger)]">
                    {state.message}
                  </p>
                )}
              </div>

              <div className="shrink-0 flex items-center gap-2">
                <button
                  type="button"
                  disabled={isBusy}
                  onClick={() => onApprove(a.id)}
                  aria-label={`Approve ${a.action_type} on ${a.target ?? 'target'}`}
                  className={cn(
                    'h-7 px-3 rounded-[8px] text-[11px] font-semibold',
                    'bg-[color-mix(in_oklab,var(--brand)_16%,transparent)]',
                    'border border-[color-mix(in_oklab,var(--brand)_34%,transparent)]',
                    'text-[var(--brand-text,var(--brand))]',
                    'hover:bg-[color-mix(in_oklab,var(--brand)_24%,transparent)]',
                    'transition-colors duration-150 motion-reduce:transition-none',
                    'disabled:opacity-50 disabled:cursor-not-allowed',
                  )}
                >
                  Approve
                </button>
                <button
                  type="button"
                  disabled={isBusy}
                  onClick={() => onReject(a.id)}
                  aria-label={`Reject ${a.action_type} on ${a.target ?? 'target'}`}
                  className={cn(
                    'h-7 px-3 rounded-[8px] text-[11px] font-semibold bg-transparent',
                    'border border-[color-mix(in_oklab,var(--danger)_30%,transparent)]',
                    'text-[var(--danger)]',
                    'hover:bg-[color-mix(in_oklab,var(--danger)_10%,transparent)]',
                    'transition-colors duration-150 motion-reduce:transition-none',
                    'disabled:opacity-50 disabled:cursor-not-allowed',
                  )}
                >
                  Reject
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Incident card (collapsed row + accordion body)
// ---------------------------------------------------------------------------

function IncidentCard({
  incident,
  isFirst,
  isOpen,
  isPendingApproval,
  onToggle,
  onApprove,
  onReject,
  onMutated,
}: {
  incident: TriageIncident;
  isFirst: boolean;
  isOpen: boolean;
  isPendingApproval: boolean;
  onToggle: () => void;
  onApprove: (actionId: string) => Promise<void>;
  onReject: (actionId: string, reason?: string) => Promise<void>;
  onMutated: () => void;
}) {
  const sevKey = severityKey(incident.severity);
  const sevVar = SEV_VAR[sevKey];
  const dossierId = `dossier-${incident.id}`;
  const dossierBodyRef = useRef<HTMLDivElement | null>(null);

  const chip: { variant: StatusVariant; label: string } = isPendingApproval
    ? { variant: 'info', label: 'AWAITING YOU' }
    : incident.status.toLowerCase() === 'investigating'
      ? { variant: 'warning', label: 'INVESTIGATING' }
      : { variant: 'muted', label: incident.status.toUpperCase() || 'UNKNOWN' };

  const metaSegments = [
    incident.mitre_technique ?? '—',
    incident.mitre_tactic ? incident.mitre_tactic.toUpperCase() : null,
    incident.source_ip ?? 'no source ip',
    formatRelativeTime(incident.detected_at),
  ].filter((s): s is string => s !== null);

  const handleKeyDown = (e: KeyboardEvent<HTMLElement>) => {
    // Ignore keydowns bubbling up from interactive descendants (dossier
    // buttons, "show more" links) so Enter/Space on THOSE doesn't also
    // toggle this row — matches Ledger.tsx's handleRowKeyDown guard.
    if (e.target !== e.currentTarget) return;
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onToggle();
    }
  };

  const handleClick = (e: MouseEvent<HTMLElement>) => {
    // A click inside the expanded dossier (buttons, "show more" links)
    // must not also toggle this row closed. Checked via ref-containment
    // rather than stopPropagation on an intermediate <div>, which would
    // require attaching a click handler to a non-interactive element
    // (jsx-a11y/no-static-element-interactions).
    if (dossierBodyRef.current && dossierBodyRef.current.contains(e.target as Node)) return;
    onToggle();
  };

  return (
    <article
      role="button"
      tabIndex={0}
      aria-expanded={isOpen}
      aria-controls={dossierId}
      aria-label={incident.title}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      className={cn(
        'relative min-h-[92px] pl-[23px] pr-5 py-5 rounded-[14px] cursor-pointer',
        !isFirst && 'border-t border-border',
        'transition-[background-color] duration-150 ease-[cubic-bezier(0.22,1,0.36,1)] motion-reduce:transition-none',
        'hover:bg-[color-mix(in_oklab,var(--foreground)_2.5%,transparent)]',
        isOpen && 'bg-[color-mix(in_oklab,var(--foreground)_2.5%,transparent)]',
      )}
    >
      <span
        aria-hidden="true"
        className="absolute left-0 top-0 bottom-0 w-[3px] rounded-l-[14px]"
        style={{ background: sevVar }}
      />

      <div className="flex items-center justify-between gap-3">
        <h3 className="min-w-0 truncate text-[16px] font-semibold tracking-[-0.32px] text-foreground">
          {incident.title}
        </h3>
        <StatusBadge size="sm" variant={chip.variant} className="shrink-0">
          {chip.label}
        </StatusBadge>
      </div>

      <p className="mt-2 truncate font-mono text-[11px] text-muted-foreground">
        <span className="font-semibold" style={{ color: sevVar }}>
          {sevKey.toUpperCase()}
        </span>
        {' · '}
        {metaSegments.join(' · ')}
      </p>

      <div
        aria-hidden={!isOpen}
        className={cn(
          'grid transition-[grid-template-rows,opacity] duration-[180ms] ease-[cubic-bezier(0.22,1,0.36,1)] motion-reduce:transition-none',
          isOpen ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0',
        )}
      >
        {/* No id here: <IncidentDossier> renders its own id={`dossier-${incidentId}`}
            on its root once mounted below — duplicating it on this wrapper would
            create two elements sharing one id. aria-controls above already targets
            that inner id directly. */}
        <div className="overflow-hidden min-h-0">
          <div ref={dossierBodyRef} className="mt-[18px] border-t border-border pt-[18px]">
            {isOpen && (
              <IncidentDossier
                incidentId={incident.id}
                title={incident.title}
                severity={sevKey}
                onApprove={onApprove}
                onReject={onReject}
                onMutated={onMutated}
              />
            )}
          </div>
        </div>
      </div>
    </article>
  );
}

// ---------------------------------------------------------------------------
// Empty state — the PRIMARY state of this dashboard. ~320px of budget, not
// a shrug. Per adversarial-review item 14, the headline never claims a
// "most recent resolved incident" age the incident schema cannot supply
// (no resolved_at / updated_at field exists) — it states only what is
// knowable.
// ---------------------------------------------------------------------------

const WHAT_WOULD_APPEAR = [
  'log_watcher · 122 sigma rules · 5 chain rules',
  'honeypots · ssh:2222 · http:8888',
  'surface scans · nmap + nuclei',
];

function TriageEmptyBlock({
  totalAssets,
  monitoredApps,
}: {
  totalAssets?: number;
  monitoredApps?: number;
}) {
  const [scan, setScan] = useState<{ status: 'idle' | 'running' | 'done' | 'error'; message?: string }>({
    status: 'idle',
  });

  const handleScan = useCallback(async () => {
    setScan({ status: 'running' });
    try {
      // No asset/target selector exists on this component (single-button
      // spec) and api.surface.scan(target, scanType) requires a caller-
      // supplied target — there is no "scan everything" backend mode. The
      // browser's own hostname is a real, non-fabricated value: on a
      // self-hosted AEGIS deployment the dashboard is served from the same
      // box being protected, so it is a defensible one-click default. This
      // is a resolution of a spec/API contract gap — see the written report.
      const target = typeof window !== 'undefined' ? window.location.hostname : '';
      if (!target) throw new Error('No scan target available in this environment.');
      await api.surface.scan(target, 'discovery');
      setScan({ status: 'done', message: `Discovery scan started for ${target}.` });
    } catch (err) {
      setScan({ status: 'error', message: err instanceof Error ? err.message : 'Could not start scan.' });
    }
  }, []);

  const evidenceLine =
    totalAssets != null && monitoredApps != null
      ? `AEGIS is watching ${totalAssets} asset${totalAssets === 1 ? '' : 's'} across ${monitoredApps} application${monitoredApps === 1 ? '' : 's'}. Detection, correlation and response are running; there is simply nothing to decide.`
      : 'AEGIS is watching your registered assets. Detection, correlation and response are running; there is simply nothing to decide.';

  return (
    <div className="flex flex-col gap-6 px-6 py-10">
      <div>
        <p className="text-[16px] font-semibold text-foreground">Nothing has needed you.</p>
        <p className="mt-1.5 max-w-[52ch] text-[13px] leading-[20px] tracking-[-0.08px] text-muted-foreground">
          {evidenceLine}
        </p>
      </div>

      <div>
        <p className="text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground">
          What would appear here
        </p>
        <ul className="mt-2 flex flex-col gap-1.5">
          {WHAT_WOULD_APPEAR.map((line) => (
            <li key={line} className="flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
              <span
                aria-hidden="true"
                className="h-1 w-1 shrink-0"
                style={{ background: 'var(--sev-info, var(--muted-foreground))' }}
              />
              {line}
            </li>
          ))}
        </ul>
      </div>

      <div>
        <button
          type="button"
          onClick={handleScan}
          disabled={scan.status === 'running'}
          className={cn(
            'h-[34px] px-4 rounded-[8px] text-[12px] font-semibold',
            'bg-[color-mix(in_oklab,var(--brand)_16%,transparent)]',
            'border border-[color-mix(in_oklab,var(--brand)_34%,transparent)]',
            'text-[var(--brand-text,var(--brand))]',
            'hover:bg-[color-mix(in_oklab,var(--brand)_24%,transparent)]',
            'transition-colors duration-150 motion-reduce:transition-none',
            'disabled:opacity-50 disabled:cursor-not-allowed',
          )}
        >
          {scan.status === 'running' ? 'Starting scan…' : 'Run a Surface scan'}
        </button>
        {scan.status === 'done' && (
          <p className="mt-2 font-mono text-[11px] text-muted-foreground">{scan.message}</p>
        )}
        {scan.status === 'error' && (
          <p role="alert" className="mt-2 text-[11px] text-[var(--danger)]">
            {scan.message}
          </p>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------------

export function TriageQueue({
  incidents,
  pendingActions,
  onApprove,
  onReject,
  loading = false,
  error = false,
  totalAssets,
  monitoredApps,
  onRetry,
}: TriageQueueProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [actionState, setActionState] = useState<Record<string, ActionUiState>>({});

  const handleToggle = useCallback((id: string) => {
    setExpandedId((cur) => (cur === id ? null : id));
  }, []);

  const runApprove = useCallback(
    async (id: string) => {
      setActionState((s) => ({ ...s, [id]: { status: 'applying' } }));
      try {
        await onApprove(id);
        setActionState((s) => {
          const next = { ...s };
          delete next[id];
          return next;
        });
      } catch (err) {
        setActionState((s) => ({
          ...s,
          [id]: { status: 'error', message: err instanceof Error ? err.message : 'Could not approve this action.' },
        }));
      }
    },
    [onApprove],
  );

  const runReject = useCallback(
    async (id: string) => {
      setActionState((s) => ({ ...s, [id]: { status: 'applying' } }));
      try {
        await onReject(id);
        setActionState((s) => {
          const next = { ...s };
          delete next[id];
          return next;
        });
      } catch (err) {
        setActionState((s) => ({
          ...s,
          [id]: { status: 'error', message: err instanceof Error ? err.message : 'Could not reject this action.' },
        }));
      }
    },
    [onReject],
  );

  const handleRetry = useCallback(() => {
    if (onRetry) onRetry();
    else if (typeof window !== 'undefined') window.location.reload();
  }, [onRetry]);

  // onMutated forwarded to each <IncidentDossier>: a dossier-level
  // approve/reject already refreshes ITS OWN detail internally, but the
  // outer incidents/pendingActions arrays (owned by page.tsx) also need a
  // refresh so this list's counts and the pinned region stay correct. No
  // page reload here — that fallback is reserved for the rarer hard-error
  // Retry path above.
  const handleMutated = useCallback(() => {
    onRetry?.();
  }, [onRetry]);

  const sortedIncidents = [...incidents].sort((a, b) => {
    const rankDiff = SEVERITY_RANK[severityKey(a.severity)] - SEVERITY_RANK[severityKey(b.severity)];
    if (rankDiff !== 0) return rankDiff;
    return new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime();
  });

  const pendingIncidentIds = new Set(pendingActions.map((a) => a.incident_id));
  const isEmpty = !loading && !error && incidents.length === 0 && pendingActions.length === 0;
  const isScrollable = sortedIncidents.length > 8;
  const maskStyle: CSSProperties | undefined = isScrollable
    ? {
        WebkitMaskImage: 'linear-gradient(to bottom, black calc(100% - 8px), transparent 100%)',
        maskImage: 'linear-gradient(to bottom, black calc(100% - 8px), transparent 100%)',
      }
    : undefined;

  return (
    <Panel
      variant="default"
      padding="none"
      border="default"
      as="section"
      aria-label="Triage queue"
      aria-busy={loading}
      className="col-span-12 lg:col-span-8"
    >
      {loading && (
        <span className="sr-only" role="status">
          Loading triage queue.
        </span>
      )}

      <SectionHeader
        flush
        title="TRIAGE QUEUE"
        count={!loading && !error ? `${incidents.length} open` : undefined}
        action={
          <span className="hidden sm:inline-flex font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground/70">
            Ordered by severity · age
          </span>
        }
      />

      <div className="p-4 flex flex-col gap-3">
        {error ? (
          <EmptyState
            size="md"
            title="Could not load incidents"
            description="The response API did not answer. Detection is unaffected — this is a display failure."
            action={
              <button
                type="button"
                onClick={handleRetry}
                className="rounded-sm text-[12px] font-semibold text-[var(--brand-text,var(--brand))] hover:underline"
              >
                Retry
              </button>
            }
          />
        ) : loading ? (
          <div aria-hidden="true" className="flex flex-col gap-3">
            {[0, 1, 2].map((i) => (
              <div key={i} className="min-h-[92px] rounded-[14px] bg-muted opacity-30" />
            ))}
          </div>
        ) : isEmpty ? (
          <TriageEmptyBlock totalAssets={totalAssets} monitoredApps={monitoredApps} />
        ) : (
          <>
            {pendingActions.length > 0 && (
              <PendingActionsBlock
                actions={pendingActions}
                actionState={actionState}
                onApprove={runApprove}
                onReject={runReject}
              />
            )}

            <div
              className={cn(isScrollable && 'max-h-[720px] overflow-y-auto pr-1')}
              style={maskStyle}
            >
              {sortedIncidents.map((incident, i) => (
                <IncidentCard
                  key={incident.id}
                  incident={incident}
                  isFirst={i === 0}
                  isOpen={expandedId === incident.id}
                  isPendingApproval={pendingIncidentIds.has(incident.id)}
                  onToggle={() => handleToggle(incident.id)}
                  onApprove={onApprove}
                  onReject={onReject}
                  onMutated={handleMutated}
                />
              ))}
            </div>
          </>
        )}
      </div>
    </Panel>
  );
}

export default TriageQueue;
