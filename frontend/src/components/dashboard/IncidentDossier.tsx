'use client';

import { useEffect, useRef, useState } from 'react';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';
import { DataRow, ProvenanceBadge, StatusBadge } from '@/components/aegis';
import type { StatusVariant } from '@/components/aegis';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DossierAction {
  id: string;
  action_type: string;
  target: string | null;
  status: string;
  ai_reasoning: string | null;
  requires_approval: boolean;
  created_at: string;
}

export interface IncidentDossierProps {
  /** Incident id; the component fetches its own detail on mount. */
  incidentId: string;
  /** Already known from the list — rendered immediately so the panel is never blank. */
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  onApprove: (actionId: string) => Promise<void>;
  onReject: (actionId: string, reason?: string) => Promise<void>;
  /** Called after a successful mutation so the parent can refetch. */
  onMutated: () => void;
}

/** Mirrors api.response.incident()'s resolved shape exactly — no field drift. */
type IncidentDetail = Awaited<ReturnType<typeof api.response.incident>>;

type LoadState = 'loading' | 'ready' | 'error';
type BusyKind = 'approve' | 'reject';

// ---------------------------------------------------------------------------
// Formatting helpers — never JSON.stringify AI output into the UI
// ---------------------------------------------------------------------------

function humanizeKey(key: string): string {
  const spaced = key.replace(/[_-]+/g, ' ').trim();
  return spaced.length > 0 ? spaced.toUpperCase() : key.toUpperCase();
}

function formatValue(value: unknown, depth = 0): string {
  if (value === null || value === undefined) return '—';
  if (typeof value === 'string') return value.trim().length > 0 ? value : '—';
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) {
    if (value.length === 0) return '—';
    return value.map((v) => formatValue(v, depth + 1)).join(', ');
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return '—';
    return entries.map(([k, v]) => `${humanizeKey(k)}: ${formatValue(v, depth + 1)}`).join(depth === 0 ? ' · ' : '; ');
  }
  return String(value);
}

function actionDotColor(status: string): string {
  switch (status.toLowerCase()) {
    case 'executed':
      return 'var(--success)';
    case 'pending':
      return 'var(--brand)';
    case 'failed':
      return 'var(--sev-critical)';
    default:
      return 'var(--muted-foreground)';
  }
}

function actionBadgeVariant(status: string): StatusVariant {
  switch (status.toLowerCase()) {
    case 'executed':
      return 'success';
    case 'pending':
      return 'info';
    case 'failed':
      return 'danger';
    default:
      return 'muted';
  }
}

// ---------------------------------------------------------------------------
// Loading skeleton — the ONLY thing rendered while the detail fetch is in
// flight. Title + severity spine already live in the parent row, so this is
// never a blank panel.
// ---------------------------------------------------------------------------

function DossierSkeleton() {
  const widths = ['82%', '64%', '40%'];
  return (
    <div className="flex flex-col gap-[10px]" role="status" aria-label="Loading incident detail">
      {widths.map((w) => (
        <div
          key={w}
          className="h-[14px] rounded-[4px]"
          style={{ width: w, background: 'color-mix(in oklab, var(--muted) 30%, transparent)' }}
        />
      ))}
      <span className="sr-only">Loading incident detail…</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Block 1 — Description
// ---------------------------------------------------------------------------

function DescriptionBlock({ description }: { description: string | null | undefined }) {
  const hasText = !!description && description.trim().length > 0;
  return (
    <div>
      <p
        className="text-[10px] font-semibold uppercase tracking-[0.1em] mb-2"
        style={{ color: 'var(--muted-foreground)' }}
      >
        Description
      </p>
      <p
        className="text-[13px] leading-[20px] max-w-[76ch]"
        style={{
          color: hasText ? 'color-mix(in oklab, var(--foreground) 90%, transparent)' : 'var(--muted-foreground)',
        }}
      >
        {hasText ? description : '—'}
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Block 2 — AI Assessment
// ---------------------------------------------------------------------------

function AiAssessmentBlock({ aiAnalysis }: { aiAnalysis: Record<string, unknown> | null | undefined }) {
  const entries = aiAnalysis ? Object.entries(aiAnalysis) : [];
  const hasAnalysis = entries.length > 0;

  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <p
          className="text-[10px] font-semibold uppercase tracking-[0.1em]"
          style={{ color: 'var(--muted-foreground)' }}
        >
          AI Assessment
        </p>
        {hasAnalysis && <ProvenanceBadge source="agent" size="sm" />}
      </div>

      {hasAnalysis ? (
        <div
          className="flex flex-col gap-2.5 max-w-[78ch]"
          style={{
            background: 'var(--subtle)',
            borderLeft: '2px solid color-mix(in oklab, var(--brand) 30%, transparent)',
            borderRadius: '0 10px 10px 0',
            padding: '14px 16px',
          }}
        >
          {entries.map(([key, value]) => (
            <div key={key}>
              <p
                className="text-[10px] uppercase tracking-[0.06em]"
                style={{ color: 'var(--muted-foreground)' }}
              >
                {humanizeKey(key)}
              </p>
              <p
                className="text-[12px] leading-[19px] whitespace-pre-wrap font-mono"
                style={{ color: 'color-mix(in oklab, var(--foreground) 88%, transparent)' }}
              >
                {formatValue(value)}
              </p>
            </div>
          ))}
        </div>
      ) : (
        <p className="text-[12px] font-mono" style={{ color: 'var(--muted-foreground)' }}>
          No AI assessment recorded for this incident.
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Block 3 — Action Chain
// ---------------------------------------------------------------------------

function ReasoningQuote({ text }: { text: string }) {
  const textRef = useRef<HTMLParagraphElement | null>(null);
  const [clamped, setClamped] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const expandedRef = useRef(expanded);

  useEffect(() => {
    expandedRef.current = expanded;
  }, [expanded]);

  useEffect(() => {
    const el = textRef.current;
    if (!el) return;

    // Overflow can only be measured while the line-clamp class is active
    // (i.e. while collapsed) — clientHeight === scrollHeight once expanded.
    const measure = () => {
      if (expandedRef.current) return;
      setClamped(el.scrollHeight - el.clientHeight > 1);
    };

    measure();

    if (typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    return () => observer.disconnect();
  }, [text]);

  return (
    <div className="mt-[6px] ml-[14px] pl-[10px]" style={{ borderLeft: '1px solid var(--border)' }}>
      <p
        ref={textRef}
        className={cn('text-[11px] leading-[17px] max-w-[72ch] font-mono', !expanded && 'line-clamp-3')}
        style={{ color: 'var(--muted-foreground)' }}
      >
        {text}
      </p>
      {(clamped || expanded) && (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          aria-expanded={expanded}
          className="mt-1 text-[10px] font-medium rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-1 focus-visible:ring-offset-card"
          style={{ color: 'var(--brand-text, var(--brand))' }}
        >
          {expanded ? 'Show less' : 'Show more'}
        </button>
      )}
    </div>
  );
}

function ApproveRejectButtons({
  action,
  busy,
  onApprove,
  onReject,
}: {
  action: DossierAction;
  busy: BusyKind | undefined;
  onApprove: () => void;
  onReject: () => void;
}) {
  const disabled = !!busy;
  const label = `${action.action_type} on ${action.target ?? 'unknown target'}`;

  return (
    <>
      <button
        type="button"
        onClick={onReject}
        disabled={disabled}
        aria-label={`Reject ${label}`}
        className={cn(
          'h-[26px] px-2.5 rounded-[8px] text-[10px] font-semibold uppercase tracking-wide border',
          'transition-colors duration-150 hover:text-[var(--sev-critical)]',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-card',
          'disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:text-[var(--muted-foreground)]',
        )}
        style={{
          borderColor: 'var(--border-strong)',
          color: 'var(--muted-foreground)',
        }}
      >
        {busy === 'reject' ? '···' : 'Reject'}
      </button>
      <button
        type="button"
        onClick={onApprove}
        disabled={disabled}
        aria-label={`Approve ${label}`}
        className={cn(
          'h-[26px] px-2.5 rounded-[8px] text-[10px] font-semibold uppercase tracking-wide',
          'transition-colors duration-150 hover:opacity-90',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-card',
          'disabled:opacity-50 disabled:cursor-not-allowed',
        )}
        style={{
          background: 'var(--brand)',
          color: 'var(--brand-foreground)',
        }}
      >
        {busy === 'approve' ? '···' : 'Approve'}
      </button>
    </>
  );
}

function ActionRow({
  action,
  busy,
  error,
  onApprove,
  onReject,
}: {
  action: DossierAction;
  busy: BusyKind | undefined;
  error: string | undefined;
  onApprove: () => void;
  onReject: () => void;
}) {
  const status = action.status ?? '';
  const showApproveReject = action.requires_approval && status.toLowerCase() === 'pending';

  return (
    <DataRow
      density="compact"
      borderless={false}
      leading={
        <span role="cell">
          <span
            aria-hidden="true"
            className="block w-[5px] h-[5px] rounded-full"
            style={{ background: actionDotColor(status) }}
          />
        </span>
      }
      trailing={
        <div role="cell" className="flex items-center gap-2">
          <StatusBadge size="sm" dot variant={actionBadgeVariant(status)}>
            {status ? status.toUpperCase() : 'UNKNOWN'}
          </StatusBadge>
          {showApproveReject && (
            <ApproveRejectButtons action={action} busy={busy} onApprove={onApprove} onReject={onReject} />
          )}
        </div>
      }
    >
      <div role="cell" className="flex-1 min-w-0 py-0.5">
        <p>
          <span className="text-[12px] font-semibold" style={{ color: 'var(--foreground)' }}>
            {action.action_type}
          </span>
          <span className="text-[12px] mx-1.5" style={{ color: 'var(--muted-foreground)' }} aria-hidden="true">
            &rarr;
          </span>
          <span className="text-[11px] font-mono" style={{ color: 'var(--muted-foreground)' }}>
            {action.target ?? '—'}
          </span>
        </p>
        {action.ai_reasoning && <ReasoningQuote text={action.ai_reasoning} />}
        {error && (
          <p role="alert" className="text-[11px] font-mono mt-1.5" style={{ color: 'var(--sev-critical)' }}>
            {error}
          </p>
        )}
      </div>
    </DataRow>
  );
}

function ActionChainBlock({
  actions,
  busy,
  errors,
  onApprove,
  onReject,
}: {
  actions: DossierAction[];
  busy: Record<string, BusyKind | undefined>;
  errors: Record<string, string | undefined>;
  onApprove: (action: DossierAction) => void;
  onReject: (action: DossierAction) => void;
}) {
  return (
    <div>
      <p
        className="text-[10px] font-semibold uppercase tracking-[0.1em] mb-2.5"
        style={{ color: 'var(--muted-foreground)' }}
      >
        Action Chain &middot; {actions.length}
      </p>

      {actions.length === 0 ? (
        <p className="text-[12px] font-mono" style={{ color: 'var(--muted-foreground)' }}>
          No response actions were taken. This incident was recorded for correlation only.
        </p>
      ) : (
        // DataRow renders role="row" — give it a valid ARIA ancestor chain
        // rather than orphaning it (Panel/DataRow primitives are shared and
        // owned elsewhere, so the fix is applied here at the call site).
        <div role="table" aria-label="Response action chain">
          <div role="rowgroup">
            {actions.map((action) => (
              <ActionRow
                key={action.id}
                action={action}
                busy={busy[action.id]}
                error={errors[action.id]}
                onApprove={() => onApprove(action)}
                onReject={() => onReject(action)}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------------

export function IncidentDossier({
  incidentId,
  title,
  severity,
  onApprove,
  onReject,
  onMutated,
}: IncidentDossierProps) {
  const [loadState, setLoadState] = useState<LoadState>('loading');
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [actionBusy, setActionBusy] = useState<Record<string, BusyKind | undefined>>({});
  const [actionError, setActionError] = useState<Record<string, string | undefined>>({});

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();

    setLoadState('loading');
    api.response
      .incident(incidentId)
      .then((data) => {
        if (cancelled || controller.signal.aborted) return;
        setDetail(data);
        setLoadState('ready');
      })
      .catch(() => {
        if (cancelled || controller.signal.aborted) return;
        setLoadState('error');
      });

    return () => {
      // Collapsing the dossier (unmount) or switching incidents aborts the
      // in-flight request at the state layer: no setState after teardown,
      // and a stale response can never clobber a newer one.
      cancelled = true;
      controller.abort();
    };
  }, [incidentId, reloadToken]);

  async function handleApprove(action: DossierAction) {
    setActionBusy((b) => ({ ...b, [action.id]: 'approve' }));
    setActionError((e) => ({ ...e, [action.id]: undefined }));
    try {
      await onApprove(action.id);
      onMutated();
      setReloadToken((k) => k + 1);
    } catch (err) {
      setActionError((e) => ({
        ...e,
        [action.id]: err instanceof Error ? err.message : 'Approval failed.',
      }));
    } finally {
      setActionBusy((b) => ({ ...b, [action.id]: undefined }));
    }
  }

  async function handleReject(action: DossierAction) {
    setActionBusy((b) => ({ ...b, [action.id]: 'reject' }));
    setActionError((e) => ({ ...e, [action.id]: undefined }));
    try {
      await onReject(action.id);
      onMutated();
      setReloadToken((k) => k + 1);
    } catch (err) {
      setActionError((e) => ({
        ...e,
        [action.id]: err instanceof Error ? err.message : 'Rejection failed.',
      }));
    } finally {
      setActionBusy((b) => ({ ...b, [action.id]: undefined }));
    }
  }

  return (
    <div
      id={`dossier-${incidentId}`}
      role="region"
      aria-label={`Details for ${title}`}
      data-severity={severity}
      className="flex flex-col gap-5"
    >
      {loadState === 'loading' && <DossierSkeleton />}

      {loadState === 'error' && (
        <div className="flex items-center gap-3">
          <p className="text-[12px] font-mono" style={{ color: 'var(--danger)' }}>
            Could not load incident detail.
          </p>
          <button
            type="button"
            onClick={() => setReloadToken((k) => k + 1)}
            className="text-[12px] font-medium underline-offset-2 hover:underline rounded-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-1 focus-visible:ring-offset-card"
            style={{ color: 'var(--brand-text, var(--brand))' }}
          >
            Retry
          </button>
        </div>
      )}

      {loadState === 'ready' && detail && (
        <>
          <DescriptionBlock description={detail.description} />
          <AiAssessmentBlock aiAnalysis={detail.ai_analysis} />
          <ActionChainBlock
            actions={detail.actions}
            busy={actionBusy}
            errors={actionError}
            onApprove={handleApprove}
            onReject={handleReject}
          />
        </>
      )}
    </div>
  );
}
