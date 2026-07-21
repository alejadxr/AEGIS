'use client';

import { useCallback, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeft, Check, Copy } from 'lucide-react';
import { api, ApiError } from '@/lib/api';
import { cn, formatDate, formatRelativeTime } from '@/lib/utils';
import { Panel, SectionHeader, EmptyState, StatusBadge, ProvenanceBadge } from '@/components/aegis';
import type { StatusVariant } from '@/components/aegis';
import { IncidentDossier } from '@/components/dashboard/IncidentDossier';

/**
 * IncidentDetailPage — /dashboard/response/[id]
 *
 * The destination Ledger.tsx has been `router.push`-ing to since day one
 * (previously a 404: this directory held only page.tsx, no [id] segment).
 *
 * Leads with the four fields the recon proved are populated on essentially
 * every row — description, ai_analysis, ip_intel, raw_alert — and states
 * plainly where data genuinely does not exist (contained_at, target_asset_id)
 * rather than rendering a wall of em-dashes for dead columns. `mitre_tactic`,
 * `resolved_at` and `raw_alert` are not yet declared on api.response.incident()'s
 * TS return type (see IncidentDetail below) even though the backend model
 * already carries them — every read of those three fields is optional-chained
 * and gated behind an explicit non-empty check, so this page degrades to
 * omitting the cell/panel instead of crashing, both today and once a backend
 * change catches api.ts's types up to the model.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type IncidentDetailBase = Awaited<ReturnType<typeof api.response.incident>>;

/**
 * Fields the backend's IncidentOut model already carries (app/api/response.py)
 * but api.response.incident()'s TS type does not yet declare. Declared here
 * as optional so a value of the *actual* (narrower) api.ts type remains
 * assignable — no cast needed — and every access below treats them as
 * possibly absent rather than assuming they exist.
 */
interface IncidentDetailExtra {
  mitre_tactic?: string | null;
  resolved_at?: string | null;
  raw_alert?: Record<string, unknown> | null;
}

type IncidentDetail = IncidentDetailBase & IncidentDetailExtra;

type ActionListItem = Awaited<ReturnType<typeof api.response.actions>>[number];

type SeverityKey = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface FactCell {
  key: string;
  label: string;
  value: ReactNode;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SEV_VAR: Record<SeverityKey, string> = {
  critical: 'var(--sev-critical, var(--danger))',
  high: 'var(--sev-high, var(--brand-accent))',
  medium: 'var(--sev-medium, var(--warning))',
  low: 'var(--sev-low, var(--brand))',
  info: 'var(--sev-info, var(--muted-foreground))',
};

function severityKey(sev: string | null | undefined): SeverityKey {
  const s = (sev ?? '').toLowerCase();
  if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low' || s === 'info') return s;
  return 'info';
}

/** critical→danger, high→warning, medium→warning, low→info, else muted. */
function severityBadgeVariant(sev: string | null | undefined): StatusVariant {
  const s = (sev ?? '').toLowerCase();
  if (s === 'critical') return 'danger';
  if (s === 'high' || s === 'medium') return 'warning';
  if (s === 'low') return 'info';
  return 'muted';
}

function confidenceTone(v: number): SeverityKey {
  if (v >= 0.7) return 'critical';
  if (v >= 0.4) return 'high';
  if (v >= 0.15) return 'medium';
  if (v > 0) return 'low';
  return 'info';
}

/** null AND '' both count as absent — the data genuinely contains both. */
function nonEmpty(v: string | null | undefined): string | null {
  if (v === null || v === undefined) return null;
  const t = v.trim();
  return t.length > 0 ? t : null;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Skips null/undefined/empty-string/empty-array/empty-object. Zero, false
 * and non-empty strings/arrays/objects all count as present. */
function isNonEmptyValue(v: unknown): boolean {
  if (v === null || v === undefined) return false;
  if (typeof v === 'string') return v.trim().length > 0;
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === 'object') return Object.keys(v as object).length > 0;
  return true;
}

/** Mirrors IncidentDossier's private humanizeKey/formatValue — that
 * component is reused verbatim (zero edits) so its helpers aren't
 * exported; duplicated here rather than dumping JSON.stringify into a <pre>. */
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

// ---------------------------------------------------------------------------
// Small presentational pieces
// ---------------------------------------------------------------------------

function FactDateValue({ iso }: { iso: string }) {
  return (
    <span>
      {formatDate(iso)} <span className="text-muted-foreground">({formatRelativeTime(iso)})</span>
    </span>
  );
}

function SourceIpValue({ ip }: { ip: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(ip);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard API unavailable (insecure context / permissions) — fail
      // silently rather than fabricate a success state.
    }
  }, [ip]);

  return (
    <span className="inline-flex items-center gap-1">
      <span>{ip}</span>
      <button
        type="button"
        onClick={handleCopy}
        aria-label="Copy source IP"
        className={cn(
          'inline-flex items-center justify-center w-11 h-11 -my-3.5 -mr-2 shrink-0 rounded-md',
          'text-muted-foreground hover:text-foreground transition-colors',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]',
        )}
      >
        {copied ? <Check size={13} aria-hidden /> : <Copy size={13} aria-hidden />}
      </button>
      <span className="text-[10px] text-muted-foreground/70 w-[42px] shrink-0" aria-hidden="true">
        {copied ? 'Copied' : ''}
      </span>
      <span role="status" className="sr-only">
        {copied ? 'Copied source IP to clipboard' : ''}
      </span>
    </span>
  );
}

function IncidentDetailSkeleton() {
  return (
    <div className="space-y-6">
      <span role="status" className="sr-only">
        Loading incident.
      </span>
      <div aria-hidden="true" className="motion-safe:animate-pulse">
        <div className="h-[10px] w-20 rounded bg-muted/40 mb-4" />
        <div className="h-[22px] w-2/3 max-w-md rounded bg-muted/40 mb-3" />
        <div className="flex gap-2 mb-6">
          <div className="h-5 w-20 rounded-md bg-muted/40" />
          <div className="h-5 w-28 rounded-md bg-muted/40" />
          <div className="h-5 w-16 rounded-md bg-muted/40" />
        </div>
        <div className="rounded-2xl border border-border overflow-hidden mb-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-border">
            {[0, 1, 2, 3].map((i) => (
              <div key={i} className="px-5 py-3.5">
                <div className="h-[10px] w-16 rounded bg-muted/40 mb-2" />
                <div className="h-[13px] w-24 rounded bg-muted/40" />
              </div>
            ))}
          </div>
        </div>
        <div className="rounded-2xl border border-border overflow-hidden px-5 py-4 space-y-4">
          {[0, 1, 2].map((i) => (
            <div key={i} className="space-y-2">
              <div className="h-[10px] w-24 rounded bg-muted/40" />
              <div className="h-[14px] w-full max-w-lg rounded bg-muted/40" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------------

type PageState = 'loading' | 'ready' | 'not-found' | 'error';

export default function IncidentDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const router = useRouter();

  const [state, setState] = useState<PageState>('loading');
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [redundancyActions, setRedundancyActions] = useState<ActionListItem[]>([]);
  const [reloadToken, setReloadToken] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setState('loading');

    (async () => {
      const [incResult, actResult] = await Promise.allSettled([
        api.response.incident(id),
        api.response.actions(),
      ]);
      if (cancelled) return;

      if (incResult.status === 'rejected') {
        const err = incResult.reason;
        setDetail(null);
        setState(err instanceof ApiError && err.status === 404 ? 'not-found' : 'error');
        return;
      }

      setDetail(incResult.value as IncidentDetail);
      setRedundancyActions(actResult.status === 'fulfilled' ? actResult.value : []);
      setState('ready');
    })();

    return () => {
      cancelled = true;
    };
  }, [id, reloadToken]);

  useEffect(() => {
    if (detail?.title) document.title = `${detail.title} · AEGIS`;
  }, [detail?.title]);

  const refetch = useCallback(() => setReloadToken((t) => t + 1), []);

  const handleBack = useCallback(() => {
    if (typeof window !== 'undefined' && window.history.length > 1) router.back();
    else router.push('/dashboard/response');
  }, [router]);

  const handleApprove = useCallback(async (actionId: string) => {
    await api.response.approveAction(actionId);
  }, []);

  const handleReject = useCallback(async (actionId: string, reason?: string) => {
    await api.response.rejectAction(actionId, reason);
  }, []);

  // -------------------------------------------------------------------------
  // Loading
  // -------------------------------------------------------------------------
  if (state === 'loading') {
    return <IncidentDetailSkeleton />;
  }

  // -------------------------------------------------------------------------
  // 404 — a working route back, not a dead end
  // -------------------------------------------------------------------------
  if (state === 'not-found') {
    return (
      <div className="flex items-center justify-center py-20">
        <EmptyState
          size="lg"
          title="Incident not found."
          description="It may have been purged by the 90-day retention service, or the id no longer exists."
          action={
            <button
              type="button"
              onClick={() => router.push('/dashboard/response')}
              className={cn(
                'inline-flex items-center justify-center h-10 px-4 rounded-lg text-[12px] font-semibold',
                'bg-[var(--brand)] text-[var(--brand-foreground)] hover:opacity-90 transition-opacity',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]',
                'focus-visible:ring-offset-2 focus-visible:ring-offset-background',
              )}
            >
              Back to Response
            </button>
          }
        />
      </div>
    );
  }

  // -------------------------------------------------------------------------
  // Any other error — retry re-runs the fetch, never a page reload (the id
  // already lives in the URL)
  // -------------------------------------------------------------------------
  if (state === 'error' || !detail) {
    return (
      <div className="flex items-center justify-center py-20">
        <EmptyState
          size="lg"
          title="Could not load this incident."
          action={
            <button
              type="button"
              onClick={refetch}
              className={cn(
                'inline-flex items-center justify-center h-10 px-4 rounded-lg text-[12px] font-semibold',
                'border border-border text-foreground hover:bg-muted/40 transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]',
              )}
            >
              Retry
            </button>
          }
        />
      </div>
    );
  }

  // -------------------------------------------------------------------------
  // Ready — derive everything from `detail` (never rendered until non-null)
  // -------------------------------------------------------------------------

  const mt = nonEmpty(detail.mitre_technique);
  const mtac = nonEmpty(detail.mitre_tactic);
  const mitreValue = mt && mtac ? `${mt} · ${mtac}` : mt ?? mtac;

  const detectedIso = nonEmpty(detail.detected_at);
  const resolvedIso = nonEmpty(detail.resolved_at);
  const sourceIp = nonEmpty(detail.source_ip);

  const cells: FactCell[] = [];
  if (detectedIso) cells.push({ key: 'detected', label: 'Detected', value: <FactDateValue iso={detectedIso} /> });
  if (resolvedIso) cells.push({ key: 'resolved', label: 'Resolved', value: <FactDateValue iso={resolvedIso} /> });
  if (sourceIp) cells.push({ key: 'source_ip', label: 'Source IP', value: <SourceIpValue ip={sourceIp} /> });
  if (mitreValue) cells.push({ key: 'mitre', label: 'MITRE', value: mitreValue });
  const showFacts = cells.length >= 2;

  const analysis = detail.ai_analysis;
  const ipIntelRaw = analysis?.ip_intel;
  const ipIntel = isPlainObject(ipIntelRaw) && Object.keys(ipIntelRaw).length > 0 ? ipIntelRaw : null;
  const actionsTakenRaw = analysis?.actions_taken;
  const actionsTaken = typeof actionsTakenRaw === 'number' ? actionsTakenRaw : null;

  const detailActions = detail.actions ?? [];
  const netActionsForIncident = redundancyActions.filter((a) => a.incident_id === id);
  const knownActionsCount = detailActions.length > 0 ? detailActions.length : netActionsForIncident.length;
  const showDiscrepancy = actionsTaken !== null && actionsTaken > 0 && knownActionsCount === 0;

  const rawAlert = isPlainObject(detail.raw_alert) && Object.keys(detail.raw_alert).length > 0 ? detail.raw_alert : null;

  const provenanceSource: 'algorithm' | 'agent' =
    detail.source === 'fast_triage' || detail.source === 'correlation_engine' ? 'algorithm' : 'agent';

  const ipIntelEntries = ipIntel ? Object.entries(ipIntel).filter(([, v]) => isNonEmptyValue(v)) : [];
  const confidenceRaw = ipIntelEntries.find(([k]) => k === 'confidence')?.[1];
  const confidenceEntries: Array<[string, number]> = isPlainObject(confidenceRaw)
    ? Object.entries(confidenceRaw).filter((e): e is [string, number] => typeof e[1] === 'number' && e[1] >= 0 && e[1] <= 1)
    : [];
  const providersRaw = ipIntelEntries.find(([k]) => k === 'providers')?.[1];
  const providersList: string[] = Array.isArray(providersRaw)
    ? providersRaw.filter((p): p is string => typeof p === 'string')
    : [];
  const genericIntelEntries = ipIntelEntries.filter(([k]) => k !== 'confidence' && k !== 'providers');

  return (
    <div className="space-y-6 animate-fade-in">
      {/* HEADER — sits directly on the page background, not a Panel */}
      <div>
        <button
          type="button"
          onClick={handleBack}
          className={cn(
            'inline-flex items-center gap-1.5 min-h-[44px] -ml-1 pl-1 pr-2 rounded-md',
            'text-[11px] uppercase tracking-[0.14em] text-muted-foreground hover:text-foreground',
            'transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]',
          )}
        >
          <ArrowLeft size={14} aria-hidden />
          RESPONSE
        </button>

        <h1 className="mt-1 text-[18px] leading-[24px] md:text-[22px] md:leading-[28px] font-semibold text-foreground break-words">
          {detail.title}
        </h1>

        <div className="flex flex-wrap items-center gap-2 mt-2">
          <StatusBadge variant={severityBadgeVariant(detail.severity)}>{detail.severity.toUpperCase()}</StatusBadge>
          <StatusBadge variant="muted">{detail.status.replace(/_/g, ' ').toUpperCase()}</StatusBadge>
          <ProvenanceBadge source={provenanceSource} label={detail.source} />
        </div>
      </div>

      {/* FACTS */}
      {showFacts && (
        <Panel variant="default" padding="none" as="section" aria-label="Facts">
          <SectionHeader flush title="FACTS" />
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-[var(--border)]">
            {cells.map((c) => (
              <div key={c.key} className="px-5 py-3.5">
                <p className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">{c.label}</p>
                <div className="mt-1 font-mono text-[13px] text-foreground">{c.value}</div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* ANALYSIS */}
      <Panel variant="default" padding="none" as="section" aria-label="Analysis">
        <SectionHeader flush title="ANALYSIS" />
        <div className="px-5 py-4">
          <IncidentDossier
            incidentId={id}
            title={detail.title}
            severity={severityKey(detail.severity)}
            onApprove={handleApprove}
            onReject={handleReject}
            onMutated={refetch}
          />
        </div>
        {showDiscrepancy && (
          <div className="border-t border-border px-5 py-3">
            <p className="text-[12px] leading-[17px] text-muted-foreground">
              The triage pipeline reports {actionsTaken} playbook step(s) ran for this incident, but no Action
              records were written for them, so they cannot be listed here.
            </p>
          </div>
        )}
      </Panel>

      {/* ORIGIN INTEL */}
      {ipIntel && (
        <Panel variant="default" padding="none" as="section" aria-label="Origin intel">
          <SectionHeader flush title="ORIGIN INTEL" />
          <div className="flex flex-wrap gap-x-5 gap-y-2 px-5 py-4">
            {confidenceEntries.length > 0 && (
              <div className="w-full flex flex-wrap gap-x-5 gap-y-2">
                {confidenceEntries.map(([k, v]) => {
                  const tone = confidenceTone(v);
                  return (
                    <div key={k} className="flex items-center gap-2">
                      <span className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">{humanizeKey(k)}</span>
                      <span className="h-1 w-16 rounded-full bg-muted overflow-hidden">
                        <span
                          className="block h-full rounded-full"
                          style={{ width: `${Math.round(v * 100)}%`, background: SEV_VAR[tone] }}
                        />
                      </span>
                      <span className="font-mono text-[11px] text-foreground">{v.toFixed(2)}</span>
                    </div>
                  );
                })}
              </div>
            )}

            {providersList.length > 0 && (
              <div className="w-full flex flex-wrap items-center gap-1.5">
                <span className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">Providers</span>
                <span className="inline-flex items-center rounded-full border border-border bg-muted/30 px-2 py-0.5 font-mono text-[11px] text-muted-foreground">
                  {providersList.join(', ')}
                </span>
              </div>
            )}

            {genericIntelEntries.map(([k, v]) => {
              const emailMatch = /abuse/i.test(k) && typeof v === 'string' && v.includes('@') ? v.trim() : null;
              return (
                <div key={k} className="flex items-baseline gap-1.5">
                  <span className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">{humanizeKey(k)}</span>
                  <span className="font-mono text-[12px] text-foreground break-all">{formatValue(v)}</span>
                  {emailMatch && (
                    <a
                      href={`mailto:${emailMatch}`}
                      className={cn(
                        'text-[11px] text-[var(--brand-text,var(--brand))] hover:underline rounded-sm',
                        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]',
                      )}
                    >
                      Contact
                    </a>
                  )}
                </div>
              );
            })}
          </div>
          <p className="px-5 pb-4 text-[11px] text-muted-foreground">
            {`Attribution from ${providersList.length} provider(s); fields absent from this pipeline are omitted, not zero.`}
          </p>
        </Panel>
      )}

      {/* RAW ALERT */}
      {rawAlert && (
        <Panel variant="default" padding="none" as="section" aria-label="Raw alert">
          <SectionHeader flush title="RAW ALERT" />
          <details>
            <summary
              className={cn(
                'cursor-pointer px-5 min-h-[44px] flex items-center text-[12px]',
                'text-[var(--brand-text,var(--brand))]',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-inset',
              )}
            >
              Show the originating alert payload
            </summary>
            <div className="px-5 pb-4 pt-1 divide-y divide-border/60">
              {Object.entries(rawAlert).map(([k, v]) => (
                <div key={k} className="py-2">
                  <p className="text-[10px] uppercase tracking-[0.1em] text-muted-foreground">{humanizeKey(k)}</p>
                  <p className="mt-0.5 text-[12px] font-mono text-foreground whitespace-pre-wrap break-words">
                    {formatValue(v)}
                  </p>
                </div>
              ))}
            </div>
          </details>
        </Panel>
      )}
    </div>
  );
}
