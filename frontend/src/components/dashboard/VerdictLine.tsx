'use client';

import { formatRelativeTime } from '@/lib/utils';

/**
 * VerdictLine — the 3am answer.
 *
 * The single apex of the dashboard hierarchy: one display-size sentence
 * stating whether anything needs the operator right now, plus one mono
 * line of the supporting receipts. Sits directly on the page background
 * (NOT a Panel) — the highest element in the hierarchy needs no container.
 *
 * The zero case ("Nothing needs you.") is the PRIMARY state of this
 * dashboard, not an empty state. It renders at full weight, full
 * foreground color — never muted, never an icon, never the word "empty".
 *
 * The sub-line's job is to make that silence credible: it states what is
 * actually being watched and what has actually been done, rather than
 * repeating the same zero-valued counters WatchPanel prints below it.
 * actionsExecuted30d / blockedIpsNow are `null` (not 0) when their fetch
 * failed — a dead endpoint must never render as an honest "0", so a null
 * segment is omitted entirely instead of printed as zero.
 */
export interface VerdictLineProps {
  /** FP-filtered incidents with status open|investigating. Drives the headline. */
  activeIncidents: number;
  /** actions with status === 'pending'. Takes headline priority over incidents. */
  pendingActions: number;
  totalAssets: number;
  monitoredApps: number;
  /** ISO timestamp of newest FP-filtered incident, or null. */
  lastIncidentAt: string | null;
  /** overview.actions_taken — executed actions, trailing 30d. null = fetch failed, omit segment. */
  actionsExecuted30d: number | null;
  /** firewall.blocked.count — IPs enforced at this instant. null = fetch failed, omit segment. */
  blockedIpsNow: number | null;
  loading?: boolean;
}

const MIDDOT = '·';

/** A single sub-line segment: numeral in foreground, label in muted-foreground. */
function Segment({ numeral, label }: { numeral: string; label: string }) {
  return (
    <>
      <span className="text-[var(--foreground)] tabular-nums">{numeral}</span>
      <span className="text-[var(--muted-foreground)]"> {label}</span>
    </>
  );
}

export function VerdictLine({
  activeIncidents,
  pendingActions,
  totalAssets,
  monitoredApps,
  lastIncidentAt,
  actionsExecuted30d,
  blockedIpsNow,
  loading = false,
}: VerdictLineProps) {
  if (loading) {
    return (
      <section aria-label="Current verdict" aria-busy="true" className="col-span-12 pt-8">
        <h1 className="sr-only">Loading verdict…</h1>
        <div
          aria-hidden="true"
          className="h-10 w-[420px] max-w-full rounded-[6px] bg-[var(--muted)] opacity-40"
        />
        <div
          aria-hidden="true"
          className="mt-3 h-3 w-[300px] max-w-full rounded-[6px] bg-[var(--muted)] opacity-40"
        />
      </section>
    );
  }

  // Headline copy — exact priority order. Only the leading numeral (when
  // present) is colored; everything else is var(--foreground).
  let numeral: number | null = null;
  let rest: string;
  if (pendingActions > 0) {
    numeral = pendingActions;
    rest = ` action${pendingActions === 1 ? '' : 's'} awaiting your approval.`;
  } else if (activeIncidents > 0) {
    numeral = activeIncidents;
    rest = ` incident${activeIncidents === 1 ? '' : 's'} need${activeIncidents === 1 ? 's' : ''} your decision.`;
  } else {
    rest = 'Nothing needs you.';
  }

  // Sub-line segments, in exact spec order. Segments whose backing value is
  // null (fetch failure) are omitted entirely — never rendered as 0.
  const segments: Array<{ numeral: string; label: string }> = [
    { numeral: String(totalAssets), label: 'assets' },
    { numeral: String(monitoredApps), label: 'apps' },
  ];
  if (actionsExecuted30d !== null) {
    segments.push({
      numeral: actionsExecuted30d.toLocaleString(),
      label: 'actions executed · 30d',
    });
  }
  if (blockedIpsNow !== null) {
    segments.push({ numeral: String(blockedIpsNow), label: 'IPs blocked now' });
  }
  let lastIncidentLabel: string | null = null;
  if (lastIncidentAt) {
    const rel = formatRelativeTime(lastIncidentAt);
    if (rel && rel !== '—') {
      lastIncidentLabel = rel;
    }
  }

  return (
    <section aria-label="Current verdict" className="col-span-12 pt-8">
      <h1
        className="max-w-[22ch] font-sans font-semibold text-[30px] leading-[34px] tracking-[-1.4px] text-[var(--foreground)] sm:text-[40px] sm:leading-[44px] sm:tracking-[-2px]"
      >
        {numeral !== null && (
          <span className="text-[var(--brand-text)] tabular-nums">{numeral}</span>
        )}
        {rest}
      </h1>
      <p className="mt-3 font-mono text-[12px] font-medium leading-[18px] sm:leading-[16px]">
        {segments.map((seg, i) => (
          <span key={`${seg.label}-${i}`}>
            {i > 0 && <span className="text-[var(--muted-foreground)]"> {MIDDOT} </span>}
            <Segment numeral={seg.numeral} label={seg.label} />
          </span>
        ))}
        {lastIncidentLabel && (
          <span>
            <span className="text-[var(--muted-foreground)]"> {MIDDOT} </span>
            <span className="text-[var(--muted-foreground)]">last incident </span>
            <span className="text-[var(--foreground)] tabular-nums">{lastIncidentLabel}</span>
          </span>
        )}
      </p>
    </section>
  );
}
