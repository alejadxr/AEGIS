'use client';

import { formatRelativeTime } from '@/lib/utils';

/**
 * VerdictLine — the 3am answer.
 *
 * The single apex of the dashboard hierarchy: one display-size sentence
 * stating whether anything needs the operator right now, plus one mono
 * line of the four supporting counts. Sits directly on the page
 * background (NOT a Panel) — the highest element in the hierarchy needs
 * no container.
 *
 * The zero case ("Nothing needs you.") is the PRIMARY state of this
 * dashboard, not an empty state. It renders at full weight, full
 * foreground color — never muted, never an icon, never the word "empty".
 */
export interface VerdictLineProps {
  /** FP-filtered incident count with status open|investigating. */
  activeIncidents: number;
  /** Count of actions with status === 'pending' from api.response.actions(). */
  pendingActions: number;
  /** From api.dashboard.overview(). */
  totalAssets: number;
  openVulnerabilities: number;
  honeypotInteractions: number;
  /** From api.dashboard.monitoredApps().count. */
  monitoredApps: number;
  /** ISO timestamp of the newest FP-filtered incident, or null. */
  lastIncidentAt: string | null;
  loading?: boolean;
}

const MIDDOT = '·';

export function VerdictLine({
  activeIncidents,
  pendingActions,
  totalAssets,
  openVulnerabilities,
  honeypotInteractions,
  monitoredApps,
  lastIncidentAt,
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

  // Sub-line segments, in exact spec order. The last-incident segment is
  // omitted entirely when there is no known last incident.
  const segments: string[] = [
    `${totalAssets} assets watched`,
    `${monitoredApps} apps`,
    `${openVulnerabilities} open vulns`,
    `${honeypotInteractions} honeypot hits`,
  ];
  if (lastIncidentAt) {
    const rel = formatRelativeTime(lastIncidentAt);
    if (rel && rel !== '—') {
      segments.push(`last incident ${rel}`);
    }
  }
  const subLine = segments.join(` ${MIDDOT} `);

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
      <p className="mt-3 font-mono text-[12px] font-medium leading-[18px] text-[var(--muted-foreground)] sm:leading-[16px]">
        {subLine}
      </p>
    </section>
  );
}
