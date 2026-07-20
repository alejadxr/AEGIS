'use client';

import * as React from 'react';
import { useRouter } from 'next/navigation';
import { ChevronDown, ChevronUp } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Panel, SectionHeader, EmptyState } from '@/components/aegis';

/**
 * Ledger — the record.
 *
 * A dense monospace table of recent incidents and AI audit entries, placed
 * at the bottom where chronology belongs. Replaces IncidentTimeline (a
 * 200px scrubber with auto-zoom heuristics, two-row collision hacking and
 * manual zoom controls, built for a firehose, rendering five events, and
 * shipping visible "Â·" mojibake in its live subtitle instead of a real
 * middle dot).
 *
 * This component never fetches and never drops a single entry. `entries`
 * must already be sorted newest-first and, per the backend's known
 * behaviour, the caller (page.tsx) MUST strip `[FP-` prefixed incident
 * titles before handing them here — /dashboard/timeline does not apply
 * that filter itself even though five sibling queries in the same backend
 * file do.
 *
 * Grouping: `/dashboard/timeline` interleaves real incidents with an
 * `AuditLog` row for every AI action, including routine scans that fire
 * every ~7 minutes (`AI: scheduled_scan`). Left flat, a busy window is nine
 * parts identical audit chatter to one part signal. Consecutive `audit`-type
 * rows that share the exact same title (and severity) are collapsed into a
 * single summary row — count + time range — expandable via a real button
 * (`aria-expanded`) into the individual rows it represents. Nothing is ever
 * discarded: every raw row is one click away. `incident` rows are never
 * grouped, even if adjacent/duplicated — they are always individually
 * significant and individually navigable.
 *
 * Type column: the backend's TimelineEvent has no `module` field — page.tsx
 * previously always sent a permanently-empty `module: ''`, rendering 113
 * blank cells. This component instead renders the real `type` field
 * ('incident' | 'audit') in the same 120px column: uppercase, muted, no
 * colour and no pill, since severity already owns the colour channel in
 * this table.
 *
 * Progressive disclosure, not a nested scroll region: only `initialRows`
 * (default 40) entries render at first; a "SHOW N MORE" control at the
 * foot of the table reveals the rest 40 at a time. The page scrolls — this
 * panel never traps the wheel inside its own `overflow-y-auto` box.
 */

export interface LedgerEntry {
  id: string;
  type: string;
  title: string;
  description: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | null;
  timestamp: string;
}

type LedgerWindow = '24h' | '7d' | '30d';

export interface LedgerProps {
  entries: LedgerEntry[];
  /** Current page-wide window, mirrored in the header subtitle. */
  window: LedgerWindow;
  /**
   * Mirrors the shared window-control contract used by CommandBar and its
   * sibling panels. This component does not call it directly — the window
   * switch itself lives in the page-level command bar, not in this panel's
   * empty state — but the prop stays required so `window`/`onWindowChange`
   * keep travelling together at every call site.
   */
  onWindowChange: (w: LedgerWindow) => void;
  loading?: boolean;
  error?: boolean;
  /**
   * Optional: re-run whatever fetch populates `entries`. Not part of the
   * original contract — additive and optional so existing callers keep
   * compiling. Falls back to a full page reload (a real, working retry,
   * never a decorative no-op button) when omitted.
   */
  onRetry?: () => void;
  /** Rows rendered before the SHOW MORE control. Default 40. */
  initialRows?: number;
}

// ─── Constants ──────────────────────────────────────────────────────────────

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

type SeverityKey = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Explicit map, never template-literal interpolation — an unrecognised
 * severity string must never produce an undefined CSS var (which resolves
 * to an invisible dot on a dark card). */
const SEV_VAR: Record<SeverityKey, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  info: 'var(--sev-info)',
};

const SEV_LABEL: Record<SeverityKey, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

const COL_TIME = 110;
const COL_SEVERITY = 128;
const COL_TYPE = 120;

const TH_CLASS =
  'px-4 align-middle text-left text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground border-b border-border';

const ROW_TRANSITION =
  'transition-[background-color] duration-150 ease-[cubic-bezier(0.22,1,0.36,1)] motion-reduce:transition-none';

const ROW_HOVER = 'hover:bg-[color-mix(in_oklab,var(--foreground)_2%,transparent)]';

// ─── Helpers ────────────────────────────────────────────────────────────────

function severityKey(severity: string | null | undefined): SeverityKey {
  const s = (severity ?? '').toLowerCase();
  if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low' || s === 'info') return s;
  return 'info';
}

/** 'incident' -> 'INCIDENT', 'audit' -> 'AUDIT', anything else -> the raw
 * value uppercased — never a blank cell, since `type` is a real, always-
 * populated backend field (unlike the retired `module` field). */
function typeLabel(type: string): string {
  if (type === 'incident') return 'INCIDENT';
  if (type === 'audit') return 'AUDIT';
  return type.toUpperCase();
}

function pad2(n: number): string {
  return String(n).padStart(2, '0');
}

/** Backend emits naive UTC datetimes without a trailing Z — normalize
 * before parsing, matching the convention already used by
 * formatRelativeTime / WatchPanel's mostRecentActivity. */
function toDate(iso: string): Date | null {
  if (!iso) return null;
  const normalized = iso.endsWith('Z') || iso.includes('+') ? iso : `${iso}Z`;
  const d = new Date(normalized);
  return Number.isNaN(d.getTime()) ? null : d;
}

function formatLedgerTime(iso: string): string {
  const d = toDate(iso);
  if (!d) return '—';
  const ageMs = Date.now() - d.getTime();
  if (ageMs < 24 * 3600 * 1000) {
    return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  }
  return `${pad2(d.getDate())} ${MONTHS[d.getMonth()]} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
}

/** Seconds-free variant used inside a group's collapsed time-range label
 * ("12:44–13:53") — the range already communicates precision at the
 * minute level; seconds would just make two timestamps harder to compare. */
function formatShortTime(iso: string): string {
  const d = toDate(iso);
  if (!d) return '—';
  const ageMs = Date.now() - d.getTime();
  if (ageMs < 24 * 3600 * 1000) {
    return `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  }
  return `${pad2(d.getDate())} ${MONTHS[d.getMonth()]} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
}

// ─── Grouping ───────────────────────────────────────────────────────────────
//
// Collapse consecutive runs (>= 2) of `audit`-type rows that share an exact
// title + severity into a single collapsible summary. `incident` rows are
// never grouped. Pure function of `entries` — no state, safe to recompute
// in a `useMemo`.

interface LedgerGroup {
  /** Stable id derived from the first (newest) entry in the run. */
  id: string;
  title: string;
  severity: SeverityKey;
  /** Always 'audit' today — only audit-type runs are grouped — but sourced
   * from the real entry rather than hardcoded, so the TYPE column stays
   * correct if that ever changes. */
  type: string;
  /** Newest-first, mirrors the source order of `entries`. */
  members: LedgerEntry[];
}

/** Rows required before the header is worth pinning. Each row is 34px, so 12
 *  rows is ~408px — comfortably taller than the sticky offset the header would
 *  travel to, which is what keeps it from overlapping its own tbody. */
const STICKY_HEAD_MIN_ROWS = 12;

type LedgerDisplayItem =
  | { kind: 'single'; entry: LedgerEntry }
  | { kind: 'group'; group: LedgerGroup };

function buildDisplayItems(entries: LedgerEntry[]): LedgerDisplayItem[] {
  const items: LedgerDisplayItem[] = [];
  let i = 0;
  while (i < entries.length) {
    const head = entries[i];
    if (head.type === 'audit') {
      let j = i + 1;
      while (
        j < entries.length &&
        entries[j].type === 'audit' &&
        entries[j].title === head.title &&
        entries[j].severity === head.severity
      ) {
        j += 1;
      }
      const runLength = j - i;
      if (runLength >= 2) {
        items.push({
          kind: 'group',
          group: {
            id: `group-${head.id}`,
            title: head.title,
            severity: severityKey(head.severity),
            type: head.type,
            members: entries.slice(i, j),
          },
        });
        i = j;
        continue;
      }
    }
    items.push({ kind: 'single', entry: head });
    i += 1;
  }
  return items;
}

type LedgerFlatRow =
  | { kind: 'single'; key: string; entry: LedgerEntry }
  | { kind: 'groupHeader'; key: string; group: LedgerGroup; expanded: boolean }
  | { kind: 'nested'; key: string; entry: LedgerEntry; groupId: string };

function flattenDisplayItems(
  items: LedgerDisplayItem[],
  expandedGroups: Set<string>,
): LedgerFlatRow[] {
  const rows: LedgerFlatRow[] = [];
  for (const item of items) {
    if (item.kind === 'single') {
      rows.push({ kind: 'single', key: item.entry.id, entry: item.entry });
      continue;
    }
    const expanded = expandedGroups.has(item.group.id);
    rows.push({ kind: 'groupHeader', key: item.group.id, group: item.group, expanded });
    if (expanded) {
      for (const member of item.group.members) {
        rows.push({ kind: 'nested', key: `${item.group.id}-${member.id}`, entry: member, groupId: item.group.id });
      }
    }
  }
  return rows;
}

// ─── Skeleton row ───────────────────────────────────────────────────────────

const SKELETON_WIDTHS = [56, 64, 50, '55%'] as const;
const SKELETON_COL_WIDTHS = [COL_TIME, COL_SEVERITY, COL_TYPE];

function LedgerSkeletonRow({ last }: { last: boolean }) {
  const widths = SKELETON_WIDTHS;
  const colWidths = SKELETON_COL_WIDTHS;
  return (
    <tr className="h-9">
      {widths.map((w, i) => (
        <td
          key={i}
          className={cn('px-4 align-middle', !last && 'border-b border-border')}
          style={i < colWidths.length ? { width: colWidths[i] } : undefined}
        >
          <div
            className="h-[8px] rounded-full bg-[var(--muted-foreground)] opacity-30"
            style={{ width: typeof w === 'number' ? `${w}px` : w }}
            aria-hidden
          />
        </td>
      ))}
    </tr>
  );
}

// ─── Empty (zero-entries) row ───────────────────────────────────────────────

function LedgerEmptyRow({
  windowValue,
  colSpan,
}: {
  windowValue: LedgerWindow;
  colSpan: number;
}) {
  return (
    <tr>
      <td colSpan={colSpan} className="h-[88px] px-4 text-center align-middle">
        <p className="font-mono text-[12px] leading-[16px] text-muted-foreground opacity-70">
          No events in the last {windowValue}.
        </p>
        <p className="mt-1 font-mono text-[11px] leading-[16px] text-muted-foreground">
          Widen the window to see more history.
        </p>
      </td>
    </tr>
  );
}

// ─── Data row ───────────────────────────────────────────────────────────────

interface LedgerRowProps {
  entry: LedgerEntry;
  isLast: boolean;
  expanded: boolean;
  onToggleExpand: () => void;
  /** True for a row rendered under an expanded group — indented and
   * slightly muted so it visually reads as "detail of the row above". */
  nested?: boolean;
}

function LedgerRow({ entry, isLast, expanded, onToggleExpand, nested = false }: LedgerRowProps) {
  const router = useRouter();
  const sevKey = severityKey(entry.severity);
  const sevColor = SEV_VAR[sevKey];
  const isIncident = entry.type === 'incident';
  const timeLabel = formatLedgerTime(entry.timestamp);
  const typeLabelText = typeLabel(entry.type);

  const rowAriaLabel = `${timeLabel}, ${SEV_LABEL[sevKey]} severity, ${typeLabelText}, ${entry.title}${
    isIncident ? ', opens incident details' : ''
  }`;

  const navigate = React.useCallback(() => {
    router.push(`/dashboard/response/${entry.id}`);
  }, [router, entry.id]);

  const handleRowKeyDown = (e: React.KeyboardEvent<HTMLTableRowElement>) => {
    // Ignore keydowns bubbled up from the nested expand button so Enter/Space
    // on it doesn't ALSO trigger row navigation.
    if (e.target !== e.currentTarget) return;
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      navigate();
    }
  };

  const handleExpandClick = (e: React.MouseEvent<HTMLButtonElement>) => {
    e.stopPropagation();
    onToggleExpand();
  };

  const cellBorder = !isLast && 'border-b border-border';

  return (
    <tr
      role={isIncident ? 'button' : undefined}
      tabIndex={isIncident ? 0 : undefined}
      aria-label={isIncident ? rowAriaLabel : undefined}
      title={entry.title}
      onClick={isIncident ? navigate : undefined}
      onKeyDown={isIncident ? handleRowKeyDown : undefined}
      className={cn(
        !expanded && 'h-9',
        ROW_TRANSITION,
        ROW_HOVER,
        nested && 'bg-[color-mix(in_oklab,var(--foreground)_1.5%,transparent)] opacity-80',
        isIncident
          ? [
              'cursor-pointer',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--ring)]',
            ]
          : 'cursor-default',
      )}
    >
      <td
        className={cn('align-middle', nested ? 'pl-9 pr-4' : 'px-4', cellBorder)}
        style={{ width: COL_TIME }}
      >
        <span className="whitespace-nowrap font-mono text-[11px] tabular-nums text-muted-foreground">
          {timeLabel}
        </span>
      </td>

      <td className={cn('px-4 align-middle', cellBorder)} style={{ width: COL_SEVERITY }}>
        <span className="inline-flex items-center gap-1.5">
          <span
            aria-hidden
            className="h-[6px] w-[6px] shrink-0 rounded-full"
            style={{ background: sevColor }}
          />
          <span
            className="max-[559px]:hidden font-mono text-[10px] font-semibold uppercase tracking-[0.08em]"
            style={{ color: sevColor }}
          >
            {SEV_LABEL[sevKey]}
          </span>
        </span>
      </td>

      <td
        className={cn('max-[719px]:hidden px-4 align-middle', cellBorder)}
        style={{ width: COL_TYPE }}
      >
        <span className="block truncate font-mono text-[10.5px] uppercase tracking-[0.08em] text-[var(--muted-foreground)]">
          {typeLabelText}
        </span>
      </td>

      <td className={cn('px-4 align-middle', cellBorder)}>
        <div className="flex min-w-0 items-center gap-1.5">
          <span
            className={cn(
              'min-w-0 text-[12px] font-normal text-foreground',
              expanded ? 'whitespace-normal' : 'line-clamp-1',
            )}
          >
            {entry.title}
          </span>
          <button
            type="button"
            onClick={handleExpandClick}
            aria-expanded={expanded}
            aria-label={expanded ? 'Collapse event text' : 'Expand event text'}
            className="shrink-0 rounded p-0.5 text-muted-foreground/50 hover:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
          >
            {expanded ? <ChevronUp size={12} aria-hidden /> : <ChevronDown size={12} aria-hidden />}
          </button>
        </div>
      </td>
    </tr>
  );
}

// ─── Collapsed-group summary row ───────────────────────────────────────────

interface LedgerGroupRowProps {
  group: LedgerGroup;
  isLast: boolean;
  expanded: boolean;
  onToggle: () => void;
}

function LedgerGroupRow({ group, isLast, expanded, onToggle }: LedgerGroupRowProps) {
  const sevColor = SEV_VAR[group.severity];
  const count = group.members.length;
  // members[] is newest-first (source order); the range reads oldest→newest,
  // left to right, matching how a human writes a time span.
  const newest = group.members[0];
  const oldest = group.members[group.members.length - 1];
  const timeLabel = formatLedgerTime(newest.timestamp);
  const rangeLabel = `${formatShortTime(oldest.timestamp)}–${formatShortTime(newest.timestamp)}`;
  const cellBorder = !isLast && 'border-b border-border';

  return (
    <tr className={cn('h-9', ROW_TRANSITION, ROW_HOVER)}>
      <td className={cn('px-4 align-middle', cellBorder)} style={{ width: COL_TIME }}>
        <span className="whitespace-nowrap font-mono text-[11px] tabular-nums text-muted-foreground">
          {timeLabel}
        </span>
      </td>

      <td className={cn('px-4 align-middle', cellBorder)} style={{ width: COL_SEVERITY }}>
        <span className="inline-flex items-center gap-1.5">
          <span
            aria-hidden
            className="h-[6px] w-[6px] shrink-0 rounded-full"
            style={{ background: sevColor }}
          />
          <span
            className="max-[559px]:hidden font-mono text-[10px] font-semibold uppercase tracking-[0.08em]"
            style={{ color: sevColor }}
          >
            {SEV_LABEL[group.severity]}
          </span>
        </span>
      </td>

      <td
        className={cn('max-[719px]:hidden px-4 align-middle', cellBorder)}
        style={{ width: COL_TYPE }}
      >
        <span className="block truncate font-mono text-[10.5px] uppercase tracking-[0.08em] text-[var(--muted-foreground)]">
          {typeLabel(group.type)}
        </span>
      </td>

      <td className={cn('px-4 align-middle', cellBorder)}>
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={expanded}
          aria-label={`${expanded ? 'Collapse' : 'Expand'} ${count} grouped "${group.title}" events, ${rangeLabel}`}
          className="flex w-full min-w-0 items-center gap-2 rounded text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
        >
          <span className="min-w-0 truncate text-[12px] font-normal text-foreground">
            {group.title}
          </span>
          <span className="shrink-0 rounded-full bg-[color-mix(in_oklab,var(--foreground)_8%,transparent)] px-1.5 py-[1px] font-mono text-[10px] font-semibold tabular-nums text-muted-foreground">
            {'×'}
            {count}
          </span>
          <span className="shrink-0 truncate font-mono text-[11px] text-muted-foreground/70">
            {'·'} {rangeLabel}
          </span>
          <span className="ml-auto shrink-0 text-muted-foreground/50">
            {expanded ? <ChevronUp size={12} aria-hidden /> : <ChevronDown size={12} aria-hidden />}
          </span>
        </button>
      </td>
    </tr>
  );
}

// ─── Root component ─────────────────────────────────────────────────────────

export function Ledger({
  entries,
  window: windowValue,
  loading = false,
  error = false,
  onRetry,
  initialRows = 40,
}: LedgerProps) {
  const [expandedIds, setExpandedIds] = React.useState<Set<string>>(new Set());
  const [expandedGroups, setExpandedGroups] = React.useState<Set<string>>(new Set());
  const [visibleRows, setVisibleRows] = React.useState(initialRows);

  // A window switch (24h/7d/30d) is a fresh view of the ledger — start it
  // back at the top instead of carrying over however far a previous window
  // had been expanded.
  React.useEffect(() => {
    setVisibleRows(initialRows);
  }, [windowValue, initialRows]);

  const toggleExpand = React.useCallback((id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const toggleGroup = React.useCallback((id: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  // Progressive disclosure, not a nested scroll region: the page scrolls,
  // this table just grows. Grouping (buildDisplayItems) runs on the visible
  // slice only, so a "SHOW MORE" click never re-buckets rows already on
  // screen into a different group.
  const visibleEntries = React.useMemo(() => entries.slice(0, visibleRows), [entries, visibleRows]);
  const remainingCount = entries.length - visibleEntries.length;
  const nextRevealCount = Math.min(40, remainingCount);
  const displayItems = React.useMemo(() => buildDisplayItems(visibleEntries), [visibleEntries]);
  const flatRows = React.useMemo(
    () => flattenDisplayItems(displayItems, expandedGroups),
    [displayItems, expandedGroups],
  );

  const handleRetry = React.useCallback(() => {
    if (onRetry) onRetry();
    else if (typeof window !== 'undefined') window.location.reload();
  }, [onRetry]);

  const subtitle = `Incidents and AI decisions · last ${windowValue}`;

  if (error) {
    return (
      <Panel variant="default" padding="none" as="section" className="col-span-12">
        <SectionHeader flush title="LEDGER" subtitle={subtitle} />
        <EmptyState
          size="sm"
          title="Could not load the ledger"
          description="The timeline endpoint did not answer. Detection is unaffected — this is a display failure."
          action={
            <button
              type="button"
              onClick={handleRetry}
              className="rounded-sm px-2 py-1 text-[12px] font-semibold text-[color:var(--brand-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] hover:underline"
            >
              Retry
            </button>
          }
        />
      </Panel>
    );
  }

  const showEmpty = !loading && entries.length === 0;

  return (
    <Panel variant="default" padding="none" as="section" className="col-span-12" aria-busy={loading}>
      <SectionHeader flush title="LEDGER" subtitle={subtitle} count={`${entries.length} entries`} />

      <div>
        <table className="w-full table-fixed border-collapse">
          <caption className="sr-only">Recent incidents and AI decisions</caption>
          {/* Sticky only when the table is genuinely taller than the viewport it
              would scroll through. A sticky thead inside a SHORT table has too
              little containing-block room to travel, so it lands pinned mid-table
              and paints over a real data row (reproduced: a whole AUDIT row was
              hidden underneath it). Below the threshold the header just scrolls
              with the page, which is the correct behaviour when the whole table
              already fits on screen. */}
          <thead
            className={cn(
              'bg-card',
              flatRows.length >= STICKY_HEAD_MIN_ROWS && 'sticky top-[var(--sticky-top)] z-10',
            )}
          >
            <tr className="h-[34px]">
              <th scope="col" className={TH_CLASS} style={{ width: COL_TIME }}>
                Time
              </th>
              <th scope="col" className={TH_CLASS} style={{ width: COL_SEVERITY }}>
                Severity
              </th>
              <th
                scope="col"
                className={cn(TH_CLASS, 'max-[719px]:hidden')}
                style={{ width: COL_TYPE }}
              >
                Type
              </th>
              <th scope="col" className={TH_CLASS}>
                Event
              </th>
            </tr>
          </thead>
          <tbody>
            {loading &&
              Array.from({ length: 8 }).map((_, i) => (
                <LedgerSkeletonRow key={i} last={i === 7} />
              ))}

            {!loading && showEmpty && (
              <LedgerEmptyRow windowValue={windowValue} colSpan={4} />
            )}

            {!loading &&
              !showEmpty &&
              flatRows.map((row, i) => {
                const isLast = i === flatRows.length - 1;
                if (row.kind === 'groupHeader') {
                  return (
                    <LedgerGroupRow
                      key={row.key}
                      group={row.group}
                      isLast={isLast}
                      expanded={row.expanded}
                      onToggle={() => toggleGroup(row.group.id)}
                    />
                  );
                }
                const entry = row.entry;
                return (
                  <LedgerRow
                    key={row.key}
                    entry={entry}
                    isLast={isLast}
                    expanded={expandedIds.has(entry.id)}
                    onToggleExpand={() => toggleExpand(entry.id)}
                    nested={row.kind === 'nested'}
                  />
                );
              })}
          </tbody>
        </table>

        {!loading && !showEmpty && remainingCount > 0 && (
          <button
            type="button"
            onClick={() => setVisibleRows((n) => n + 40)}
            className="h-9 w-full border-t border-[var(--border)] font-mono text-[11px] uppercase tracking-[0.12em] text-[var(--brand-text)] hover:bg-[color-mix(in_oklab,var(--brand)_6%,transparent)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] transition-colors duration-150"
          >
            Show {nextRevealCount} more
          </button>
        )}
      </div>
    </Panel>
  );
}

export default Ledger;
