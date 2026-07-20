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
 * Module column: the backend's TimelineEvent has no `module` field, so
 * page.tsx currently always sends `module: ''`. Rendering a whole column of
 * "—" teaches the eye to skip it. This component renders the Module column
 * only when at least one incoming entry actually carries a module value —
 * today that means the column simply doesn't render, and the Event column
 * reclaims the width instead.
 */

export interface LedgerEntry {
  id: string;
  type: string;
  title: string;
  description: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | null;
  module: string;
  timestamp: string;
}

type LedgerWindow = '24h' | '7d' | '30d';

export interface LedgerProps {
  entries: LedgerEntry[];
  /** Current page-wide window, mirrored in the header. */
  window: LedgerWindow;
  /** Widens the window from the empty state. */
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

const NEXT_WINDOW: Partial<Record<LedgerWindow, LedgerWindow>> = {
  '24h': '7d',
  '7d': '30d',
};

const COL_TIME = 110;
const COL_SEVERITY = 128;
const COL_MODULE = 120;

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
  /** Newest-first, mirrors the source order of `entries`. */
  members: LedgerEntry[];
}

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

const SKELETON_WIDTHS_FULL = [56, 64, 50, '55%'] as const;
const SKELETON_WIDTHS_COMPACT = [56, 64, '55%'] as const;

function LedgerSkeletonRow({ last, hasModuleData }: { last: boolean; hasModuleData: boolean }) {
  const widths = hasModuleData ? SKELETON_WIDTHS_FULL : SKELETON_WIDTHS_COMPACT;
  const colWidths = hasModuleData ? [COL_TIME, COL_SEVERITY, COL_MODULE] : [COL_TIME, COL_SEVERITY];
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
  onWindowChange,
  colSpan,
}: {
  windowValue: LedgerWindow;
  onWindowChange: (w: LedgerWindow) => void;
  colSpan: number;
}) {
  const next = NEXT_WINDOW[windowValue];
  return (
    <tr>
      <td colSpan={colSpan} className="h-[88px] px-4 text-center align-middle">
        <p className="font-mono text-[12px] leading-[16px] text-muted-foreground opacity-70">
          — no entries in the last {windowValue} —
        </p>
        {next ? (
          <button
            type="button"
            onClick={() => onWindowChange(next)}
            className="mt-1 rounded-sm text-[12px] font-semibold text-[color:var(--brand-text)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] hover:underline"
          >
            Widen to {next}
          </button>
        ) : (
          <p className="mt-1 font-mono text-[11px] leading-[16px] text-muted-foreground">
            Nothing recorded in 30 days.
          </p>
        )}
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
  hasModuleData: boolean;
  /** True for a row rendered under an expanded group — indented and
   * slightly muted so it visually reads as "detail of the row above". */
  nested?: boolean;
}

function LedgerRow({ entry, isLast, expanded, onToggleExpand, hasModuleData, nested = false }: LedgerRowProps) {
  const router = useRouter();
  const sevKey = severityKey(entry.severity);
  const sevColor = SEV_VAR[sevKey];
  const isIncident = entry.type === 'incident';
  const timeLabel = formatLedgerTime(entry.timestamp);
  const moduleLabel = entry.module ? entry.module.toLowerCase() : '—';

  const rowAriaLabel = `${timeLabel}, ${SEV_LABEL[sevKey]} severity, ${moduleLabel}, ${entry.title}${
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

      {hasModuleData && (
        <td
          className={cn('max-[719px]:hidden px-4 align-middle', cellBorder)}
          style={{ width: COL_MODULE }}
        >
          <span className="block truncate font-mono text-[11px] lowercase text-muted-foreground">
            {moduleLabel}
          </span>
        </td>
      )}

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
  hasModuleData: boolean;
  onToggle: () => void;
}

function LedgerGroupRow({ group, isLast, expanded, hasModuleData, onToggle }: LedgerGroupRowProps) {
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

      {hasModuleData && (
        <td
          className={cn('max-[719px]:hidden px-4 align-middle', cellBorder)}
          style={{ width: COL_MODULE }}
        >
          <span className="block truncate font-mono text-[11px] lowercase text-muted-foreground">—</span>
        </td>
      )}

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
  onWindowChange,
  loading = false,
  error = false,
  onRetry,
}: LedgerProps) {
  const [expandedIds, setExpandedIds] = React.useState<Set<string>>(new Set());
  const [expandedGroups, setExpandedGroups] = React.useState<Set<string>>(new Set());

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

  // Only render the Module column at all if something in the current data
  // actually populates it — see the class doc comment above.
  const hasModuleData = React.useMemo(
    () => entries.some((e) => !!e.module && e.module.trim().length > 0),
    [entries],
  );

  const displayItems = React.useMemo(() => buildDisplayItems(entries), [entries]);
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

      <div className="max-h-[420px] overflow-y-auto">
        <table className="w-full table-fixed border-collapse">
          <caption className="sr-only">Recent incidents and AI decisions</caption>
          <thead className="sticky top-0 z-10 bg-card">
            <tr className="h-[34px]">
              <th scope="col" className={TH_CLASS} style={{ width: COL_TIME }}>
                Time
              </th>
              <th scope="col" className={TH_CLASS} style={{ width: COL_SEVERITY }}>
                Severity
              </th>
              {hasModuleData && (
                <th
                  scope="col"
                  className={cn(TH_CLASS, 'max-[719px]:hidden')}
                  style={{ width: COL_MODULE }}
                >
                  Module
                </th>
              )}
              <th scope="col" className={TH_CLASS}>
                Event
              </th>
            </tr>
          </thead>
          <tbody>
            {loading &&
              Array.from({ length: 8 }).map((_, i) => (
                <LedgerSkeletonRow key={i} last={i === 7} hasModuleData={hasModuleData} />
              ))}

            {!loading && showEmpty && (
              <LedgerEmptyRow
                windowValue={windowValue}
                onWindowChange={onWindowChange}
                colSpan={hasModuleData ? 4 : 3}
              />
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
                      hasModuleData={hasModuleData}
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
                    hasModuleData={hasModuleData}
                    nested={row.kind === 'nested'}
                  />
                );
              })}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

export default Ledger;
