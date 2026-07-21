'use client';

import { ChevronDown } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn, formatRelativeTime } from '@/lib/utils';
import { Panel, SectionHeader, DataRow } from '@/components/aegis';

/**
 * WatchPanel — ENFORCEMENT + COVERAGE + BLIND SPOTS.
 *
 * Full rewrite. The previous version re-printed the same four counters
 * VerdictLine already prints (two of which are zero) and decorated them
 * with four TrendChips that were structurally always "0" — the backend has
 * never returned assets_trend/vulns_trend/incidents_trend/interactions_trend,
 * api.ts invented them in its TS type, and the chips rendered a fabricated
 * value forever. TrendChip is deleted; nothing here reads a *_trend field.
 *
 * This component never fetches. The parent page owns every API call and
 * passes results straight through as props:
 *   - api.firewall.blocked()  -> blockedIps / piReachable
 *   - api.firewall.stats()    -> realFirewallActive
 *   - api.dashboard.overview()-> actionsExecuted30d / honeypotHits30d /
 *                                 openVulnerabilities
 *   - api.surface.assets()    -> totalAssets / activeAssets / lastScanAt
 *   - api.dashboard.monitoredApps() -> apps
 *   - api.phantom.honeypots() -> honeypotsRunning
 *
 * Three regions, separated by a full-bleed border-t, in this order:
 *   A. ENFORCEMENT  — proof of life: IPs the firewall is holding right now,
 *      Pi executor / system firewall reachability, and the 30d action count.
 *   B. COVERAGE     — what is under watch: assets, apps, decoys.
 *   C. BLIND SPOTS  — honest zeros stated plainly. This region's job is to
 *      render "0" as a real finding, never as a hole to hide — it is never
 *      empty and a zero here is neither colour-coded good nor bad.
 *
 * Null vs. zero is load-bearing throughout: `null` means "we could not ask",
 * a number (including 0) means "we asked and this is the honest answer".
 * Region A never collapses "cannot reach the firewall" into a fake "0".
 *
 * MOBILE (<md): this panel is tall (~600px of stacked regions), and on a
 * phone it is being promoted to the #2 scroll position (see dashboard/page.tsx),
 * so a collapsed shape matters. Below md the three regions become:
 *   - a static 3-up strip (~96px) answering "is enforcement running" at a
 *     glance: IPs blocked now, Pi/firewall up-or-down, actions in 30d.
 *   - a native <details> disclosure, closed by default, holding the
 *     existing COVERAGE and BLIND SPOTS blocks verbatim.
 * The full EnforcementRegion (blocked-IP list, StatusLines, IP grid) is not
 * shown on mobile — the strip supersedes it — but the element is rendered
 * once and hidden via a wrapper, never duplicated or forked.
 * Desktop (>=md) is byte-for-byte the same three bordered regions as before;
 * every mobile addition is gated on wrapper elements via md:hidden /
 * hidden md:block pairs.
 */

export interface WatchPanelApp {
  name: string;
  status: string;
  open_incidents: number;
  last_activity: string | null;
  resolved_count: number;
}

export interface WatchPanelProps {
  /** firewall.blocked().items mapped to .ip. null = fetch failed. */
  blockedIps: string[] | null;
  /** firewall.blocked().pi_reachable */
  piReachable: boolean | null;
  /** firewall.stats().real_firewall_active */
  realFirewallActive: boolean | null;
  /** overview.actions_taken — executed actions, trailing 30d. */
  actionsExecuted30d: number | null;
  totalAssets: number;
  /** assets.filter(a => a.status === 'active').length. null = assets fetch failed. */
  activeAssets: number | null;
  apps: WatchPanelApp[];
  /** honeypots.filter(h => h.status === 'running').length. null = fetch failed. */
  honeypotsRunning: number | null;
  /** overview.honeypot_interactions — backend bounds this to 30d (dashboard.py:120-123). */
  honeypotHits30d: number;
  /** overview.open_vulnerabilities */
  openVulnerabilities: number;
  /** max(assets[].last_scan_at) or null. */
  lastScanAt: string | null;
  loading?: boolean;
  /** true when either firewall call rejected — swaps region A for an error state. */
  firewallError?: boolean;
}

// ---------------------------------------------------------------------------
// Shared bits
// ---------------------------------------------------------------------------

/** Static skeleton bar — no animation, per the zero-idle-motion rule. */
function SkeletonBar({ w, h = '11px', className }: { w: string; h?: string; className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={cn('inline-block rounded bg-muted opacity-30', className)}
      style={{ width: w, height: h }}
    />
  );
}

/** dot + label + value readout, tri-state honest (true / false / unknown). */
function StatusLine({
  label,
  state,
  trueText,
  falseText,
}: {
  label: string;
  state: boolean | null;
  trueText: string;
  falseText: string;
}) {
  const dotColor =
    state === true ? 'var(--sev-low)' : state === false ? 'var(--sev-critical)' : 'var(--muted-foreground)';
  const valueText = state === true ? trueText : state === false ? falseText : 'unknown';

  return (
    <div className="flex items-center gap-2 text-[12px]">
      <span aria-hidden="true" className="h-[6px] w-[6px] shrink-0 rounded-full" style={{ background: dotColor }} />
      <span className="text-muted-foreground">{label}</span>
      <span className="font-medium text-foreground">{valueText}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// REGION A — ENFORCEMENT
// ---------------------------------------------------------------------------

function EnforcementRegion({
  blockedIps,
  piReachable,
  realFirewallActive,
  actionsExecuted30d,
  loading,
  firewallError,
}: Pick<
  WatchPanelProps,
  'blockedIps' | 'piReachable' | 'realFirewallActive' | 'actionsExecuted30d' | 'loading' | 'firewallError'
>) {
  if (loading) {
    return (
      <div className="px-5 py-4">
        <SkeletonBar w="64px" h="34px" />
        <div className="mt-2">
          <SkeletonBar w="120px" />
        </div>
        <div className="mt-4 flex flex-col gap-2">
          <SkeletonBar w="150px" h="12px" />
          <SkeletonBar w="170px" h="12px" />
        </div>
        <div className="mt-4 grid grid-cols-2 gap-x-3 gap-y-1.5">
          {Array.from({ length: 8 }).map((_, i) => (
            <SkeletonBar key={i} w="72px" h="10px" />
          ))}
        </div>
      </div>
    );
  }

  // "Cannot reach the firewall" and "0 blocked" are opposite facts — never
  // collapse the former into the latter.
  const unavailable = firewallError === true || blockedIps === null;
  const ips = blockedIps ?? [];
  const isEmpty = !unavailable && ips.length === 0;

  const numeralClass = unavailable
    ? 'text-foreground'
    : isEmpty
      ? 'text-muted-foreground'
      : 'text-[var(--brand-text)]';

  return (
    <div className="px-5 py-4">
      <span className={cn('font-mono text-[34px] font-semibold leading-none tabular-nums', numeralClass)}>
        {unavailable ? '—' : ips.length}
      </span>

      {unavailable ? (
        <p className="mt-1.5 text-[12px] text-[var(--sev-high)]">Firewall status unavailable</p>
      ) : (
        <p className="mt-1.5 text-[11px] uppercase tracking-[0.14em] text-muted-foreground">IPS BLOCKED NOW</p>
      )}

      <div className="mt-4 flex flex-col gap-2">
        <StatusLine label="Pi executor" state={piReachable} trueText="reachable" falseText="unreachable" />
        <StatusLine label="System firewall" state={realFirewallActive} trueText="active" falseText="inactive" />
      </div>

      {!unavailable &&
        (isEmpty ? (
          <p className="mt-4 text-[12px] text-muted-foreground">No IPs currently held.</p>
        ) : (
          <div className="mt-4 grid grid-cols-2 gap-x-3 gap-y-1.5">
            {ips.slice(0, 12).map((ip, idx) => (
              <span key={`${ip}-${idx}`} className="truncate font-mono tabular-nums text-[10.5px] text-muted-foreground">
                {ip}
              </span>
            ))}
            {ips.length > 12 && (
              <span className="font-mono tabular-nums text-[10.5px] text-muted-foreground">
                +{ips.length - 12} more
              </span>
            )}
          </div>
        ))}

      <p className="mt-4 font-mono text-[11px] text-muted-foreground">
        {actionsExecuted30d != null ? actionsExecuted30d.toLocaleString() : '—'} actions executed · 30d
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// REGION B — COVERAGE
// ---------------------------------------------------------------------------

function CoverageRow({
  label,
  value,
  subline,
  borderless,
}: {
  label: string;
  value: string;
  subline?: string;
  borderless?: boolean;
}) {
  return (
    <div>
      <DataRow
        density="compact"
        borderless={borderless}
        leading={<span className="text-[12px] font-normal text-muted-foreground">{label}</span>}
        trailing={
          <span className="font-mono text-[20px] font-semibold tracking-[-0.6px] tabular-nums text-foreground">
            {value}
          </span>
        }
      />
      {subline && (
        <div className="px-4 sm:px-5 pb-2.5 font-mono tabular-nums text-[10px] leading-relaxed text-muted-foreground">
          {subline}
        </div>
      )}
    </div>
  );
}

function CoverageRegion({
  totalAssets,
  activeAssets,
  apps,
  honeypotsRunning,
  loading,
}: Pick<WatchPanelProps, 'totalAssets' | 'activeAssets' | 'apps' | 'honeypotsRunning' | 'loading'>) {
  if (loading) {
    return (
      <div className="px-4 sm:px-5 py-4">
        <div className="flex flex-col gap-3">
          {['Assets watched', 'Apps tailed', 'Decoys deployed'].map((label) => (
            <div key={label} className="flex items-center justify-between">
              <span className="text-[12px] font-normal text-muted-foreground">{label}</span>
              <SkeletonBar w="32px" h="20px" />
            </div>
          ))}
        </div>
        <div className="mt-4 flex flex-wrap gap-x-2 gap-y-1.5">
          {Array.from({ length: 6 }).map((_, i) => (
            <SkeletonBar key={i} w="56px" h="11px" />
          ))}
        </div>
      </div>
    );
  }

  const onlineApps = apps.filter((a) => a.status === 'online').length;

  return (
    <div>
      <CoverageRow
        label="Assets watched"
        value={String(totalAssets)}
        subline={activeAssets != null ? `${activeAssets} active · ${totalAssets - activeAssets} inactive` : undefined}
        borderless
      />
      <CoverageRow label="Apps tailed" value={String(apps.length)} subline={`${onlineApps} online`} />
      <CoverageRow
        label="Decoys deployed"
        value={honeypotsRunning != null ? String(honeypotsRunning) : '—'}
        subline={honeypotsRunning != null ? 'running' : undefined}
      />

      {apps.length > 0 && (
        <div className="px-4 sm:px-5 pb-4 pt-2 flex flex-wrap gap-x-2 gap-y-1.5">
          {apps.map((app, idx) => (
            <span key={`${app.name}-${idx}`} className="inline-flex items-center gap-1.5">
              <span
                aria-hidden="true"
                className={cn(
                  'h-[5px] w-[5px] shrink-0 rounded-full',
                  app.status === 'online' ? 'bg-[var(--sev-low)]' : 'bg-[var(--muted-foreground)]',
                )}
              />
              <span className="font-mono text-[10.5px] text-muted-foreground">{app.name}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// REGION C — BLIND SPOTS
// ---------------------------------------------------------------------------

function BlindSpotsRegion({
  honeypotHits30d,
  honeypotsRunning,
  openVulnerabilities,
  totalAssets,
  lastScanAt,
  loading,
}: Pick<
  WatchPanelProps,
  'honeypotHits30d' | 'honeypotsRunning' | 'openVulnerabilities' | 'totalAssets' | 'lastScanAt' | 'loading'
>) {
  if (loading) {
    return (
      <div className="px-4 sm:px-5 py-4 flex flex-col gap-4">
        {[0, 1].map((i) => (
          <div key={i}>
            <SkeletonBar w="180px" h="13px" />
            <div className="mt-1.5">
              <SkeletonBar w="240px" h="11px" />
            </div>
          </div>
        ))}
      </div>
    );
  }

  const honeypotLine1 = `${honeypotHits30d} honeypot contact${honeypotHits30d === 1 ? '' : 's'} · 30d`;
  const honeypotLine2 =
    honeypotHits30d === 0
      ? honeypotsRunning != null
        ? `${honeypotsRunning} decoy${honeypotsRunning === 1 ? '' : 's'} ${honeypotsRunning === 1 ? 'is' : 'are'} live and none has been touched. Nothing is probing the deception layer.`
        : 'None has been touched. Nothing is probing the deception layer.'
      : honeypotsRunning != null
        ? `Recorded across ${honeypotsRunning} live decoy${honeypotsRunning === 1 ? '' : 's'}. Review Phantom for detail.`
        : 'Recorded against the deception layer. Review Phantom for detail.';

  const vulnLine1 = `${openVulnerabilities} open vulnerabilit${openVulnerabilities === 1 ? 'y' : 'ies'}`;
  const vulnLine2 = `Across ${totalAssets} asset${totalAssets === 1 ? '' : 's'}${
    lastScanAt ? `, last scan ${formatRelativeTime(lastScanAt)}` : ''
  }.`;

  return (
    <div className="px-4 sm:px-5 py-4 flex flex-col gap-4">
      <div>
        <p className="text-[13px] text-foreground">{honeypotLine1}</p>
        <p className="mt-0.5 text-[11px] leading-[15px] text-muted-foreground">{honeypotLine2}</p>
      </div>
      <div>
        <p className="text-[13px] text-foreground">{vulnLine1}</p>
        <p className="mt-0.5 text-[11px] leading-[15px] text-muted-foreground">{vulnLine2}</p>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// MOBILE — enforcement strip (<md only)
// ---------------------------------------------------------------------------

/** One cell of the 3-up mobile strip. Value/label stack, 72px tall. */
function StripCell({
  value,
  valueClassName,
  label,
  labelClassName,
  children,
}: {
  value?: ReactNode;
  valueClassName?: string;
  label: string;
  labelClassName?: string;
  children?: ReactNode;
}) {
  return (
    <div className="flex min-h-[72px] flex-col items-start gap-1 px-3 py-3">
      {children ?? (
        <span
          className={cn(
            'font-mono text-[22px] font-semibold leading-[24px] tabular-nums text-foreground',
            valueClassName,
          )}
        >
          {value}
        </span>
      )}
      <span className={cn('text-[10px] uppercase tracking-[0.1em] text-muted-foreground', labelClassName)}>
        {label}
      </span>
    </div>
  );
}

/** dot + word readout for the strip's ENFORCER cell — colour is never the sole signal. */
function StripStatus({ ok, onText, offText }: { ok: boolean | null; onText: string; offText: string }) {
  return (
    <span className="flex items-center gap-1.5 font-mono text-[11px] leading-[14px] text-foreground">
      <span
        aria-hidden="true"
        className="h-[6px] w-[6px] shrink-0 rounded-full"
        style={{ background: ok ? 'var(--success)' : 'var(--danger)' }}
      />
      {ok ? onText : offText}
    </span>
  );
}

function MobileEnforcementStrip({
  blockedIps,
  piReachable,
  realFirewallActive,
  actionsExecuted30d,
  loading,
  firewallError,
}: Pick<
  WatchPanelProps,
  'blockedIps' | 'piReachable' | 'realFirewallActive' | 'actionsExecuted30d' | 'loading' | 'firewallError'
>) {
  if (loading) {
    return (
      <div className="grid grid-cols-3 divide-x divide-[var(--border)]" aria-hidden="true">
        {[0, 1, 2].map((i) => (
          <div key={i} className="flex min-h-[72px] flex-col justify-center gap-1.5 px-3 py-3">
            <SkeletonBar w="40px" h="22px" />
            <SkeletonBar w="56px" h="9px" />
          </div>
        ))}
      </div>
    );
  }

  const unavailable = firewallError === true || blockedIps === null;
  const ips = blockedIps ?? [];

  return (
    <div className="grid grid-cols-3 divide-x divide-[var(--border)]">
      <StripCell
        value={unavailable ? '—' : ips.length}
        valueClassName={unavailable ? 'text-[var(--sev-high)]' : undefined}
        label={unavailable ? 'FIREWALL UNAVAILABLE' : 'IPS BLOCKED'}
        labelClassName={unavailable ? 'text-[var(--sev-high)]' : undefined}
      />
      <StripCell label="ENFORCEMENT">
        <span className="flex flex-col gap-1">
          <StripStatus ok={piReachable === true} onText="PI UP" offText="PI DOWN" />
          <StripStatus ok={realFirewallActive === true} onText="FW ACTIVE" offText="FW OFF" />
        </span>
      </StripCell>
      <StripCell
        value={actionsExecuted30d != null ? actionsExecuted30d.toLocaleString() : '—'}
        label="ACTIONS 30D"
      />
    </div>
  );
}

/** Coverage + Blind Spots, rendered together — reused verbatim on desktop and inside the mobile disclosure. */
function CoverageAndBlindSpots(
  props: Pick<
    WatchPanelProps,
    | 'totalAssets'
    | 'activeAssets'
    | 'apps'
    | 'honeypotsRunning'
    | 'honeypotHits30d'
    | 'openVulnerabilities'
    | 'lastScanAt'
    | 'loading'
  >,
) {
  return (
    <>
      <div className="border-t border-[var(--border)]">
        <SectionHeader flush title="COVERAGE" />
        <CoverageRegion
          totalAssets={props.totalAssets}
          activeAssets={props.activeAssets}
          apps={props.apps}
          honeypotsRunning={props.honeypotsRunning}
          loading={props.loading}
        />
      </div>
      <div className="border-t border-[var(--border)]">
        <SectionHeader flush title="BLIND SPOTS" />
        <BlindSpotsRegion
          honeypotHits30d={props.honeypotHits30d}
          honeypotsRunning={props.honeypotsRunning}
          openVulnerabilities={props.openVulnerabilities}
          totalAssets={props.totalAssets}
          lastScanAt={props.lastScanAt}
          loading={props.loading}
        />
      </div>
    </>
  );
}

function MobileCoverageDisclosure(
  props: Pick<
    WatchPanelProps,
    | 'totalAssets'
    | 'activeAssets'
    | 'apps'
    | 'honeypotsRunning'
    | 'honeypotHits30d'
    | 'openVulnerabilities'
    | 'lastScanAt'
    | 'loading'
  >,
) {
  return (
    <details className="group">
      <summary
        className={cn(
          'flex min-h-[44px] list-none items-center justify-between border-t border-[var(--border)] px-4 text-[12px] text-[var(--brand-text,var(--brand))]',
          '[&::-webkit-details-marker]:hidden',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--ring)]',
          props.loading && 'pointer-events-none opacity-50',
        )}
      >
        Coverage and blind spots
        <ChevronDown
          size={13}
          aria-hidden="true"
          className="shrink-0 motion-safe:transition-transform motion-safe:duration-150 group-open:rotate-180"
        />
      </summary>
      <CoverageAndBlindSpots {...props} />
    </details>
  );
}

// ---------------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------------

export function WatchPanel({
  blockedIps,
  piReachable,
  realFirewallActive,
  actionsExecuted30d,
  totalAssets,
  activeAssets,
  apps,
  honeypotsRunning,
  honeypotHits30d,
  openVulnerabilities,
  lastScanAt,
  loading = false,
  firewallError = false,
}: WatchPanelProps) {
  return (
    <Panel
      variant="default"
      padding="none"
      as="aside"
      aria-label="Enforcement and coverage"
      aria-busy={loading}
      className="col-span-12 lg:col-span-4 lg:sticky lg:top-[var(--sticky-top)] lg:z-10"
    >
      {loading && (
        <span className="sr-only" role="status">
          Loading watch panel data.
        </span>
      )}

      {/* HEADER — desktop keeps the original per-region "ENFORCEMENT" title;
          mobile gets one combined title so the collapsed disclosure below it
          is not orphaned under a header describing only a third of it. */}
      <SectionHeader flush title="ENFORCEMENT" className="hidden md:flex" />
      <SectionHeader flush title="ENFORCEMENT & COVERAGE" className="md:hidden" />

      {/* DESKTOP (>=md) — unchanged: full enforcement region under its own header. */}
      <div className="hidden md:block">
        <EnforcementRegion
          blockedIps={blockedIps}
          piReachable={piReachable}
          realFirewallActive={realFirewallActive}
          actionsExecuted30d={actionsExecuted30d}
          loading={loading}
          firewallError={firewallError}
        />
      </div>

      {/* MOBILE (<md) — 3-up strip supersedes the full enforcement region,
          followed by a closed-by-default disclosure for coverage/blind spots. */}
      <div className="md:hidden">
        <MobileEnforcementStrip
          blockedIps={blockedIps}
          piReachable={piReachable}
          realFirewallActive={realFirewallActive}
          actionsExecuted30d={actionsExecuted30d}
          loading={loading}
          firewallError={firewallError}
        />
        <MobileCoverageDisclosure
          totalAssets={totalAssets}
          activeAssets={activeAssets}
          apps={apps}
          honeypotsRunning={honeypotsRunning}
          honeypotHits30d={honeypotHits30d}
          openVulnerabilities={openVulnerabilities}
          lastScanAt={lastScanAt}
          loading={loading}
        />
      </div>

      {/* DESKTOP (>=md) — unchanged: COVERAGE + BLIND SPOTS under their own headers. */}
      <div className="hidden md:block">
        <CoverageAndBlindSpots
          totalAssets={totalAssets}
          activeAssets={activeAssets}
          apps={apps}
          honeypotsRunning={honeypotsRunning}
          honeypotHits30d={honeypotHits30d}
          openVulnerabilities={openVulnerabilities}
          lastScanAt={lastScanAt}
          loading={loading}
        />
      </div>
    </Panel>
  );
}

export default WatchPanel;
