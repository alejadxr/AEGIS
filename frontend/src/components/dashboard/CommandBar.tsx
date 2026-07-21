'use client';

import { Fragment, useEffect, useRef, useState, type KeyboardEvent } from 'react';
import Link from 'next/link';
import { Sun01Icon, Moon02Icon } from 'hugeicons-react';
import { X } from 'lucide-react';
import { cn, formatRelativeTime } from '@/lib/utils';

/**
 * CommandBar — the sticky 52px instrument strip that opens every dashboard
 * page. It is the ENTIRE replacement for the old 11-step blocking
 * "Welcome to AEGIS" modal (GuideTour): a one-click-dismissible 34px strip
 * instead of a full-screen scrim.
 *
 * Rules applied:
 *  - the-green-ban: DETECT's `var(--success)` dot is the ONLY sanctioned
 *    green on the page, and it is always paired with a text value
 *    ('ONLINE' / 'OFFLINE') — never colour alone.
 *  - colour-not-alone: every readout is dot + label + value, never a bare dot.
 *  - zero-idle-motion: no pulse/ping/shimmer anywhere, including the loading
 *    skeleton blocks (static opacity, no animate-pulse).
 *  - semantic-color-tokens only: no raw Tailwind palette utilities
 *    (text-red-400 etc.) — every colour is a CSS custom property, either via
 *    a themed Tailwind class (bg-brand-muted, text-muted-foreground, ...)
 *    or an arbitrary value that resolves to var(--token).
 *  - focus-states: relies on the global `*:focus-visible` rule in
 *    globals.css (2px solid var(--ring), 2px offset) — never overridden
 *    with `outline-none` here.
 *  - keyboard-operable: the time-window control is a real
 *    role="radiogroup" with roving tabindex and arrow-key navigation.
 *
 * NOTE for the integration agent: this component expects to be rendered
 * full-bleed (outside any max-w/px-* container), directly below TopNav, so
 * that "sticky top-16" (TopNav is sticky top-0 h-16) lines up flush and the
 * inner max-w-[1400px] mx-auto px-6 wrapper is the only horizontal
 * constraint. See the written report for the top-16 vs top-0 / role="banner"
 * duplicate-landmark notes.
 */

export type TimeWindow = '24h' | '7d' | '30d';

export interface CommandBarProps {
  /** From api.dashboard.monitoredApps().count. */
  monitoredApps: number;
  /** From api.dashboard.overview().total_assets. */
  totalAssets: number;
  /** ISO timestamp of the most recent timeline entry, or null. */
  lastEventAt: string | null;
  /** Current page-wide window. Lifted to page.tsx, syncs the ?window= query param. */
  window: TimeWindow;
  onWindowChange: (w: TimeWindow) => void;
  /** True until the first successful overview() response. */
  loading?: boolean;
  /** False when overview() rejected — drives the API health dot. */
  apiOnline: boolean;
}

const WINDOW_OPTIONS: Array<{ id: TimeWindow; label: string }> = [
  { id: '24h', label: '24H' },
  { id: '7d', label: '7D' },
  { id: '30d', label: '30D' },
];

export function CommandBar({
  monitoredApps,
  totalAssets,
  lastEventAt,
  window: activeWindow,
  onWindowChange,
  loading = false,
  apiOnline,
}: CommandBarProps) {
  const version = process.env.NEXT_PUBLIC_AEGIS_VERSION;

  const [showFirstRun, setShowFirstRun] = useState(false);

  useEffect(() => {
    try {
      if (!localStorage.getItem('aegis_guide_seen')) {
        setShowFirstRun(true);
      }
    } catch {
      // localStorage unavailable (private browsing, disabled storage) — keep hidden
    }
  }, []);

  const dismissFirstRun = () => {
    try {
      localStorage.setItem('aegis_guide_seen', '1');
    } catch {
      // ignore write failures — still hide for this session
    }
    setShowFirstRun(false);
  };

  const readouts: Array<{ id: string; dotColor: string; label: string; value: string }> = [
    {
      id: 'detect',
      // The ONLY sanctioned green on the page: a 6px dot paired with a text value.
      dotColor: apiOnline ? 'var(--success)' : 'var(--sev-critical, var(--danger))',
      label: 'DETECT',
      value: apiOnline ? 'ONLINE' : 'OFFLINE',
    },
    {
      id: 'watching',
      dotColor: 'var(--muted-foreground)',
      label: 'WATCHING',
      value: `${totalAssets} ASSETS`,
    },
    {
      id: 'apps',
      dotColor: 'var(--muted-foreground)',
      label: 'APPS',
      value: String(monitoredApps),
    },
    {
      id: 'last-event',
      dotColor: 'var(--muted-foreground)',
      label: 'LAST EVENT',
      value: lastEventAt ? formatRelativeTime(lastEventAt) : 'NONE',
    },
  ];

  // top-[var(--nav-h)], not top-16: TopNav measures 65px, so a hardcoded 64px
  // left a 1px sliver of page content showing through between the two bars.
  // The variable is defined once in dashboard/layout.tsx so the two cannot
  // drift apart again. Rendered as a plain <div>, not <header role="banner">:
  // TopNav already declares that landmark and two banners is an a11y violation.
  return (
    <>
    {/* Below md the strip scrolls away with the page; TopNav is the only
        pinned top chrome, and --sticky-top collapses to --nav-h in
        globals.css to match (nothing is pinned below TopNav on mobile). */}
    <div className="static w-full md:sticky md:top-[var(--nav-h)] md:z-30">
      <div
        className="border-b border-border"
        style={{
          background: 'color-mix(in oklab, var(--background) 82%, transparent)',
          backdropFilter: 'blur(12px)',
          WebkitBackdropFilter: 'blur(12px)',
        }}
      >
        <div className="max-w-[1400px] mx-auto px-4 md:px-6 h-[52px] flex items-center">
          {/* LEFT CLUSTER — hidden below md: TopNav already shows the AEGIS
              wordmark + version, so duplicating it here below md wasted the
              entire left slot on a phone. */}
          <div className="hidden md:flex items-center gap-[10px] shrink-0">
            <span className="font-sans font-semibold text-[15px] tracking-[-0.4px] text-foreground">
              AEGIS
            </span>
            {version && (
              <span className="font-mono text-[10px] text-muted-foreground tabular-nums">
                v{version}
              </span>
            )}
          </div>

          {/* Mobile-only: the DETECT readout is hidden below 900px on desktop,
              which left the whole bar duplicating TopNav's wordmark. Below md it
              is the ONLY thing in the left slot — the one fact that matters at 3am. */}
          <div className="md:hidden flex items-center min-w-0 shrink">
            <StatusReadout
              dotColor={readouts[0].dotColor}
              label={readouts[0].label}
              value={readouts[0].value}
              loading={loading}
            />
          </div>

          {/* CENTRE CLUSTER — hidden below 900px */}
          <div className="hidden min-[900px]:flex flex-1 items-center min-w-0 overflow-hidden px-4">
            {readouts.map((r, i) => (
              <Fragment key={r.id}>
                {i > 0 && (
                  <span
                    aria-hidden="true"
                    className="w-px h-4 shrink-0"
                    style={{ background: 'var(--border)', margin: '0 14px' }}
                  />
                )}
                <StatusReadout dotColor={r.dotColor} label={r.label} value={r.value} loading={loading} />
              </Fragment>
            ))}
          </div>

          {/* RIGHT CLUSTER */}
          <div className="flex items-center gap-2 shrink-0 ml-auto">
            <WindowControl value={activeWindow} onChange={onWindowChange} />
            <ThemeToggle />
          </div>
        </div>
      </div>
    </div>

      {/* FIRST-RUN STRIP — the entire replacement for the blocking 11-step modal.
          Deliberately OUTSIDE the sticky wrapper: while it lived inside, the
          sticky element measured 88px instead of 53px, so --sticky-top (118px)
          was 35px too small and the CommandBar painted over the top of the
          sticky WatchPanel. Out here the strip scrolls away normally and the
          pinned element keeps a constant height, which is also better UX for a
          dismissible tip. */}
      {showFirstRun && (
        <div
          className="w-full border-b"
          style={{
            background: 'color-mix(in oklab, var(--brand) 8%, transparent)',
            borderColor: 'color-mix(in oklab, var(--brand) 20%, transparent)',
          }}
        >
          <div className="max-w-[1400px] mx-auto px-4 md:px-6 min-h-[44px] md:h-[34px] py-2 md:py-0 flex items-center justify-between gap-3 md:gap-4">
            <p className="text-[12px] leading-[16px] font-normal text-foreground line-clamp-2 md:truncate md:leading-normal">
              New to AEGIS? An 11-step walkthrough explains every module.{' '}
              <Link
                href="/dashboard/guide"
                className="font-semibold text-[var(--brand-text,var(--brand))] underline-offset-2 hover:underline"
              >
                Open walkthrough →
              </Link>
            </p>
            <button
              type="button"
              onClick={dismissFirstRun}
              aria-label="Dismiss"
              className="tap-44 w-11 h-11 md:w-auto md:h-auto shrink-0 flex items-center justify-center text-muted-foreground hover:text-foreground transition-colors duration-150"
            >
              <X size={20} />
            </button>
          </div>
        </div>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Sub-components (module-private)
// ---------------------------------------------------------------------------

interface StatusReadoutProps {
  dotColor: string;
  label: string;
  value: string;
  loading?: boolean;
}

function StatusReadout({ dotColor, label, value, loading }: StatusReadoutProps) {
  return (
    <div className="flex items-center min-w-0">
      <span aria-hidden="true" className="w-[6px] h-[6px] rounded-full shrink-0" style={{ background: dotColor }} />
      <span className="ml-[6px] text-[10px] font-semibold uppercase tracking-[0.1em] text-muted-foreground shrink-0">
        {label}
      </span>
      {loading ? (
        <span
          aria-hidden="true"
          className="ml-[5px] w-[42px] h-[11px] rounded-[3px] shrink-0"
          style={{ background: 'var(--muted)', opacity: 0.45 }}
        />
      ) : (
        <span className="ml-[5px] text-[11px] font-mono tabular-nums text-foreground truncate">{value}</span>
      )}
    </div>
  );
}

function WindowControl({ value, onChange }: { value: TimeWindow; onChange: (w: TimeWindow) => void }) {
  const btnRefs = useRef<Array<HTMLButtonElement | null>>([]);

  const handleKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const idx = WINDOW_OPTIONS.findIndex((o) => o.id === value);
    if (idx === -1) return;
    let nextIdx: number | null = null;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
      nextIdx = (idx + 1) % WINDOW_OPTIONS.length;
    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
      nextIdx = (idx - 1 + WINDOW_OPTIONS.length) % WINDOW_OPTIONS.length;
    } else if (e.key === 'Home') {
      nextIdx = 0;
    } else if (e.key === 'End') {
      nextIdx = WINDOW_OPTIONS.length - 1;
    }
    if (nextIdx !== null) {
      e.preventDefault();
      const next = WINDOW_OPTIONS[nextIdx];
      onChange(next.id);
      btnRefs.current[nextIdx]?.focus();
    }
  };

  return (
    <div
      role="radiogroup"
      aria-label="Time window"
      onKeyDown={handleKeyDown}
      className="flex items-center gap-[2px] p-[2px] rounded-[8px] border border-border shrink-0"
    >
      {WINDOW_OPTIONS.map((opt, i) => {
        const active = opt.id === value;
        return (
          <button
            key={opt.id}
            ref={(el) => {
              btnRefs.current[i] = el;
            }}
            type="button"
            role="radio"
            aria-checked={active}
            tabIndex={active ? 0 : -1}
            onClick={() => onChange(opt.id)}
            className={cn(
              'h-[28px] px-[10px] max-md:h-[44px] max-md:min-w-[54px] max-md:px-[14px] rounded-[6px] flex items-center justify-center',
              'text-[11px] font-mono uppercase tracking-wide transition-colors duration-150',
              'motion-safe:active:scale-[0.97] motion-safe:duration-[120ms]',
              active
                ? 'bg-brand-muted text-[var(--brand-text,var(--brand))] font-semibold'
                : 'bg-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

function ThemeToggle() {
  const [isDark, setIsDark] = useState(true);

  useEffect(() => {
    const current = document.documentElement.getAttribute('data-theme');
    setIsDark(current !== 'light');
  }, []);

  const toggle = () => {
    const next = isDark ? 'light' : 'dark';
    setIsDark(!isDark);
    try {
      localStorage.setItem('aegis-theme', next);
    } catch {
      // ignore write failures — attribute change below still drives the UI
    }
    document.documentElement.setAttribute('data-theme', next);
  };

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label="Toggle theme"
      className={cn(
        'hidden md:flex w-8 h-8 shrink-0 items-center justify-center rounded-[8px]',
        'border border-border text-muted-foreground',
        'transition-colors duration-150',
        'hover:border-[var(--border-hover,var(--border-strong))] hover:text-foreground',
      )}
    >
      {isDark ? <Sun01Icon size={15} /> : <Moon02Icon size={15} />}
    </button>
  );
}
