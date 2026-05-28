'use client';

import * as React from 'react';
import Link from 'next/link';
import { cn } from '@/lib/utils';
import { Panel } from './Panel';

/**
 * KPI — large metric tile used in the dashboard hero row.
 *
 * Wraps <Panel> with the canonical KPI rhythm: small uppercase label, large
 * monospace tabular value, optional sub-text + delta + sparkline.
 *
 * Rules: tabular-nums for data, touch-target-size (min-h 112px), color-not-only
 * (tone dot + label), focus-states when href is set.
 */
export type KPITone = 'neutral' | 'accent' | 'danger' | 'warning' | 'success';

export interface KPIProps {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  /** Tone drives the dot + hover edge color. */
  tone?: KPITone;
  href?: string;
  /** Warm orange wash on the right edge — matches AEGIS hero KPI tile. */
  warm?: boolean;
  /** Optional sparkline / delta slot rendered at the bottom-right. */
  trend?: React.ReactNode;
  /** Optional delta slot (e.g. "+12%" or "-3"). */
  delta?: React.ReactNode;
  ariaLabel?: string;
  className?: string;
}

const TONE_DOT: Record<KPITone, string> = {
  neutral: 'bg-muted-foreground/40',
  accent: 'bg-[var(--brand-accent)]',
  danger: 'bg-[var(--danger)]',
  warning: 'bg-[var(--warning)]',
  success: 'bg-[var(--success)]',
};

const TONE_HOVER: Record<KPITone, string> = {
  neutral: 'hover:border-white/[0.12]',
  accent: 'hover:border-[var(--brand-accent)]/40',
  danger: 'hover:border-[var(--danger)]/40',
  warning: 'hover:border-[var(--warning)]/40',
  success: 'hover:border-[var(--success)]/40',
};

export function KPI({
  label,
  value,
  sub,
  tone = 'neutral',
  href,
  warm = false,
  trend,
  delta,
  ariaLabel,
  className,
}: KPIProps) {
  const body = (
    <Panel
      padding="md"
      className={cn(
        'group relative isolate flex flex-col justify-between',
        'min-h-[112px] sm:min-h-[120px]',
        'transition-[transform,border-color,box-shadow] duration-200',
        'hover:-translate-y-0.5 hover:shadow-[0_8px_24px_-12px_rgba(249,115,22,0.18)]',
        href &&
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand-accent)]/60 focus-visible:ring-offset-2 focus-visible:ring-offset-background',
        TONE_HOVER[tone],
        className,
      )}
      aria-label={ariaLabel ?? `${label}: ${typeof value === 'string' ? value : ''}`}
    >
      {warm && (
        <span
          aria-hidden
          className="pointer-events-none absolute inset-0 rounded-2xl opacity-60"
          style={{
            background:
              'radial-gradient(120% 80% at 110% 100%, rgba(249,115,22,0.10) 0%, rgba(249,115,22,0) 55%)',
          }}
        />
      )}

      <div className="relative flex items-center gap-2">
        <span className={cn('w-1.5 h-1.5 rounded-full shrink-0', TONE_DOT[tone])} aria-hidden />
        <span className="text-[10px] sm:text-[11px] font-medium uppercase tracking-[0.14em] text-muted-foreground truncate">
          {label}
        </span>
        {delta && (
          <span className="ml-auto text-[10px] font-mono tabular-nums text-muted-foreground/70">
            {delta}
          </span>
        )}
      </div>

      <div className="relative flex items-end justify-between gap-3">
        <div className="min-w-0">
          <p
            className="text-[24px] sm:text-[28px] lg:text-[30px] font-semibold leading-none tracking-[-0.02em] text-foreground tabular-nums truncate"
            style={{
              fontFamily:
                'var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace)',
            }}
          >
            {value}
          </p>
          {sub && (
            <p className="mt-2 text-[11px] text-muted-foreground/70 truncate">{sub}</p>
          )}
        </div>
        {trend && <div className="shrink-0 opacity-80">{trend}</div>}
      </div>
    </Panel>
  );

  if (href) {
    return (
      <Link href={href} className="block rounded-2xl focus:outline-none">
        {body}
      </Link>
    );
  }
  return body;
}
