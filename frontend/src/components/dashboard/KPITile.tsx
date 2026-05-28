'use client';

import Link from 'next/link';
import { cn } from '@/lib/utils';

interface KPITileProps {
  label: string;
  value: string | number;
  sub?: string;
  tone?: 'neutral' | 'accent' | 'danger' | 'warning' | 'success';
  href?: string;
  warm?: boolean; // adds the warm orange wash from image 1
  ariaLabel?: string;
}

/**
 * KPITile — incident-first KPI card matching image 1.
 *
 * Pattern: small uppercase label (top-left), large monospace tabular value (centered),
 * optional sub-text (bottom-left). Subtle warm gradient on the right edge when warm=true.
 *
 * Rules applied: number-tabular, color-semantic, focus-states, touch-target-size,
 * text-styles-system. Touch target ≥44px via min-h.
 */
export function KPITile({
  label,
  value,
  sub,
  tone = 'neutral',
  href,
  warm = false,
  ariaLabel,
}: KPITileProps) {
  const toneRing: Record<NonNullable<KPITileProps['tone']>, string> = {
    neutral: 'hover:border-white/[0.12]',
    accent: 'hover:border-[var(--brand-accent)]/40',
    danger: 'hover:border-[var(--danger)]/40',
    warning: 'hover:border-[var(--warning)]/40',
    success: 'hover:border-[var(--success)]/40',
  };

  const toneDot: Record<NonNullable<KPITileProps['tone']>, string> = {
    neutral: 'bg-muted-foreground/40',
    accent: 'bg-[var(--brand-accent)]',
    danger: 'bg-[var(--danger)]',
    warning: 'bg-[var(--warning)]',
    success: 'bg-[var(--success)]',
  };

  const inner = (
    <div
      className={cn(
        'group relative isolate flex flex-col justify-between',
        'min-h-[112px] sm:min-h-[120px] rounded-2xl p-4 sm:p-5',
        'bg-card border border-border',
        'transition-[transform,border-color,box-shadow] duration-200',
        'hover:-translate-y-0.5 hover:shadow-[0_8px_24px_-12px_rgba(249,115,22,0.18)]',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand-accent)]/60 focus-visible:ring-offset-2 focus-visible:ring-offset-background',
        toneRing[tone],
      )}
      aria-label={ariaLabel ?? `${label}: ${value}`}
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
        <span className={cn('w-1.5 h-1.5 rounded-full', toneDot[tone])} aria-hidden />
        <span className="text-[10px] sm:text-[11px] font-medium uppercase tracking-[0.14em] text-muted-foreground">
          {label}
        </span>
      </div>

      <div className="relative">
        <p
          className="text-[24px] sm:text-[28px] lg:text-[30px] font-semibold leading-none tracking-[-0.02em] text-foreground tabular-nums"
          style={{ fontFamily: 'var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace)' }}
        >
          {value}
        </p>
        {sub && (
          <p className="mt-2 text-[11px] text-muted-foreground/70 truncate">
            {sub}
          </p>
        )}
      </div>
    </div>
  );

  if (href) {
    return (
      <Link
        href={href}
        className="block rounded-2xl focus:outline-none"
      >
        {inner}
      </Link>
    );
  }
  return inner;
}
