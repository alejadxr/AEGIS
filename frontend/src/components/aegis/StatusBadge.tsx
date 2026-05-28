'use client';

import * as React from 'react';
import { cn } from '@/lib/utils';

/**
 * StatusBadge — single source of truth for severity / status pills.
 *
 * Replaces 12+ inline pill implementations. Pairs color with icon AND text
 * label to satisfy color-not-only (a11y priority 1).
 *
 * Variants tinted via color-mix(in oklab,...) so they read consistently in
 * light and dark mode (no raw hex anywhere).
 */
export type StatusVariant =
  | 'muted'
  | 'info'
  | 'success'
  | 'warning'
  | 'danger'
  | 'critical'
  | 'accent';

export type StatusSize = 'sm' | 'md';

export interface StatusBadgeProps {
  variant?: StatusVariant;
  size?: StatusSize;
  icon?: React.ReactNode;
  /** When true (default), a colored dot renders at the start of the badge. */
  dot?: boolean;
  /** Pulse the dot — use for "live" / "active" states. */
  pulse?: boolean;
  children: React.ReactNode;
  className?: string;
  /** Optional aria-label override (otherwise the text content is used). */
  'aria-label'?: string;
  title?: string;
}

const VARIANT_TOKEN: Record<StatusVariant, string> = {
  muted: 'var(--muted-foreground)',
  info: 'var(--chart-5, #22D3EE)',
  success: 'var(--success)',
  warning: 'var(--warning)',
  danger: 'var(--danger)',
  critical: 'var(--danger)',
  accent: 'var(--brand-accent)',
};

const SIZE_CLASS: Record<StatusSize, string> = {
  sm: 'px-1.5 py-[2px] text-[10px] gap-1',
  md: 'px-2 py-[3px] text-[11px] gap-1.5',
};

export function StatusBadge({
  variant = 'muted',
  size = 'md',
  icon,
  dot = true,
  pulse = false,
  children,
  className,
  title,
  ...rest
}: StatusBadgeProps) {
  const token = VARIANT_TOKEN[variant];
  return (
    <span
      role="status"
      title={title}
      className={cn(
        'inline-flex items-center rounded-md font-medium uppercase tracking-[0.08em]',
        'border whitespace-nowrap select-none',
        SIZE_CLASS[size],
        variant === 'critical' && 'font-semibold',
        className,
      )}
      style={{
        background: `color-mix(in oklab, ${token} 14%, transparent)`,
        borderColor: `color-mix(in oklab, ${token} 28%, transparent)`,
        color: token,
      }}
      {...rest}
    >
      {dot && !icon && (
        <span
          aria-hidden
          className={cn(
            'w-1.5 h-1.5 rounded-full shrink-0',
            pulse && 'animate-pulse',
          )}
          style={{ background: token }}
        />
      )}
      {icon && (
        <span aria-hidden className="shrink-0 inline-flex">
          {icon}
        </span>
      )}
      <span className="truncate">{children}</span>
    </span>
  );
}
