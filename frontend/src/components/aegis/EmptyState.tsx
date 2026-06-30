'use client';

import * as React from 'react';
import { cn } from '@/lib/utils';

/**
 * EmptyState — universal "no data yet" tile for lists, tables, charts.
 *
 * Rules: aria-labels (role="status"), focus-states inherited by action slot,
 * progressive-loading partner (use after loading completes with empty result).
 */
export interface EmptyStateProps {
  icon?: React.ReactNode;
  title: React.ReactNode;
  description?: React.ReactNode;
  action?: React.ReactNode;
  /** Padded vertical layout. */
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const SIZE_CLASS = {
  sm: 'py-6 gap-1',
  md: 'py-10 gap-2',
  lg: 'py-16 gap-3',
} as const;

export function EmptyState({
  icon,
  title,
  description,
  action,
  size = 'md',
  className,
}: EmptyStateProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        'flex flex-col items-center justify-center text-center px-5',
        SIZE_CLASS[size],
        className,
      )}
    >
      {icon && (
        <div className="text-muted-foreground/40 mb-1" aria-hidden>
          {icon}
        </div>
      )}
      <p className="text-[12px] text-foreground/80 font-medium">{title}</p>
      {description && (
        <p className="text-[11px] text-muted-foreground/60 max-w-[36ch] leading-relaxed">
          {description}
        </p>
      )}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}
