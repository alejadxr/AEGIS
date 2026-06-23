'use client';

import * as React from 'react';
import { cn } from '@/lib/utils';

/**
 * DataRow — table-style row for asset / IP / incident / action lists.
 *
 * Provides consistent padding, hover state, minimum touch height, and an
 * action slot pinned right. Used in <Panel> list bodies.
 *
 * Rules: touch-target-size (min-h 44px), focus-states, semantic <div role="row">.
 */
export interface DataRowProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Left-aligned primary content (icon + label/sub). */
  leading?: React.ReactNode;
  /** Optional center content (metadata, columns). */
  children?: React.ReactNode;
  /** Right-aligned action area (buttons, badges, counts). */
  trailing?: React.ReactNode;
  /** Visual + a11y: render as button-like row. */
  interactive?: boolean;
  /** Remove top border on the first row of a list. */
  borderless?: boolean;
  /** Density: comfortable | compact */
  density?: 'comfortable' | 'compact';
}

const DENSITY_CLASS = {
  comfortable: 'min-h-[52px] py-3',
  compact: 'min-h-[44px] py-2.5',
} as const;

export const DataRow = React.forwardRef<HTMLDivElement, DataRowProps>(function DataRow(
  {
    leading,
    children,
    trailing,
    interactive = false,
    borderless = false,
    density = 'comfortable',
    className,
    ...rest
  },
  ref,
) {
  return (
    <div
      ref={ref}
      role="row"
      tabIndex={interactive ? 0 : undefined}
      className={cn(
        'group flex items-center gap-3 px-4 sm:px-5',
        DENSITY_CLASS[density],
        !borderless && 'border-t border-border',
        'transition-colors',
        interactive && [
          'cursor-pointer hover:bg-white/[0.02]',
          'focus-visible:outline-none focus-visible:bg-white/[0.03]',
          'focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-[var(--brand-accent)]/40',
        ],
        !interactive && 'hover:bg-white/[0.02]',
        className,
      )}
      {...rest}
    >
      {leading && <div className="shrink-0 flex items-center">{leading}</div>}
      {children && <div className="flex-1 min-w-0 flex items-center gap-3">{children}</div>}
      {trailing && <div className="shrink-0 flex items-center gap-2">{trailing}</div>}
    </div>
  );
});

DataRow.displayName = 'DataRow';
