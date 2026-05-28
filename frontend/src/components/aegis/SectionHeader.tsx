'use client';

import * as React from 'react';
import { cn } from '@/lib/utils';

/**
 * SectionHeader — the strip atop a <Panel>.
 *
 * Canonical AEGIS pattern: uppercase tracking label on the left, optional
 * subtitle/count, action slot on the right. Replaces 6+ inline header
 * strips currently duplicated across dashboard components.
 *
 * Rules: typography hierarchy (11px uppercase 0.14em label), color-not-only
 * (icon + label), focus-states (action slot inherits).
 */
export interface SectionHeaderProps {
  title: React.ReactNode;
  /** Small mono subtitle rendered next to the title (e.g. "· last 14d"). */
  subtitle?: React.ReactNode;
  /** Icon shown left of the title. */
  icon?: React.ReactNode;
  /** Right-aligned action slot (buttons, badges, counts). */
  action?: React.ReactNode;
  /** Live indicator dot (orange pulse) before the title. */
  live?: boolean;
  /** Inline mono count on the right (e.g. "5 pending"). */
  count?: React.ReactNode;
  className?: string;
  /** When true, header has no bottom border (use when Panel has no body). */
  flush?: boolean;
}

export function SectionHeader({
  title,
  subtitle,
  icon,
  action,
  live,
  count,
  className,
  flush = false,
}: SectionHeaderProps) {
  return (
    <header
      className={cn(
        'flex items-center justify-between gap-3 px-4 sm:px-5 py-3',
        !flush && 'border-b border-border',
        className,
      )}
    >
      <div className="flex items-center gap-2 min-w-0">
        {live && (
          <span
            aria-hidden
            className="w-1.5 h-1.5 rounded-full bg-[var(--brand-accent)] animate-pulse"
          />
        )}
        {icon && <span className="text-muted-foreground/60 shrink-0">{icon}</span>}
        <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-muted-foreground truncate">
          {title}
        </span>
        {subtitle && (
          <span className="text-[10px] font-mono text-muted-foreground/50 truncate">
            {subtitle}
          </span>
        )}
      </div>

      {(action || count) && (
        <div className="flex items-center gap-3 shrink-0">
          {count && (
            <span className="text-[10px] font-mono text-muted-foreground/50">{count}</span>
          )}
          {action}
        </div>
      )}
    </header>
  );
}
