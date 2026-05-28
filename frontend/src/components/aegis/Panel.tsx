'use client';

import * as React from 'react';
import { cn } from '@/lib/utils';

/**
 * Panel — the canonical AEGIS content surface.
 *
 * Replaces all ad-hoc `bg-card border border-border rounded-2xl` shells
 * across the dashboard. ALL surfaces in refactored pages funnel through
 * this primitive so dark-mode background drift cannot reappear.
 *
 * Rules applied (ui-ux-pro-max):
 *  - semantic-color-tokens: only uses `bg-card`, `border-border`, and
 *    `color-mix(in oklab, var(--token) X%, transparent)` for accents.
 *  - focus-states: interactive variant adds 2px focus ring + offset.
 *  - color-not-only: variant edges pair with optional headerVariant/icon.
 *  - spacing-scale: padding tokens map 1:1 to dashboard rhythm
 *      none → 0, sm → p-3 sm:p-4, md → p-4 sm:p-5, lg → p-5 sm:p-6
 *  - reduced-motion: transitions are 200ms and CSS-only (system respects
 *    prefers-reduced-motion via globals).
 */
export type PanelVariant = 'default' | 'prominent' | 'warning' | 'danger' | 'glass';
export type PanelPadding = 'none' | 'sm' | 'md' | 'lg';
export type PanelBorder = 'none' | 'default' | 'strong';

export interface PanelProps extends React.HTMLAttributes<HTMLElement> {
  variant?: PanelVariant;
  padding?: PanelPadding;
  border?: PanelBorder;
  interactive?: boolean;
  /** Render as a semantic element. Defaults to <section>. */
  as?: 'section' | 'article' | 'div' | 'aside';
  children: React.ReactNode;
}

const VARIANT_CLASS: Record<PanelVariant, string> = {
  default: 'bg-card',
  prominent: 'bg-card ring-1 ring-white/[0.04] shadow-[0_8px_24px_-16px_rgba(0,0,0,0.45)]',
  warning: 'bg-card',
  danger: 'bg-card',
  glass: 'bg-card/85 backdrop-blur-md',
};

const VARIANT_BORDER: Record<PanelVariant, string> = {
  default: '',
  prominent: '',
  warning: '!border-[color-mix(in_oklab,var(--warning)_28%,transparent)]',
  danger: '!border-[color-mix(in_oklab,var(--danger)_28%,transparent)]',
  glass: '',
};

const BORDER_CLASS: Record<PanelBorder, string> = {
  none: 'border-0',
  default: 'border border-border',
  strong: 'border border-[var(--border-strong,var(--border))]',
};

const PADDING_CLASS: Record<PanelPadding, string> = {
  none: '',
  sm: 'p-3 sm:p-4',
  md: 'p-4 sm:p-5',
  lg: 'p-5 sm:p-6',
};

export const Panel = React.forwardRef<HTMLElement, PanelProps>(function Panel(
  {
    variant = 'default',
    padding = 'none',
    border = 'default',
    interactive = false,
    as = 'section',
    className,
    children,
    ...rest
  },
  ref,
) {
  const Comp = as as 'section';
  return (
    <Comp
      ref={ref as React.Ref<HTMLElement>}
      className={cn(
        'relative rounded-2xl overflow-hidden',
        BORDER_CLASS[border],
        VARIANT_CLASS[variant],
        VARIANT_BORDER[variant],
        PADDING_CLASS[padding],
        interactive && [
          'transition-[border-color,box-shadow,transform] duration-200',
          'hover:border-white/[0.12] hover:-translate-y-[1px]',
          'focus-visible:outline-none focus-visible:ring-2',
          'focus-visible:ring-[var(--brand-accent)]/60 focus-visible:ring-offset-2',
          'focus-visible:ring-offset-background',
        ],
        className,
      )}
      {...rest}
    >
      {children}
    </Comp>
  );
});

Panel.displayName = 'Panel';
