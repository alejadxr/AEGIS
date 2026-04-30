'use client';

import { useEffect, useState } from 'react';
import { ArrowUpRight01Icon, ArrowDownLeft01Icon } from 'hugeicons-react';
import { cn, formatNumber } from '@/lib/utils';
import { Card, CardContent } from '@/components/ui/card';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type IconComponent = React.ComponentType<any>;

interface StatCardProps {
  title: string;
  value: number;
  trend: number;
  icon: IconComponent;
  color?: 'accent' | 'orange' | 'danger' | 'warning' | 'success';
}

const colorConfig: Record<NonNullable<StatCardProps['color']>, { icon: string; ring: string }> = {
  accent:  { icon: 'text-primary',       ring: 'group-hover:border-primary/30' },
  orange:  { icon: 'text-[var(--brand-accent)]', ring: 'group-hover:border-[var(--brand-accent)]/30' },
  danger:  { icon: 'text-[var(--danger)]',  ring: 'group-hover:border-[var(--danger)]/30' },
  warning: { icon: 'text-[var(--warning)]', ring: 'group-hover:border-[var(--warning)]/30' },
  success: { icon: 'text-[var(--success)]', ring: 'group-hover:border-[var(--success)]/30' },
};

export function StatCard({ title, value, trend, icon: Icon, color = 'accent' }: StatCardProps) {
  const cfg = colorConfig[color];
  const isPositive = trend >= 0;
  const [displayValue, setDisplayValue] = useState(0);

  useEffect(() => {
    const duration = 600;
    const steps = 24;
    const increment = value / steps;
    let current = 0;
    let step = 0;
    const timer = setInterval(() => {
      step++;
      current = Math.min(Math.round(increment * step), value);
      setDisplayValue(current);
      if (step >= steps) clearInterval(timer);
    }, duration / steps);
    return () => clearInterval(timer);
  }, [value]);

  return (
    <Card className={cn(
      'group relative rounded-xl py-0 gap-0 shadow-none overflow-hidden',
      'transition-[transform,border-color,box-shadow] duration-200',
      'hover:-translate-y-0.5 hover:shadow-[0_4px_20px_-4px_rgba(0,0,0,0.08)]',
      cfg.ring,
    )}>
      {/* Subtle top accent line on hover */}
      <span className={cn(
        'absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r from-transparent via-current to-transparent opacity-0 group-hover:opacity-40 transition-opacity',
        cfg.icon
      )} />

      <CardContent className="p-4 sm:p-5">
        <div className="flex items-center justify-between mb-3.5">
          <span className="text-label">{title}</span>
          <div className={cn(
            'flex items-center justify-center w-7 h-7 rounded-md bg-muted/60',
            cfg.icon
          )}>
            <Icon size={14} />
          </div>
        </div>

        <p className="text-[30px] sm:text-[36px] font-bold text-foreground tracking-[-0.035em] leading-none font-mono tabular-nums">
          {formatNumber(displayValue)}
        </p>

        {trend !== 0 ? (
          <div className="flex items-center gap-1 mt-3">
            {isPositive ? (
              <ArrowUpRight01Icon size={11} className="text-[var(--success)]" />
            ) : (
              <ArrowDownLeft01Icon size={11} className="text-[var(--danger)]" />
            )}
            <span className={cn(
              'text-[11px] font-mono font-semibold tabular-nums',
              isPositive ? 'text-[var(--success)]' : 'text-[var(--danger)]'
            )}>
              {isPositive ? '+' : '-'}{Math.abs(trend)}%
            </span>
            <span className="text-[10px] text-muted-foreground/50 font-mono tracking-wide uppercase ml-1">
              vs last
            </span>
          </div>
        ) : (
          <div className="mt-3 flex items-center gap-1.5">
            <span className="w-1 h-1 rounded-full bg-muted-foreground/40" />
            <span className="text-[10px] text-muted-foreground/50 font-mono tracking-wide uppercase">
              no change
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
