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

const colorConfig = {
  accent: {
    iconText: 'text-primary',
  },
  orange: {
    iconText: 'text-[#F97316]',
  },
  danger: {
    iconText: 'text-destructive',
  },
  warning: {
    iconText: 'text-[#F59E0B]',
  },
  success: {
    iconText: 'text-[#22C55E]',
  },
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
    <Card className="rounded-xl py-0 gap-0 shadow-none transition-all duration-200 hover:shadow-lg hover:shadow-primary/5 hover:border-primary/20 hover:-translate-y-0.5">
      <CardContent className="p-4 sm:p-5">
        {/* Label row */}
        <div className="flex items-center justify-between mb-3">
          <span className="text-label">{title}</span>
          <Icon className={cn(cfg.iconText, 'opacity-40')} size={15} />
        </div>

        {/* Value */}
        <p className="text-[32px] sm:text-[38px] font-bold text-foreground tracking-tight leading-none font-mono tabular-nums">
          {formatNumber(displayValue)}
        </p>

        {/* Trend */}
        {trend !== 0 && (
          <div className="flex items-center gap-1 mt-2.5">
            {isPositive ? (
              <ArrowUpRight01Icon size={11} className="text-[#22C55E]" />
            ) : (
              <ArrowDownLeft01Icon size={11} className="text-destructive" />
            )}
            <span className={cn(
              'text-[11px] font-mono font-semibold tabular-nums',
              isPositive ? 'text-[#22C55E]' : 'text-destructive'
            )}>
              {isPositive ? '+' : '-'}{Math.abs(trend)}%
            </span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
