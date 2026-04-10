'use client';

import { useEffect, useState } from 'react';
import { ArrowUpRight01Icon, ArrowDownLeft01Icon } from 'hugeicons-react';
import { cn, formatNumber } from '@/lib/utils';

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
    iconText: 'text-[#22D3EE]',
  },
  orange: {
    iconText: 'text-[#F97316]',
  },
  danger: {
    iconText: 'text-[#EF4444]',
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
    <div className="c6-card p-4 sm:p-5 transition-all duration-150 hover:border-white/[0.08]">
      {/* Label row */}
      <div className="flex items-center justify-between mb-3">
        <span className="text-label">{title}</span>
        <Icon className={cn(cfg.iconText, 'opacity-40')} size={15} />
      </div>

      {/* Value */}
      <p className="text-[28px] sm:text-[32px] font-semibold text-white tracking-tight leading-none font-mono tabular-nums">
        {formatNumber(displayValue)}
      </p>

      {/* Trend */}
      {trend !== 0 && (
        <div className="flex items-center gap-1 mt-2.5">
          {isPositive ? (
            <ArrowUpRight01Icon size={11} className="text-[#22C55E]" />
          ) : (
            <ArrowDownLeft01Icon size={11} className="text-[#EF4444]" />
          )}
          <span className={cn(
            'text-[11px] font-mono tabular-nums',
            isPositive ? 'text-[#22C55E]/70' : 'text-[#EF4444]/70'
          )}>
            {Math.abs(trend)}%
          </span>
        </div>
      )}
    </div>
  );
}
