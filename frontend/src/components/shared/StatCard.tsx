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
    iconBg: 'bg-[#22D3EE]/10',
    iconText: 'text-[#22D3EE]',
  },
  orange: {
    iconBg: 'bg-[#F97316]/10',
    iconText: 'text-[#F97316]',
  },
  danger: {
    iconBg: 'bg-[#EF4444]/10',
    iconText: 'text-[#EF4444]',
  },
  warning: {
    iconBg: 'bg-[#F59E0B]/10',
    iconText: 'text-[#F59E0B]',
  },
  success: {
    iconBg: 'bg-[#22C55E]/10',
    iconText: 'text-[#22C55E]',
  },
};

export function StatCard({ title, value, trend, icon: Icon, color = 'accent' }: StatCardProps) {
  const cfg = colorConfig[color];
  const isPositive = trend >= 0;
  const [displayValue, setDisplayValue] = useState(0);

  // Animated counter
  useEffect(() => {
    const duration = 800;
    const steps = 30;
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
    <div className="group c6-card p-4 sm:p-6 transition-all duration-200 hover:border-white/[0.1] hover:shadow-[var(--c6-shadow)]">
      {/* Header: Icon + Title */}
      <div className="flex items-center gap-3 mb-4">
        <div className={cn('w-9 h-9 rounded-xl flex items-center justify-center', cfg.iconBg)}>
          <Icon className={cfg.iconText} size={18} />
        </div>
        <span className="text-[13px] font-medium text-zinc-500">{title}</span>
      </div>

      {/* Value + Trend */}
      <div className="flex items-end justify-between">
        <p className="text-[24px] sm:text-[32px] font-bold text-white tracking-tight leading-none tabular-nums font-mono">
          {formatNumber(displayValue)}
        </p>
        <div className={cn(
          'flex items-center gap-1 px-2 py-1 rounded-lg text-xs font-semibold',
          isPositive
            ? 'bg-[#22C55E]/10 text-[#22C55E]'
            : 'bg-[#EF4444]/10 text-[#EF4444]'
        )}>
          {isPositive ? <ArrowUpRight01Icon size={12} /> : <ArrowDownLeft01Icon size={12} />}
          {Math.abs(trend)}%
        </div>
      </div>
    </div>
  );
}
