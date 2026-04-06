import { cn } from '@/lib/utils';

interface SeverityBadgeProps {
  severity: string;
  className?: string;
}

const severityStyles: Record<string, string> = {
  critical: 'bg-[#EF4444]/10 text-[#EF4444]',
  high: 'bg-[#F97316]/10 text-[#F97316]',
  medium: 'bg-[#F59E0B]/10 text-[#F59E0B]',
  low: 'bg-[#3B82F6]/10 text-[#3B82F6]',
  info: 'bg-zinc-500/10 text-zinc-500',
};

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const normalized = severity.toLowerCase();
  const style = severityStyles[normalized] || 'bg-zinc-500/10 text-zinc-500';

  return (
    <span
      className={cn(
        'text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-md',
        style,
        className
      )}
    >
      {severity}
    </span>
  );
}
