import { cn } from '@/lib/utils';

interface StatusIndicatorProps {
  status: 'online' | 'offline' | 'warning' | 'running' | 'stopped' | 'rotating' | string;
  label?: string;
  className?: string;
}

const statusColors: Record<string, string> = {
  online: 'bg-[#22C55E]',
  running: 'bg-[#22C55E]',
  active: 'bg-[#22C55E]',
  resolved: 'bg-[#22C55E]',
  executed: 'bg-[#22C55E]',
  approved: 'bg-[#22C55E]',
  remediated: 'bg-[#22C55E]',
  offline: 'bg-muted-foreground',
  stopped: 'bg-muted-foreground',
  inactive: 'bg-muted-foreground',
  decommissioned: 'bg-muted-foreground',
  warning: 'bg-[#F59E0B]',
  rotating: 'bg-[#F59E0B]',
  investigating: 'bg-[#F59E0B]',
  pending: 'bg-[#F59E0B]',
  contained: 'bg-[#F59E0B]',
  error: 'bg-destructive',
  failed: 'bg-destructive',
  critical: 'bg-destructive',
  open: 'bg-primary',
  queued: 'bg-[#A855F7]',
};

export function StatusIndicator({ status, label, className }: StatusIndicatorProps) {
  const color = statusColors[status.toLowerCase()] || 'bg-muted-foreground';

  return (
    <div className={cn('flex items-center gap-2', className)}>
      <span className="relative flex h-2 w-2">
        <span className={cn('animate-ping absolute inline-flex h-full w-full rounded-full opacity-75', color)} />
        <span className={cn('relative inline-flex rounded-full h-2 w-2', color)} />
      </span>
      {label && <span className="text-[11px] text-muted-foreground capitalize font-medium">{label || status}</span>}
    </div>
  );
}
