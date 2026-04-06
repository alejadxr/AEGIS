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
  offline: 'bg-zinc-600',
  stopped: 'bg-zinc-600',
  inactive: 'bg-zinc-600',
  decommissioned: 'bg-zinc-600',
  warning: 'bg-[#F59E0B]',
  rotating: 'bg-[#F59E0B]',
  investigating: 'bg-[#F59E0B]',
  pending: 'bg-[#F59E0B]',
  contained: 'bg-[#F59E0B]',
  error: 'bg-[#EF4444]',
  failed: 'bg-[#EF4444]',
  critical: 'bg-[#EF4444]',
  open: 'bg-[#22D3EE]',
  queued: 'bg-[#A855F7]',
};

export function StatusIndicator({ status, label, className }: StatusIndicatorProps) {
  const color = statusColors[status.toLowerCase()] || 'bg-zinc-600';

  return (
    <div className={cn('flex items-center gap-2', className)}>
      <span className="relative flex h-2 w-2">
        <span className={cn('animate-ping absolute inline-flex h-full w-full rounded-full opacity-75', color)} />
        <span className={cn('relative inline-flex rounded-full h-2 w-2', color)} />
      </span>
      {label && <span className="text-[11px] text-zinc-400 capitalize font-medium">{label || status}</span>}
    </div>
  );
}
