import { cn } from '@/lib/utils';

interface StatusIndicatorProps {
  status: 'online' | 'offline' | 'warning' | 'running' | 'stopped' | 'rotating' | string;
  label?: string;
  className?: string;
}

const statusColors: Record<string, string> = {
  online:         'bg-[var(--success)]',
  running:        'bg-[var(--success)]',
  active:         'bg-[var(--success)]',
  resolved:       'bg-[var(--success)]',
  executed:       'bg-[var(--success)]',
  approved:       'bg-[var(--success)]',
  remediated:     'bg-[var(--success)]',
  auto_responded: 'bg-[var(--success)]',
  offline:        'bg-muted-foreground/60',
  stopped:        'bg-muted-foreground/60',
  inactive:       'bg-muted-foreground/60',
  decommissioned: 'bg-muted-foreground/60',
  warning:        'bg-[var(--warning)]',
  rotating:       'bg-[var(--warning)]',
  investigating:  'bg-[var(--warning)]',
  pending:        'bg-[var(--warning)]',
  contained:      'bg-[var(--warning)]',
  error:          'bg-[var(--danger)]',
  failed:         'bg-[var(--danger)]',
  critical:       'bg-[var(--danger)]',
  open:           'bg-[var(--danger)]',
  queued:         'bg-[var(--info)]',
};

const pulsingStatuses = new Set([
  'investigating', 'open', 'critical', 'error', 'warning', 'running', 'rotating', 'pending',
]);

export function StatusIndicator({ status, label, className }: StatusIndicatorProps) {
  const normalizedStatus = status.toLowerCase();
  const color = statusColors[normalizedStatus] || 'bg-muted-foreground/60';
  const shouldPulse = pulsingStatuses.has(normalizedStatus);

  return (
    <div className={cn('flex items-center gap-2', className)}>
      <span className="relative flex h-2 w-2 shrink-0">
        {shouldPulse && (
          <span className={cn('animate-ping absolute inline-flex h-full w-full rounded-full opacity-60', color)} />
        )}
        <span className={cn('relative inline-flex rounded-full h-2 w-2', color)} />
      </span>
      {label && <span className="text-[11px] text-muted-foreground capitalize font-medium">{label}</span>}
    </div>
  );
}
