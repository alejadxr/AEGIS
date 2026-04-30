import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';

interface SeverityBadgeProps {
  severity: string;
  className?: string;
}

const severityStyles: Record<string, string> = {
  critical: 'bg-destructive/10 text-destructive border-destructive/20',
  high: 'bg-[var(--brand-accent)]/10 text-[var(--brand-accent)] border-[var(--brand-accent)]/20',
  medium: 'bg-[var(--warning)]/10 text-[var(--warning)] border-[var(--warning)]/20',
  low: 'bg-[var(--info)]/10 text-[var(--info)] border-[var(--info)]/20',
  info: 'bg-muted text-muted-foreground border-border',
};

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const normalized = severity.toLowerCase();
  const style = severityStyles[normalized] || 'bg-muted text-muted-foreground border-border';

  return (
    <Badge
      variant="outline"
      className={cn(
        'text-[10px] font-semibold uppercase tracking-wider rounded-md',
        style,
        className
      )}
    >
      {severity}
    </Badge>
  );
}
