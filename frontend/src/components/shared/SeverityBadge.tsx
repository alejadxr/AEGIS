import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';

interface SeverityBadgeProps {
  severity: string;
  className?: string;
}

const severityStyles: Record<string, string> = {
  critical: 'bg-destructive/10 text-destructive border-destructive/20',
  high: 'bg-[#F97316]/10 text-[#F97316] border-[#F97316]/20',
  medium: 'bg-[#F59E0B]/10 text-[#F59E0B] border-[#F59E0B]/20',
  low: 'bg-[#3B82F6]/10 text-[#3B82F6] border-[#3B82F6]/20',
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
