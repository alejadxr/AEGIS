import { cn, formatRelativeTime, severityColor } from '@/lib/utils';

interface TimelineItem {
  id: string;
  title: string;
  description: string;
  severity?: string | null;
  module?: string;
  timestamp: string;
}

interface TimelineProps {
  items: TimelineItem[];
  emptyMessage?: string;
}

const moduleColors: Record<string, string> = {
  surface: 'bg-cyan',
  response: 'bg-danger',
  phantom: 'bg-purple',
  system: 'bg-text-muted',
};

export function Timeline({ items, emptyMessage = 'No recent activity' }: TimelineProps) {
  if (items.length === 0) {
    return (
      <div className="p-8 text-center text-text-muted text-sm">{emptyMessage}</div>
    );
  }

  return (
    <div className="space-y-0">
      {items.map((item, idx) => (
        <div key={item.id} className="flex gap-3 group">
          {/* Vertical line + dot */}
          <div className="flex flex-col items-center">
            <div
              className={cn(
                'w-2.5 h-2.5 rounded-full mt-1.5 shrink-0 ring-2 ring-dark-surface',
                item.module ? moduleColors[item.module] || 'bg-text-muted' : 'bg-cyan'
              )}
            />
            {idx < items.length - 1 && (
              <div className="w-px flex-1 bg-dark-border min-h-[24px]" />
            )}
          </div>

          {/* Content */}
          <div className="pb-4 min-w-0 flex-1">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <p className="text-sm font-medium text-text-primary leading-tight">
                  {item.title}
                </p>
                <p className="text-xs text-text-muted mt-0.5 line-clamp-2">
                  {item.description}
                </p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {item.severity && (
                  <span className={cn('text-xs font-medium capitalize', severityColor(item.severity as 'critical' | 'high' | 'medium' | 'low' | 'info'))}>
                    {item.severity}
                  </span>
                )}
                <span className="text-xs text-text-muted whitespace-nowrap">
                  {formatRelativeTime(item.timestamp)}
                </span>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
