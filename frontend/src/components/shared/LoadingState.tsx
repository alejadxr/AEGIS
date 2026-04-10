import { cn } from '@/lib/utils';
import { Loader2 } from 'lucide-react';
import { Card } from '@/components/ui/card';

interface LoadingStateProps {
  message?: string;
  className?: string;
}

export function LoadingState({ message = 'Loading...', className }: LoadingStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center p-12', className)}>
      <Loader2 className="w-8 h-8 text-primary animate-spin mb-3" />
      <p className="text-[13px] text-muted-foreground">{message}</p>
    </div>
  );
}

export function LoadingSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <Card key={i} className="rounded-xl py-0 gap-0 shadow-none p-4 animate-pulse">
          <div className="h-4 bg-muted rounded w-3/4 mb-2" />
          <div className="h-3 bg-muted rounded w-1/2" />
        </Card>
      ))}
    </div>
  );
}
