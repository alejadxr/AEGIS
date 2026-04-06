import { cn } from '@/lib/utils';
import { Loader2 } from 'lucide-react';

interface LoadingStateProps {
  message?: string;
  className?: string;
}

export function LoadingState({ message = 'Loading...', className }: LoadingStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center p-12', className)}>
      <Loader2 className="w-8 h-8 text-[#22D3EE] animate-spin mb-3" />
      <p className="text-[13px] text-zinc-500">{message}</p>
    </div>
  );
}

export function LoadingSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="c6-card p-4 animate-pulse">
          <div className="h-4 bg-white/[0.06] rounded w-3/4 mb-2" />
          <div className="h-3 bg-white/[0.06] rounded w-1/2" />
        </div>
      ))}
    </div>
  );
}
