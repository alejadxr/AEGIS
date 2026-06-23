'use client';
import Link from 'next/link';
import { AlertTriangle } from 'lucide-react';

export interface DemoModeBannerProps {
  feature?: string;
  nextPath: string;
}

export function DemoModeBanner({ feature = 'feature', nextPath }: DemoModeBannerProps) {
  return (
    <div className="mb-4 rounded-2xl border border-amber-500/30 bg-amber-500/10 p-4 flex items-start gap-3">
      <AlertTriangle className="w-5 h-5 text-amber-400 mt-0.5 shrink-0" aria-hidden />
      <div className="flex-1 min-w-0">
        <p className="font-medium text-amber-200">Demo mode enabled</p>
        <p className="text-sm text-amber-100/80 mt-1">
          Read-only preview. {feature} changes are disabled. Sign in with a production API key to make changes.
        </p>
      </div>
      <Link
        href={`/login?next=${encodeURIComponent(nextPath)}`}
        className="shrink-0 inline-flex items-center px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-zinc-900 text-sm font-medium transition-colors"
      >
        Sign in →
      </Link>
    </div>
  );
}
