'use client';

import { AlertTriangle, ExternalLink } from 'lucide-react';
import { DeceptionBreadcrumbHit } from '@/lib/api';
import { formatRelativeTime } from '@/lib/utils';

interface Props {
  hits: DeceptionBreadcrumbHit[];
  onSelectCampaign?: (campaignId: string) => void;
}

export function BreadcrumbHits({ hits, onSelectCampaign }: Props) {
  if (hits.length === 0) {
    return (
      <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl">
        <div className="px-4 sm:px-6 py-4 border-b border-white/[0.06] flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-[#F97316]" />
          <span className="text-[14px] font-semibold text-white">
            Breadcrumb Hits
          </span>
        </div>
        <div className="p-6 text-center">
          <p className="text-zinc-500 text-[13px]">
            No breadcrumb hits yet. When an attacker reuses stolen bait, it
            will appear here in real time.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl">
      <div className="px-4 sm:px-6 py-4 border-b border-white/[0.06] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-[#F97316]" />
          <span className="text-[14px] font-semibold text-white">
            Breadcrumb Hits
          </span>
          <span className="text-[11px] text-zinc-500 font-mono ml-2">
            {hits.length} attackers re-using bait
          </span>
        </div>
      </div>
      <div className="divide-y divide-white/[0.04]">
        {hits.map((hit) => (
          <div
            key={hit.id}
            className="px-4 sm:px-6 py-4 flex items-start gap-4 hover:bg-white/[0.01] transition-colors"
          >
            <div className="w-9 h-9 rounded-xl bg-red-500/10 border border-red-500/30 flex items-center justify-center shrink-0">
              <AlertTriangle className="w-4 h-4 text-red-400" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[13px] font-semibold text-white">
                  {hit.bait_kind.replace(/_/g, ' ')}
                </span>
                <span className="px-2 py-0.5 text-[10px] font-semibold bg-red-500/10 border border-red-500/30 text-red-400 rounded uppercase tracking-wide">
                  CRITICAL
                </span>
                <span className="text-[11px] text-zinc-600 font-mono">
                  {hit.hit_count} hits
                </span>
              </div>
              <p className="text-[12px] text-zinc-400 mt-1 truncate">
                Planted in{' '}
                <span className="text-zinc-300 font-mono">{hit.planted_in}</span>
              </p>
              {hit.last_hit_source && (
                <p className="text-[11px] text-zinc-600 mt-1 truncate font-mono">
                  Source: {hit.last_hit_source}
                </p>
              )}
              <div className="flex items-center gap-3 mt-2">
                <span className="text-[10px] text-zinc-600 font-mono">
                  UUID: {hit.breadcrumb_uuid.slice(0, 16)}...
                </span>
                <span className="text-[10px] text-zinc-600">
                  {hit.last_hit_at ? formatRelativeTime(hit.last_hit_at) : '—'}
                </span>
              </div>
            </div>
            {onSelectCampaign && (
              <button
                onClick={() => onSelectCampaign(hit.campaign_id)}
                className="text-[11px] text-[#F97316] hover:text-[#FB923C] flex items-center gap-1 shrink-0"
              >
                Campaign
                <ExternalLink className="w-3 h-3" />
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
