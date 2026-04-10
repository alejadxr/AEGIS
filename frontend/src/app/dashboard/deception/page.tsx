'use client';

import { useCallback, useEffect, useState } from 'react';
import { Sparkles, Plus, RotateCw, Trash2, Loader2 } from 'lucide-react';
import { api, DeceptionCampaign, DeceptionBreadcrumbHit } from '@/lib/api';
import { cn, formatRelativeTime } from '@/lib/utils';
import { LoadingState } from '@/components/shared/LoadingState';
import { CampaignBuilder } from '@/components/deception/CampaignBuilder';
import { BreadcrumbHits } from '@/components/deception/BreadcrumbHits';

const STATUS_COLORS: Record<string, string> = {
  running: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
  deploying: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  rotating: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
  stopped: 'text-muted-foreground bg-zinc-500/10 border-zinc-500/20',
  failed: 'text-red-400 bg-red-500/10 border-red-500/30',
  pending: 'text-muted-foreground bg-zinc-500/10 border-zinc-500/20',
};

export default function DeceptionPage() {
  const [campaigns, setCampaigns] = useState<DeceptionCampaign[]>([]);
  const [hits, setHits] = useState<DeceptionBreadcrumbHit[]>([]);
  const [loading, setLoading] = useState(true);
  const [builderOpen, setBuilderOpen] = useState(false);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [c, h] = await Promise.allSettled([
        api.deception.campaigns(),
        api.deception.breadcrumbHits(50),
      ]);
      setCampaigns(c.status === 'fulfilled' ? c.value : []);
      setHits(h.status === 'fulfilled' ? h.value : []);
      if (c.status === 'rejected') {
        const msg =
          c.reason instanceof Error ? c.reason.message : String(c.reason);
        if (msg.includes('403')) {
          setError('Honey-AI Deception requires the Enterprise tier.');
        }
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, 10_000);
    return () => clearInterval(timer);
  }, [load]);

  const handleRotate = async (id: string) => {
    setPendingAction(id);
    try {
      await api.deception.rotateCampaign(id);
      await load();
    } finally {
      setPendingAction(null);
    }
  };

  const handleStop = async (id: string) => {
    setPendingAction(id);
    try {
      await api.deception.deleteCampaign(id);
      await load();
    } finally {
      setPendingAction(null);
    }
  };

  if (loading) {
    return <LoadingState message="Loading deception campaigns..." />;
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-[22px] sm:text-[28px] font-bold text-foreground tracking-tight flex items-center gap-3">
            <Sparkles className="w-6 h-6 text-[#F97316]" />
            Honey-AI Deception
          </h1>
          <p className="text-sm text-muted-foreground mt-1 hidden sm:block">
            Auto-generate massive fake infrastructure and track stolen bait
            in real time
          </p>
        </div>
        <button
          onClick={() => setBuilderOpen(true)}
          className="flex items-center gap-2 bg-[#F97316] hover:bg-[#EA580C] text-[#09090B] font-semibold px-3 sm:px-4 py-2.5 rounded-xl transition-colors text-[13px] shrink-0"
        >
          <Plus className="w-4 h-4" />
          <span className="hidden sm:inline">New Campaign</span>
          <span className="sm:hidden">New</span>
        </button>
      </div>

      {error && (
        <div className="bg-amber-500/5 border border-amber-500/30 rounded-2xl px-4 py-3 text-[13px] text-amber-400">
          {error}
        </div>
      )}

      {/* Summary stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard
          label="Active Campaigns"
          value={campaigns.filter((c) => c.status === 'running').length}
        />
        <StatCard
          label="Deployed Decoys"
          value={campaigns.reduce((s, c) => s + (c.honeypot_count || 0), 0)}
        />
        <StatCard
          label="Breadcrumbs"
          value={campaigns.reduce((s, c) => s + (c.breadcrumb_count || 0), 0)}
        />
        <StatCard label="Hits" value={hits.length} tone="danger" />
      </div>

      {/* Campaign list */}
      <div className="bg-card border border-border rounded-2xl overflow-hidden">
        <div className="px-4 sm:px-6 py-4 border-b border-border">
          <span className="text-[14px] font-semibold text-foreground">
            Campaigns
          </span>
        </div>
        {campaigns.length === 0 ? (
          <div className="p-8 text-center">
            <p className="text-muted-foreground text-[13px]">
              No campaigns yet. Click{' '}
              <span className="text-[#F97316] font-medium">New Campaign</span>{' '}
              to deploy fake infrastructure.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-white/[0.04]">
            {campaigns.map((c) => (
              <div
                key={c.id}
                className="px-4 sm:px-6 py-4 flex items-start gap-4 hover:bg-white/[0.01]"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[14px] font-semibold text-foreground truncate">
                      {c.name}
                    </span>
                    <span
                      className={cn(
                        'px-2 py-0.5 text-[10px] font-semibold border rounded uppercase tracking-wide',
                        STATUS_COLORS[c.status] || STATUS_COLORS.pending,
                      )}
                    >
                      {c.status}
                    </span>
                    <span className="text-[11px] text-muted-foreground font-mono">
                      {c.theme}
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-4 mt-2 text-[11px] text-muted-foreground">
                    <span>
                      Decoys:{' '}
                      <span className="text-foreground font-mono">
                        {c.honeypot_count}/{c.decoy_count}
                      </span>
                    </span>
                    <span>
                      Breadcrumbs:{' '}
                      <span className="text-foreground font-mono">
                        {c.breadcrumb_count}
                      </span>
                    </span>
                    <span>
                      Rotation:{' '}
                      <span className="text-foreground font-mono">
                        {c.rotation_hours}h
                      </span>
                    </span>
                    {c.deployed_at && (
                      <span>
                        Deployed:{' '}
                        <span className="text-foreground">
                          {formatRelativeTime(c.deployed_at)}
                        </span>
                      </span>
                    )}
                  </div>
                  {c.error && (
                    <p className="text-[11px] text-red-400 mt-1">{c.error}</p>
                  )}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    disabled={pendingAction === c.id || c.status !== 'running'}
                    onClick={() => handleRotate(c.id)}
                    className="w-8 h-8 rounded-lg border border-border hover:border-white/[0.2] text-muted-foreground hover:text-foreground flex items-center justify-center disabled:opacity-30 disabled:cursor-not-allowed"
                    title="Rotate"
                  >
                    {pendingAction === c.id ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <RotateCw className="w-3.5 h-3.5" />
                    )}
                  </button>
                  <button
                    type="button"
                    disabled={pendingAction === c.id}
                    onClick={() => handleStop(c.id)}
                    className="w-8 h-8 rounded-lg border border-border hover:border-red-500/40 text-muted-foreground hover:text-red-400 flex items-center justify-center disabled:opacity-30 disabled:cursor-not-allowed"
                    title="Stop"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Breadcrumb hits */}
      <BreadcrumbHits hits={hits} />

      {/* Builder modal */}
      <CampaignBuilder
        open={builderOpen}
        onClose={() => setBuilderOpen(false)}
        onCreated={(c) => setCampaigns((prev) => [c, ...prev])}
      />
    </div>
  );
}

function StatCard({
  label,
  value,
  tone = 'default',
}: {
  label: string;
  value: number;
  tone?: 'default' | 'danger';
}) {
  return (
    <div className="bg-card border border-border rounded-2xl px-4 py-4">
      <div className="text-[11px] text-muted-foreground uppercase tracking-wide">
        {label}
      </div>
      <div
        className={cn(
          'text-[24px] font-bold mt-1 font-mono',
          tone === 'danger' && value > 0 ? 'text-red-400' : 'text-foreground',
        )}
      >
        {value.toLocaleString()}
      </div>
    </div>
  );
}
