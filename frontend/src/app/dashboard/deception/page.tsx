'use client';

import { useCallback, useEffect, useState } from 'react';
import { Sparkles, Plus, RotateCw, Trash2, Loader2, Lock } from 'lucide-react';
import { api, ApiError, DeceptionCampaign, DeceptionBreadcrumbHit } from '@/lib/api';
import { cn, formatRelativeTime } from '@/lib/utils';
import { LoadingState } from '@/components/shared/LoadingState';
import { CampaignBuilder } from '@/components/deception/CampaignBuilder';
import { BreadcrumbHits } from '@/components/deception/BreadcrumbHits';
import { Panel } from '@/components/aegis/Panel';
import { EmptyState } from '@/components/aegis/EmptyState';

const STATUS_COLORS: Record<string, string> = {
  running: 'text-[var(--success)] bg-[color-mix(in_oklab,var(--success)_12%,transparent)] border-[color-mix(in_oklab,var(--success)_25%,transparent)]',
  deploying: 'text-[var(--warning)] bg-[color-mix(in_oklab,var(--warning)_12%,transparent)] border-[color-mix(in_oklab,var(--warning)_25%,transparent)]',
  rotating: 'text-[var(--chart-5)] bg-[color-mix(in_oklab,var(--chart-5)_12%,transparent)] border-[color-mix(in_oklab,var(--chart-5)_25%,transparent)]',
  stopped: 'text-muted-foreground bg-muted/10 border-border',
  failed: 'text-[var(--danger)] bg-[color-mix(in_oklab,var(--danger)_12%,transparent)] border-[color-mix(in_oklab,var(--danger)_25%,transparent)]',
  pending: 'text-muted-foreground bg-muted/10 border-border',
};

export default function DeceptionPage() {
  const [campaigns, setCampaigns] = useState<DeceptionCampaign[]>([]);
  const [hits, setHits] = useState<DeceptionBreadcrumbHit[]>([]);
  const [loading, setLoading] = useState(true);
  const [builderOpen, setBuilderOpen] = useState(false);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [enterpriseGated, setEnterpriseGated] = useState(false);

  const load = useCallback(async () => {
    try {
      const [c, h] = await Promise.allSettled([
        api.deception.campaigns(),
        api.deception.breadcrumbHits(50),
      ]);
      setCampaigns(c.status === 'fulfilled' ? c.value : []);
      setHits(h.status === 'fulfilled' ? h.value : []);
      if (c.status === 'rejected') {
        const isGated =
          c.reason instanceof ApiError && c.reason.status === 403;
        if (isGated) {
          setEnterpriseGated(true);
        } else {
          const msg =
            c.reason instanceof Error ? c.reason.message : String(c.reason);
          setError(msg);
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
    if (!confirm('Delete this campaign? This cannot be undone.')) return;
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
            <Sparkles className="w-6 h-6 text-[var(--brand-accent)]" />
            Honey-AI Deception
            <span className="text-[11px] font-semibold uppercase tracking-widest px-2 py-0.5 rounded-full bg-[color-mix(in_oklab,var(--warning)_12%,transparent)] border border-[color-mix(in_oklab,var(--warning)_25%,transparent)] text-[var(--warning)]">
              Enterprise
            </span>
          </h1>
          <p className="text-sm text-muted-foreground mt-1 hidden sm:block">
            Auto-generate massive fake infrastructure and track stolen bait
            in real time
          </p>
        </div>
        <button
          onClick={() => setBuilderOpen(true)}
          className="flex items-center gap-2 bg-[var(--brand-accent)] hover:bg-[var(--brand-accent)] text-[#09090B] font-semibold px-3 sm:px-4 py-2.5 rounded-xl transition-colors text-[13px] shrink-0"
        >
          <Plus className="w-4 h-4" />
          <span className="hidden sm:inline">New Campaign</span>
          <span className="sm:hidden">New</span>
        </button>
      </div>

      {error && (
        <div className="bg-[color-mix(in_oklab,var(--danger)_8%,transparent)] border border-[color-mix(in_oklab,var(--danger)_25%,transparent)] rounded-2xl px-4 py-3 text-[13px] text-[var(--danger)]">
          {error}
        </div>
      )}

      {enterpriseGated && (
        <Panel variant="warning" padding="lg" as="div" className="text-center">
          <Lock className="w-10 h-10 text-[var(--warning)] mx-auto mb-4" />
          <h2 className="text-[16px] font-semibold text-[var(--warning)] mb-2">Honey-AI Deception</h2>
          <p className="text-[13px] text-muted-foreground max-w-md mx-auto mb-4">
            Active deception campaigns require AEGIS Enterprise tier. Contact sales for activation.
          </p>
          <a
            href="mailto:sales@somoswilab.com?subject=AEGIS%20Deception%20Inquiry"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-[13px] font-semibold border border-[color-mix(in_oklab,var(--warning)_35%,transparent)] text-[var(--warning)] hover:bg-[color-mix(in_oklab,var(--warning)_10%,transparent)] transition-colors"
          >
            Contact Sales
          </a>
        </Panel>
      )}

      {/* Summary stats — hidden when enterprise-gated (all zeros would be misleading) */}
      {!enterpriseGated && (
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
      )}

      {/* Campaign list */}
      {!enterpriseGated && (
      <Panel>
        <div className="px-4 sm:px-6 py-4 border-b border-border">
          <span className="text-[14px] font-semibold text-foreground">
            Campaigns
          </span>
        </div>
        {campaigns.length === 0 ? (
          <EmptyState
            title="No campaigns yet"
            description={<>Click <span className="text-[var(--brand-accent)] font-medium">New Campaign</span> to deploy fake infrastructure.</>}
            size="md"
          />
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
                    <p className="text-[11px] text-[var(--danger)] mt-1">{c.error}</p>
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
                    title="Delete campaign"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
      )}

      {/* Breadcrumb hits — only shown when not enterprise-gated */}
      {!enterpriseGated && <BreadcrumbHits hits={hits} />}

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
    <Panel padding="sm" as="div">
      <div className="text-[11px] text-muted-foreground uppercase tracking-wide">
        {label}
      </div>
      <div
        className={cn(
          'text-[24px] font-bold mt-1 font-mono',
          tone === 'danger' && value > 0 ? 'text-[var(--danger)]' : 'text-foreground',
        )}
      >
        {value.toLocaleString()}
      </div>
    </Panel>
  );
}
