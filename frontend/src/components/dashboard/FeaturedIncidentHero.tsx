'use client';

import Link from 'next/link';
import { Download, HardDrive, Crosshair, Network, Shield } from 'lucide-react';
import { cn } from '@/lib/utils';

// ── Public type (re-export so callers can import from this file) ──────────────

export type FeaturedIncidentData = {
  incident_number: string | null;
  title: string;
  severity: string;
  affected_asset: string;
  mitre_technique: string;
  source_ip: string;
  confidence: number;
  detected_at: string;
};

interface FeaturedIncidentHeroProps {
  data: FeaturedIncidentData | null;
  loading?: boolean;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function severityColor(sev: string): string {
  switch (sev.toLowerCase()) {
    case 'critical': return 'var(--danger)';
    case 'high':     return 'var(--brand-accent)';
    case 'medium':   return 'var(--warning)';
    case 'low':      return 'var(--chart-5, #C084FC)';
    default:         return 'var(--muted-foreground)';
  }
}

function severityPillClass(sev: string): string {
  switch (sev.toLowerCase()) {
    case 'critical': return 'pill pill-danger';
    case 'high':     return 'pill pill-warning';
    case 'medium':   return 'pill pill-warning';
    case 'low':      return 'pill pill-muted';
    default:         return 'pill pill-muted';
  }
}

function relativeTime(iso: string): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '—';
  const diff = (Date.now() - t) / 1000;
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function formatConfidence(value: number): string {
  if (value <= 0) return '—';
  // Normalise: values > 1 are already percentages
  const pct = value > 1 ? Math.round(value) : Math.round(value * 100);
  return `${pct}%`;
}

function eyebrowDate(): string {
  return new Date().toLocaleDateString('en-US', {
    weekday: 'short',
    month: 'short',
    day: 'numeric',
  });
}

// ── Loading skeleton ──────────────────────────────────────────────────────────

function HeroSkeleton() {
  return (
    <div className="animate-pulse space-y-4 pt-1" aria-busy="true" aria-label="Loading incident data">
      {/* Hero row skeleton */}
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1 space-y-3">
          <div className="h-3 w-44 rounded bg-muted/40" />
          <div className="h-9 w-72 rounded-lg bg-muted/40" />
          <div className="flex items-center gap-3">
            <div className="h-2 w-2 rounded-full bg-muted/40" />
            <div className="h-3 w-16 rounded bg-muted/40" />
            <div className="h-3 w-48 rounded bg-muted/40" />
            <div className="h-3 w-14 rounded bg-muted/40" />
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <div className="h-6 w-20 rounded-full bg-muted/40" />
          <div className="h-8 w-24 rounded-md bg-muted/40" />
        </div>
      </div>

      {/* Stat cards skeleton */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="bg-card border border-border/60 rounded-2xl p-4 space-y-3">
            <div className="flex items-center gap-2">
              <div className="h-4 w-4 rounded bg-muted/30" />
              <div className="h-3 w-20 rounded bg-muted/30" />
            </div>
            <div className="h-7 w-24 rounded bg-muted/30" />
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Stat card ─────────────────────────────────────────────────────────────────

interface StatCardProps {
  label: string;
  icon: React.ReactNode;
  value: string;
  mono?: boolean;
  href?: string;
}

function StatCard({ label, icon, value, mono = false, href }: StatCardProps) {
  const body = (
    <div className="bg-card border border-border/60 rounded-2xl p-4 flex flex-col gap-3 h-full">
      {/* Label row */}
      <div className="flex items-center gap-2 min-w-0">
        <span className="text-muted-foreground/70 shrink-0">{icon}</span>
        <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground/70 truncate">
          {label}
        </span>
      </div>

      {/* Value */}
      <p
        className={cn(
          'text-2xl font-medium text-foreground leading-none truncate',
          mono && 'font-mono tabular-nums',
        )}
      >
        {value || '—'}
      </p>
    </div>
  );

  if (href) {
    return (
      <Link
        href={href}
        className="block group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand-accent)]/60 rounded-2xl hover:opacity-90 transition-opacity"
      >
        {body}
      </Link>
    );
  }

  return <div>{body}</div>;
}

// ── Severity status pill ──────────────────────────────────────────────────────

function SeverityPill({ severity }: { severity: string }) {
  const sevLabel = severity ? severity.toUpperCase() : 'UNKNOWN';
  const pillClass = severityPillClass(severity ?? '');
  const pulsing = ['critical', 'high'].includes((severity ?? '').toLowerCase());

  return (
    <div className={pillClass}>
      <span
        className={cn('pill-dot', pulsing && 'animate-pulse')}
        style={{ background: 'currentColor' }}
      />
      {sevLabel}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function FeaturedIncidentHero({ data, loading = false }: FeaturedIncidentHeroProps) {
  if (loading) return <HeroSkeleton />;

  const hasIncident = !!data?.incident_number;

  return (
    <div className="space-y-4 pt-1">
      {/* ── Hero row ── */}
      <div className="flex items-start justify-between gap-4">
        {/* Left column */}
        <div className="min-w-0 flex-1">
          {/* Eyebrow */}
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-muted-foreground/60 mb-2">
            AEGIS Command · {eyebrowDate()}
          </p>

          {/* Greeting */}
          <h1 className="text-3xl md:text-4xl font-semibold tracking-[-0.025em] leading-none">
            {hasIncident && data ? (
              <>
                <span className="text-muted-foreground/70">Hello,&nbsp;</span>
                <Link
                  href="/dashboard/response"
                  className="text-[var(--brand-accent)] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand-accent)]/60 rounded-md"
                >
                  <span className="text-muted-foreground/60">#{data.incident_number}</span>
                </Link>
              </>
            ) : (
              <span className="text-foreground">Hello, no active incidents</span>
            )}
          </h1>

          {/* Sub-row — only when there is an incident */}
          {hasIncident && data && (
            <div className="flex items-center gap-3 mt-3 text-[12px] text-muted-foreground flex-wrap">
              {/* Severity dot */}
              <span
                className="w-1.5 h-1.5 rounded-full shrink-0"
                style={{ background: severityColor(data.severity) }}
              />
              {/* Severity label */}
              <span
                className="font-mono text-[10px] uppercase tracking-wider shrink-0"
                style={{ color: severityColor(data.severity) }}
              >
                {data.severity}
              </span>

              <span className="text-muted-foreground/40" aria-hidden>·</span>

              {/* Incident title */}
              <span className="truncate max-w-[60ch]">{data.title}</span>

              <span className="text-muted-foreground/40 shrink-0" aria-hidden>·</span>

              {/* Relative time */}
              <span className="font-mono text-[11px] shrink-0">
                {relativeTime(data.detected_at)}
              </span>
            </div>
          )}
        </div>

        {/* Right column */}
        <div className="flex items-center gap-2 shrink-0">
          {hasIncident && data && <SeverityPill severity={data.severity} />}

          <button
            type="button"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-card border border-border text-[12px] text-foreground/90 hover:bg-white/[0.04] hover:border-white/[0.12] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand-accent)]/60"
          >
            <Download size={13} />
            Export
          </button>
        </div>
      </div>

      {/* ── Stat cards ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard
          label="Affected Asset"
          icon={<HardDrive size={16} />}
          value={data?.affected_asset ?? '—'}
        />

        <StatCard
          label="MITRE Technique"
          icon={<Crosshair size={16} />}
          value={data?.mitre_technique ?? '—'}
          href="/dashboard/threats/campaigns"
        />

        <StatCard
          label="Source IP"
          icon={<Network size={16} />}
          value={data?.source_ip ?? '—'}
          mono
          href={
            data?.source_ip
              ? `/dashboard/ip-intel?ip=${encodeURIComponent(data.source_ip)}`
              : undefined
          }
        />

        <StatCard
          label="Confidence"
          icon={<Shield size={16} />}
          value={data ? formatConfidence(data.confidence) : '—'}
        />
      </div>
    </div>
  );
}
