'use client';

import * as React from 'react';
import Link from 'next/link';
import { Panel, StatusBadge } from '@/components/aegis';
import {
  ChevronDown,
  ChevronUp,
  ExternalLink,
  List as ListIcon,
  BarChart3 as ChartIconLR,
  CheckCircle2,
  Globe as GlobeIcon,
} from 'lucide-react';
import { api } from '@/lib/api';
import { formatDate } from '@/lib/utils';
import { resolveTactic, severityTone, countryFlagEmoji } from './mitreTactics';
import { mitreLabel, mitreInfo } from '@/lib/mitre';
import type { CampaignSummary } from './KPIStrip';

type Detail = Awaited<ReturnType<typeof api.threats.campaignDetail>>;

export interface CampaignCardProps {
  campaign: CampaignSummary & {
    ttp_fingerprint: string;
    first_seen: string | null;
    sample_ips: string[];
    window_hours: number;
  };
  defaultOpen?: boolean;
}

export function CampaignCard({ campaign, defaultOpen = false }: CampaignCardProps) {
  const [open, setOpen] = React.useState(defaultOpen);
  const [detail, setDetail] = React.useState<Detail | null>(null);
  const [loadingDetail, setLoadingDetail] = React.useState(false);
  const [detailError, setDetailError] = React.useState<string | null>(null);
  const [tab, setTab] = React.useState<'overview' | 'ips' | 'incidents' | 'timeline'>('overview');
  const [investigated, setInvestigated] = React.useState<boolean>(false);

  const tactic = resolveTactic(campaign.mitre_tactic);
  const isActive = campaign.last_seen ? Date.now() - new Date(campaign.last_seen).getTime() <= 24 * 3600 * 1000 : false;

  React.useEffect(() => {
    if (!open || detail) return;
    let cancelled = false;
    setLoadingDetail(true);
    setDetailError(null);
    api.threats
      .campaignDetail(campaign.cluster_id, Math.max(168, campaign.window_hours || 168))
      .then((d) => {
        if (!cancelled) {
          setDetail(d);
          setInvestigated(!!d.investigated);
        }
      })
      .catch((err) => {
        if (!cancelled) setDetailError((err as Error).message || 'Failed to load detail');
      })
      .finally(() => {
        if (!cancelled) setLoadingDetail(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, detail, campaign.cluster_id, campaign.window_hours]);

  const handleMarkInvestigated = async () => {
    try {
      await api.threats.markCampaignInvestigated(campaign.cluster_id);
      setInvestigated(true);
    } catch (e) {
      setDetailError((e as Error).message);
    }
  };

  return (
    <Panel
      as="article"
      padding="none"
      className="overflow-hidden"
      data-active={isActive}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="w-full text-left flex items-center gap-3 px-4 py-3 sm:px-5 sm:py-4 hover:bg-[color-mix(in_oklab,var(--brand-accent)_4%,transparent)] focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand-accent)]/60 min-h-[64px]"
      >
        {/* Pulse */}
        <span
          aria-hidden
          className={`relative inline-flex h-2.5 w-2.5 rounded-full shrink-0 ${
            isActive ? 'bg-[var(--danger)]' : 'bg-muted-foreground/40'
          }`}
        >
          {isActive && (
            <span className="absolute inset-0 rounded-full bg-[var(--danger)] motion-safe:animate-ping opacity-70" />
          )}
        </span>

        {/* Cluster ID + technique */}
        <div className="flex flex-col min-w-0 sm:flex-row sm:items-center sm:gap-3">
          <span className="text-[11px] font-mono text-muted-foreground">{campaign.cluster_id}</span>
          <span className="text-[13px] sm:text-[14px] font-semibold text-foreground font-mono truncate">
            {campaign.mitre_technique ? mitreLabel(campaign.mitre_technique) : 'unspecified'}
          </span>
          {tactic && (
            <span
              className="hidden sm:inline-flex text-[10px] uppercase tracking-[0.12em] px-2 py-0.5 rounded-md border border-border"
              style={{ background: `color-mix(in oklab, ${tactic.hue} 14%, transparent)` }}
            >
              {tactic.label}
            </span>
          )}
        </div>

        <div className="hidden md:flex items-center gap-4 ml-auto text-[12px] tabular-nums text-muted-foreground">
          <span><span className="text-foreground">{campaign.distinct_ips}</span> IPs</span>
          <span><span className="text-foreground">{campaign.total_incidents}</span> incidents</span>
          <span>last {campaign.last_seen ? formatDate(campaign.last_seen) : '—'}</span>
        </div>

        <StatusBadge
          variant={isActive ? 'danger' : 'muted'}
          size="sm"
          pulse={isActive}
          className="hidden sm:inline-flex ml-2"
        >
          {isActive ? 'Active' : 'Dormant'}
        </StatusBadge>

        <span className="ml-auto md:ml-0 text-muted-foreground" aria-hidden>
          {open ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </span>
      </button>

      {open && (
        <div className="border-t border-border px-4 py-4 sm:px-5 sm:py-5 space-y-4 bg-[color-mix(in_oklab,var(--brand-accent)_2%,transparent)]">
          {loadingDetail && (
            <p className="text-[12px] text-muted-foreground">Loading drill-down…</p>
          )}
          {detailError && (
            <p className="text-[12px] text-[var(--danger)]">{detailError}</p>
          )}

          {detail && (
            <>
              {/* Plain-language summary */}
              <p className="text-[13px] text-foreground/90 leading-relaxed">
                An attacker (or coordinated group) performed{' '}
                <span className="text-foreground font-medium">{detail.technique_detail.tactic}</span>{' '}
                using <span className="text-foreground font-mono">{detail.technique_detail.name}</span> from{' '}
                <span className="text-foreground tabular-nums">{detail.distinct_ips_count}</span> distinct IPs
                over <span className="tabular-nums">{detail.duration_hours}h</span>
                {detail.first_seen && (
                  <> ({formatDate(detail.first_seen)} → {formatDate(detail.last_seen)})</>
                )}
                . <span className="text-foreground">Recommended action:</span>{' '}
                <span className="text-muted-foreground">{detail.recommended_action}</span>
              </p>

              {/* Action row */}
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={handleMarkInvestigated}
                  disabled={investigated}
                  className="inline-flex items-center gap-2 rounded-lg border border-border bg-card px-3 py-2 text-[12px] text-foreground hover:border-[var(--brand-accent)]/40 transition-colors disabled:opacity-60 min-h-[36px] focus:outline-none focus:ring-2 focus:ring-[var(--brand-accent)]/60"
                >
                  <CheckCircle2 size={14} aria-hidden />
                  <span>{investigated ? 'Investigated' : 'Mark investigated'}</span>
                </button>
                {detail.investigated && (
                  <span className="text-[11px] text-muted-foreground">
                    by {detail.investigated.by_email || 'analyst'} · {formatDate(detail.investigated.at)}
                  </span>
                )}
              </div>

              {/* Tabs */}
              <div role="tablist" aria-label="Campaign sections" className="flex gap-1 border-b border-border">
                {(
                  [
                    { id: 'overview', label: 'Overview', icon: ChartIconLR },
                    { id: 'ips', label: `Attacker IPs (${detail.ips.length})`, icon: GlobeIcon },
                    { id: 'incidents', label: `Incidents (${detail.incidents.length})`, icon: ListIcon },
                    { id: 'timeline', label: 'Timeline', icon: ChartIconLR },
                  ] as const
                ).map((t) => (
                  <button
                    key={t.id}
                    role="tab"
                    aria-selected={tab === t.id}
                    onClick={() => setTab(t.id)}
                    className={`inline-flex items-center gap-1.5 px-3 py-2 text-[12px] border-b-2 -mb-px transition-colors min-h-[36px] focus:outline-none focus:ring-2 focus:ring-[var(--brand-accent)]/60 ${
                      tab === t.id
                        ? 'border-[var(--brand-accent)] text-foreground'
                        : 'border-transparent text-muted-foreground hover:text-foreground'
                    }`}
                  >
                    <t.icon size={14} aria-hidden />
                    {t.label}
                  </button>
                ))}
              </div>

              {tab === 'overview' && <OverviewTab detail={detail} />}
              {tab === 'ips' && <IPsTab ips={detail.ips} />}
              {tab === 'incidents' && <IncidentsTab incidents={detail.incidents} />}
              {tab === 'timeline' && <TimelineTab incidents={detail.incidents} />}
            </>
          )}
        </div>
      )}
    </Panel>
  );
}

function OverviewTab({ detail }: { detail: Detail }) {
  const sevEntries = Object.entries(detail.severity_distribution);
  const total = sevEntries.reduce((a, [, n]) => a + n, 0);
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div className="space-y-2">
        <div className="text-[10px] uppercase tracking-[0.14em] text-muted-foreground">Technique</div>
        <div className="font-mono text-[13px] text-foreground">{detail.technique_detail.id || '—'}</div>
        <div className="text-[13px] text-foreground">{detail.technique_detail.name}</div>
        {detail.technique_detail.id && (() => {
          const info = mitreInfo(detail.technique_detail.id);
          return info ? (
            <div className="text-[12px] text-muted-foreground italic">{info.plain}</div>
          ) : null;
        })()}
        <div className="text-[12px] text-muted-foreground">Tactic: {detail.technique_detail.tactic}</div>
        {detail.technique_detail.url && (
          <a
            href={detail.technique_detail.url}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 text-[12px] text-[var(--brand-accent)] hover:underline"
          >
            <ExternalLink size={12} aria-hidden /> attack.mitre.org
          </a>
        )}
      </div>
      <div className="space-y-2">
        <div className="text-[10px] uppercase tracking-[0.14em] text-muted-foreground">Severity distribution</div>
        <div className="flex h-2 rounded-full overflow-hidden border border-border">
          {sevEntries.map(([sev, n]) => {
            const tone = severityTone(sev);
            const pct = (n / total) * 100;
            const color = tone === 'danger' ? 'var(--danger)' : tone === 'warning' ? 'var(--warning)' : tone === 'accent' ? 'var(--brand-accent)' : 'var(--muted-foreground)';
            return (
              <span
                key={sev}
                title={`${sev}: ${n}`}
                aria-label={`${sev}: ${n}`}
                style={{ width: `${pct}%`, background: color }}
              />
            );
          })}
        </div>
        <div className="flex flex-wrap gap-2 text-[11px] text-muted-foreground">
          {sevEntries.map(([sev, n]) => (
            <span key={sev} className="tabular-nums">
              {sev}: <span className="text-foreground">{n}</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

function IPsTab({ ips }: { ips: Detail['ips'] }) {
  if (ips.length === 0) {
    return <p className="text-[12px] text-muted-foreground">No attacker IPs.</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-[12px]">
        <thead>
          <tr className="text-left text-[10px] uppercase tracking-[0.14em] text-muted-foreground">
            <th className="py-2 pr-3 font-medium">IP</th>
            <th className="py-2 pr-3 font-medium">Country</th>
            <th className="py-2 pr-3 font-medium">ASN / Org</th>
            <th className="py-2 pr-3 font-medium">Classification</th>
            <th className="py-2 pr-3 font-medium">Blocked</th>
            <th className="py-2 pr-3 font-medium" />
          </tr>
        </thead>
        <tbody>
          {ips.map((row) => (
            <tr key={row.ip} className="border-t border-border">
              <td className="py-2 pr-3 font-mono text-foreground">{row.ip}</td>
              <td className="py-2 pr-3">
                <span aria-hidden className="mr-1">{countryFlagEmoji(row.country || null)}</span>
                <span className="text-foreground">{row.country || '—'}</span>
              </td>
              <td className="py-2 pr-3 text-muted-foreground truncate max-w-[260px]">
                {row.asn ? <span className="font-mono">{row.asn}</span> : '—'}
                {row.org && <span> · {row.org}</span>}
              </td>
              <td className="py-2 pr-3">
                <ClassificationPill row={row} />
              </td>
              <td className="py-2 pr-3">
                {row.blocked ? (
                  <StatusBadge variant="success" size="sm">Blocked</StatusBadge>
                ) : (
                  <span className="text-muted-foreground">—</span>
                )}
              </td>
              <td className="py-2 pr-3 text-right">
                <Link
                  href={`/dashboard/ip-intel?ip=${encodeURIComponent(row.ip)}`}
                  className="text-[var(--brand-accent)] hover:underline"
                >
                  View →
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ClassificationPill({ row }: { row: Detail['ips'][number] }) {
  if (row.is_tor) return <StatusBadge variant="danger" size="sm">Tor</StatusBadge>;
  if (row.is_vpn) return <StatusBadge variant="warning" size="sm">VPN</StatusBadge>;
  if (row.classification) {
    const cls = row.classification.toLowerCase();
    if (cls.includes('malic')) return <StatusBadge variant="danger" size="sm">Malicious</StatusBadge>;
    if (cls.includes('suspic')) return <StatusBadge variant="warning" size="sm">{row.classification}</StatusBadge>;
    return <StatusBadge variant="muted" size="sm">{row.classification}</StatusBadge>;
  }
  if (row.error) return <span className="text-[11px] text-muted-foreground">enrichment failed</span>;
  return <span className="text-[11px] text-muted-foreground">unknown</span>;
}

function IncidentsTab({ incidents }: { incidents: Detail['incidents'] }) {
  if (incidents.length === 0) {
    return <p className="text-[12px] text-muted-foreground">No incidents in window.</p>;
  }
  return (
    <ul className="divide-y divide-border">
      {incidents.map((i) => (
        <li key={i.id} className="py-2 flex items-center gap-3 text-[12px]">
          <StatusBadge variant={severityTone(i.severity)} size="sm">{i.severity}</StatusBadge>
          <span className="text-foreground truncate flex-1">{i.title}</span>
          {i.source_ip && <span className="font-mono text-muted-foreground">{i.source_ip}</span>}
          <span className="text-muted-foreground tabular-nums">{i.detected_at ? formatDate(i.detected_at) : '—'}</span>
          <Link
            href={`/dashboard/response`}
            className="text-[var(--brand-accent)] hover:underline shrink-0"
          >
            Open →
          </Link>
        </li>
      ))}
    </ul>
  );
}

function TimelineTab({ incidents }: { incidents: Detail['incidents'] }) {
  // Lightweight in-house histogram (no recharts dep here to keep card light).
  const buckets = React.useMemo(() => {
    if (incidents.length < 2) return [];
    const times = incidents
      .map((i) => (i.detected_at ? new Date(i.detected_at).getTime() : null))
      .filter((t): t is number => t !== null)
      .sort((a, b) => a - b);
    if (times.length < 2) return [];
    const start = times[0];
    const end = times[times.length - 1];
    const bucketCount = Math.min(24, Math.max(6, Math.ceil((end - start) / (60 * 60 * 1000))));
    const width = (end - start) / bucketCount || 1;
    const arr = Array.from({ length: bucketCount }, (_, idx) => ({
      label: new Date(start + idx * width).toISOString().slice(11, 16),
      count: 0,
    }));
    for (const t of times) {
      const idx = Math.min(bucketCount - 1, Math.floor((t - start) / width));
      arr[idx].count += 1;
    }
    return arr;
  }, [incidents]);

  if (buckets.length === 0) {
    return <p className="text-[12px] text-muted-foreground">Need at least two incidents with timestamps to render a timeline.</p>;
  }
  const max = Math.max(...buckets.map((b) => b.count));
  return (
    <div className="flex items-end gap-1 h-[80px]" aria-label="Incidents over time">
      {buckets.map((b, i) => (
        <div
          key={i}
          className="flex-1 rounded-sm bg-[color-mix(in_oklab,var(--brand-accent)_45%,transparent)]"
          style={{ height: `${(b.count / max) * 100}%` }}
          title={`${b.label} · ${b.count} incident(s)`}
        />
      ))}
    </div>
  );
}
