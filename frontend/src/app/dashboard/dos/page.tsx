'use client';

import { useCallback, useEffect, useState } from 'react';
import { Shield, Activity, Network, Zap, ShieldAlert } from 'lucide-react';
import { api } from '@/lib/api';
import { cn, formatDate } from '@/lib/utils';
import { LoadingState } from '@/components/shared/LoadingState';
import { Card, CardContent } from '@/components/ui/card';
import { Panel } from '@/components/aegis/Panel';
import { EmptyState } from '@/components/aegis/EmptyState';

interface DosThresholds {
  per_ip_rps: number;
  subnet_rps: number;
  global_rps: number;
  expensive_rpm: number;
  concurrency_per_ip: number;
  block_duration_s: number;
}

interface DosCounters {
  tracked_ips: number;
  tracked_subnets: number;
  events_published: number;
  blocks: number;
}

interface DosOffender {
  ip: string;
  rps: number;
  blocked: boolean;
  reason?: string;
  first_seen?: string | null;
  country?: string;
  asn?: string;
}

interface DosStatus {
  mode: string;
  under_attack: boolean;
  global_rps: number;
  global_window_s: number;
  netshield_enabled: boolean;
  netshield_env_gate: boolean;
  thresholds: DosThresholds;
  counters: DosCounters;
  top_offenders: DosOffender[];
  available: boolean;
}

const POLL_INTERVAL_MS = 5000;

function StatCard({
  label,
  value,
  sub,
  accent,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
}) {
  return (
    <Card className="bg-[#18181B] border border-white/[0.06] rounded-2xl">
      <CardContent className="p-4">
        <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
          {label}
        </p>
        <p
          className="mt-2 text-[24px] leading-none font-bold font-mono tabular-nums text-foreground"
          style={accent ? { color: accent } : undefined}
        >
          {value}
        </p>
        {sub && <p className="mt-1.5 text-[11px] font-mono text-muted-foreground/70">{sub}</p>}
      </CardContent>
    </Card>
  );
}

function ThresholdRow({
  label,
  value,
  unit,
}: {
  label: string;
  value: number;
  unit: string;
}) {
  return (
    <div className="flex items-center justify-between px-4 py-3 border-b border-border last:border-b-0">
      <span className="text-[12.5px] text-muted-foreground">{label}</span>
      <span className="text-[13px] font-mono tabular-nums text-foreground">
        {value}
        <span className="ml-1 text-[10px] text-muted-foreground/60 uppercase">{unit}</span>
      </span>
    </div>
  );
}

export default function DosShieldPage() {
  const [status, setStatus] = useState<DosStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadStatus = useCallback(async () => {
    try {
      const data = await api.dos.status();
      setStatus(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load DoS Shield status');
      setStatus(null);
    }
  }, []);

  useEffect(() => {
    let mounted = true;
    (async () => {
      await loadStatus();
      if (mounted) setLoading(false);
    })();
    const interval = setInterval(loadStatus, POLL_INTERVAL_MS);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [loadStatus]);

  if (loading) return <LoadingState message="Loading DoS Shield status..." />;

  if (error && !status) {
    return (
      <div className="space-y-6 animate-fade-in">
        <div className="min-w-0">
          <h1 className="text-[22px] sm:text-[28px] font-bold text-foreground tracking-tight">
            DoS Shield
          </h1>
          <p className="text-sm text-muted-foreground mt-1 hidden sm:block">
            Volumetric and application-layer abuse detection
          </p>
        </div>
        <Panel variant="danger" padding="sm">
          <span className="text-[13px] text-[var(--danger)]">{error}</span>
        </Panel>
      </div>
    );
  }

  if (status && !status.available) {
    return (
      <div className="space-y-6 animate-fade-in">
        <div className="min-w-0">
          <h1 className="text-[22px] sm:text-[28px] font-bold text-foreground tracking-tight">
            DoS Shield
          </h1>
          <p className="text-sm text-muted-foreground mt-1 hidden sm:block">
            Volumetric and application-layer abuse detection
          </p>
        </div>
        <Card className="bg-[#18181B] border border-white/[0.06] rounded-2xl">
          <CardContent className="p-0">
            <EmptyState
              icon={<ShieldAlert className="w-8 h-8" />}
              title="DoS Shield unavailable"
              description="The rate-limiting engine is not initialized on this instance. Enable it in the AEGIS configuration to begin monitoring."
              size="lg"
            />
          </CardContent>
        </Card>
      </div>
    );
  }

  if (!status) return null;

  const { thresholds, counters, top_offenders } = status;
  const isMonitor = status.mode === 'monitor';
  const globalOver = status.global_rps > thresholds.global_rps;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3 min-w-0">
          <div className="p-2 rounded-xl bg-[var(--brand-accent)]/10 border border-[var(--brand-accent)]/20 shrink-0">
            <Shield className="w-5 h-5 text-[var(--brand-accent)]" />
          </div>
          <div className="min-w-0">
            <h1 className="text-[22px] sm:text-[28px] font-bold text-foreground tracking-tight">
              DoS Shield
            </h1>
            <p className="text-sm text-muted-foreground mt-0.5 hidden sm:block">
              Volumetric and application-layer abuse detection
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Mode badge */}
          <span
            className={cn(
              'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-semibold uppercase tracking-wider border',
              isMonitor
                ? 'text-[#F97316] bg-[#F97316]/10 border-[#F97316]/25'
                : 'text-[var(--success)] bg-[var(--success)]/10 border-[var(--success)]/25',
            )}
          >
            <span
              className={cn(
                'w-1.5 h-1.5 rounded-full',
                isMonitor ? 'bg-[#F97316]' : 'bg-[var(--success)]',
              )}
            />
            {isMonitor ? 'Monitor' : 'Active Enforcing'}
          </span>

          {/* Attack state */}
          {status.under_attack ? (
            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-semibold uppercase tracking-wider text-[var(--danger)] bg-[var(--danger)]/10 border border-[var(--danger)]/25">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full rounded-full bg-[var(--danger)] opacity-75 animate-ping" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-[var(--danger)]" />
              </span>
              Under Attack
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-medium text-muted-foreground bg-muted/40 border border-border">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--brand-accent)]" />
              All clear
            </span>
          )}
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <StatCard
          label="Global RPS"
          value={status.global_rps}
          sub={`limit ${thresholds.global_rps} rps`}
          accent={globalOver ? 'var(--danger)' : 'var(--brand-accent)'}
        />
        <StatCard label="Tracked IPs" value={counters.tracked_ips} />
        <StatCard label="Tracked /24s" value={counters.tracked_subnets} />
        <StatCard label="Events published" value={counters.events_published} />
        <StatCard
          label="Blocks"
          value={counters.blocks}
          accent={counters.blocks > 0 ? '#F97316' : undefined}
        />
      </div>

      {/* Thresholds + Network tier */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Thresholds */}
        <Panel padding="none">
          <div className="flex items-center gap-2 px-4 sm:px-6 py-4 border-b border-border">
            <Activity className="w-4 h-4 text-[var(--brand-accent)]" />
            <h2 className="text-[13px] font-medium uppercase tracking-wider text-foreground">
              Thresholds
            </h2>
            <span className="text-[11px] text-muted-foreground ml-1 font-mono">
              window {status.global_window_s}s
            </span>
          </div>
          <div>
            <ThresholdRow label="Per-IP request rate" value={thresholds.per_ip_rps} unit="rps" />
            <ThresholdRow label="Subnet (/24) rate" value={thresholds.subnet_rps} unit="rps" />
            <ThresholdRow label="Global rate" value={thresholds.global_rps} unit="rps" />
            <ThresholdRow label="Expensive endpoints" value={thresholds.expensive_rpm} unit="rpm" />
            <ThresholdRow
              label="Concurrency per IP"
              value={thresholds.concurrency_per_ip}
              unit="conn"
            />
            <ThresholdRow label="Block duration" value={thresholds.block_duration_s} unit="s" />
          </div>
        </Panel>

        {/* Network tier */}
        <Panel padding="none">
          <div className="flex items-center gap-2 px-4 sm:px-6 py-4 border-b border-border">
            <Network className="w-4 h-4 text-[var(--brand)]" />
            <h2 className="text-[13px] font-medium uppercase tracking-wider text-foreground">
              Network tier (Pi gateway)
            </h2>
          </div>
          <div className="p-4 sm:p-6 space-y-4">
            <div className="flex items-center justify-between gap-3">
              <span className="text-[12.5px] text-muted-foreground">NetShield status</span>
              {status.netshield_enabled ? (
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-semibold uppercase tracking-wider text-[#F97316] bg-[#F97316]/10 border border-[#F97316]/25">
                  <Zap className="w-3 h-3" />
                  Enabled
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-medium uppercase tracking-wider text-muted-foreground bg-muted/40 border border-border">
                  Disabled (gated)
                </span>
              )}
            </div>
            <p className="text-[12px] text-muted-foreground/70 leading-relaxed">
              Per-source iptables rate-limiting. Enable via runbook when ready.
            </p>
            {!status.netshield_env_gate && !status.netshield_enabled && (
              <p className="text-[11px] font-mono text-muted-foreground/50">
                Env gate closed — set the NetShield flag on the Pi executor to allow enablement.
              </p>
            )}
          </div>
        </Panel>
      </div>

      {/* Top offenders */}
      <Panel padding="none">
        <div className="flex items-center gap-2 px-4 sm:px-6 py-4 border-b border-border">
          <ShieldAlert className="w-4 h-4 text-[#F97316]" />
          <h2 className="text-[13px] font-medium uppercase tracking-wider text-foreground">
            Top offenders
          </h2>
          <span className="text-[11px] text-muted-foreground ml-1 font-mono">
            {top_offenders.length} tracked
          </span>
        </div>

        {top_offenders.length === 0 ? (
          <EmptyState
            icon={<Shield className="w-8 h-8" />}
            title="No offenders — monitoring nominal"
            description="No source has exceeded a rate threshold. Offenders will surface here as traffic anomalies are detected."
            size="lg"
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-border">
                  <th className="px-4 sm:px-6 py-2.5 text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                    IP
                  </th>
                  <th className="px-4 py-2.5 text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                    Reason
                  </th>
                  <th className="px-4 py-2.5 text-[10px] font-mono uppercase tracking-wider text-muted-foreground text-right">
                    Rate
                  </th>
                  <th className="px-4 sm:px-6 py-2.5 text-[10px] font-mono uppercase tracking-wider text-muted-foreground text-right">
                    First seen
                  </th>
                </tr>
              </thead>
              <tbody>
                {top_offenders.map((o, i) => (
                  <tr
                    key={`${o.ip}-${i}`}
                    className="border-b border-border last:border-b-0 hover:bg-muted/30 transition-colors"
                  >
                    <td className="px-4 sm:px-6 py-3">
                      <div className="flex items-center gap-2">
                        <span className="text-[12px] font-mono text-foreground">{o.ip}</span>
                        {o.blocked ? (
                          <span className="text-[9px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded text-[var(--success)] bg-[var(--success)]/10 border border-[var(--success)]/20">
                            blocked
                          </span>
                        ) : (
                          <span className="text-[9px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded text-muted-foreground bg-muted/40 border border-border">
                            watch
                          </span>
                        )}
                      </div>
                      {(o.country || o.asn) && (
                        <span className="text-[10px] font-mono text-muted-foreground/50">
                          {[o.country, o.asn].filter(Boolean).join(' · ')}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-[12px] text-muted-foreground">
                      {o.reason || '—'}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <span
                        className="text-[12px] font-mono tabular-nums font-medium"
                        style={{
                          color:
                            o.rps > thresholds.per_ip_rps
                              ? 'var(--danger)'
                              : 'var(--foreground)',
                        }}
                      >
                        {o.rps}
                        <span className="ml-1 text-[9px] text-muted-foreground/60 uppercase">
                          rps
                        </span>
                      </span>
                    </td>
                    <td className="px-4 sm:px-6 py-3 text-right text-[11px] font-mono text-muted-foreground">
                      {o.first_seen ? formatDate(o.first_seen) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
