'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { Target02Icon, ArrowLeft02Icon } from 'hugeicons-react';
import { LoadingState } from '@/components/shared/LoadingState';
import { api } from '@/lib/api';
import { formatDate } from '@/lib/utils';

interface Campaign {
  cluster_id: string;
  ttp_fingerprint: string;
  mitre_technique: string | null;
  mitre_tactic: string | null;
  distinct_ips: number;
  total_incidents: number;
  first_seen: string | null;
  last_seen: string | null;
  sample_ips: string[];
  window_hours: number;
}

export default function CampaignsPage() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [windowHours, setWindowHours] = useState(24);
  const [minIps, setMinIps] = useState(3);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const data = await api.threats.campaigns({
          window_hours: windowHours,
          min_distinct_ips: minIps,
          limit: 50,
        });
        setCampaigns(data.campaigns);
      } catch (e) {
        setError((e as Error).message || 'Failed to load campaigns');
        setCampaigns([]);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [windowHours, minIps]);

  if (loading) return <LoadingState />;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <div className="flex items-center gap-2 text-sm text-white/50 mb-1">
            <Link href="/dashboard/threats" className="hover:text-white/80 flex items-center gap-1">
              <ArrowLeft02Icon size={14} /> Threats
            </Link>
            <span>/</span>
            <span>Campaigns</span>
          </div>
          <h1 className="text-2xl font-semibold text-white flex items-center gap-2">
            <Target02Icon size={24} className="text-[#22D3EE]" />
            TTP Campaigns
          </h1>
          <p className="text-sm text-white/50 mt-1">
            Clusters of incidents sharing a MITRE (tactic, technique) fingerprint across distinct source IPs.
            Surfaces IP-rotating actors. No auto-block — for human triage only.
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs">
          <label className="flex items-center gap-2 text-white/60">
            Window:
            <select
              value={windowHours}
              onChange={(e) => setWindowHours(Number(e.target.value))}
              className="bg-[#18181B] border border-white/[0.06] rounded-lg px-2 py-1 text-white"
            >
              <option value={1}>1h</option>
              <option value={6}>6h</option>
              <option value={24}>24h</option>
              <option value={72}>3d</option>
              <option value={168}>7d</option>
            </select>
          </label>
          <label className="flex items-center gap-2 text-white/60">
            Min IPs:
            <select
              value={minIps}
              onChange={(e) => setMinIps(Number(e.target.value))}
              className="bg-[#18181B] border border-white/[0.06] rounded-lg px-2 py-1 text-white"
            >
              <option value={2}>2</option>
              <option value={3}>3</option>
              <option value={5}>5</option>
              <option value={10}>10</option>
            </select>
          </label>
        </div>
      </div>

      {error && (
        <div className="bg-[#18181B] border border-[#F97316]/40 rounded-2xl p-4 text-sm text-[#F97316]">
          {error}
        </div>
      )}

      {campaigns.length === 0 ? (
        <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-12 text-center">
          <Target02Icon size={32} className="mx-auto text-white/20 mb-3" />
          <p className="text-white/60">No TTP campaigns detected in the last {windowHours}h</p>
          <p className="text-xs text-white/40 mt-2">
            A campaign requires {minIps}+ distinct source IPs triggering incidents with the same MITRE TTP fingerprint.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {campaigns.map((c) => (
            <article
              key={c.cluster_id}
              className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-5 hover:border-[#22D3EE]/30 transition-colors"
            >
              <header className="flex items-start justify-between gap-3 mb-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-[#22D3EE] bg-[#22D3EE]/10 px-2 py-0.5 rounded">
                      {c.cluster_id}
                    </span>
                    {c.mitre_tactic && (
                      <span className="text-xs text-white/60 bg-white/[0.04] px-2 py-0.5 rounded">
                        {c.mitre_tactic}
                      </span>
                    )}
                  </div>
                  <h3 className="text-lg font-semibold text-white mt-2 font-mono">
                    {c.mitre_technique || 'unknown'}
                  </h3>
                </div>
                <div className="text-right">
                  <div className="text-2xl font-semibold text-[#F97316]">{c.distinct_ips}</div>
                  <div className="text-xs text-white/40">distinct IPs</div>
                </div>
              </header>

              <div className="grid grid-cols-3 gap-3 mb-4 text-center">
                <div className="bg-white/[0.02] rounded-lg p-2">
                  <div className="text-xs text-white/40">Incidents</div>
                  <div className="text-base font-mono text-white">{c.total_incidents}</div>
                </div>
                <div className="bg-white/[0.02] rounded-lg p-2">
                  <div className="text-xs text-white/40">First seen</div>
                  <div className="text-xs font-mono text-white">
                    {c.first_seen ? formatDate(c.first_seen) : '—'}
                  </div>
                </div>
                <div className="bg-white/[0.02] rounded-lg p-2">
                  <div className="text-xs text-white/40">Last seen</div>
                  <div className="text-xs font-mono text-white">
                    {c.last_seen ? formatDate(c.last_seen) : '—'}
                  </div>
                </div>
              </div>

              {c.sample_ips.length > 0 && (
                <div>
                  <div className="text-xs text-white/40 mb-2">Sample source IPs:</div>
                  <div className="flex flex-wrap gap-1.5">
                    {c.sample_ips.map((ip) => (
                      <Link
                        key={ip}
                        href={`/dashboard/ip-intel?ip=${encodeURIComponent(ip)}`}
                        className="text-xs font-mono text-white/70 bg-white/[0.04] hover:bg-[#22D3EE]/10 hover:text-[#22D3EE] px-2 py-1 rounded transition-colors"
                      >
                        {ip}
                      </Link>
                    ))}
                  </div>
                </div>
              )}
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
