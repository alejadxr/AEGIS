'use client';

import { useState, useEffect } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { TrendingUp, RefreshCw } from 'lucide-react';
import { cn } from '@/lib/utils';

interface RaaSDataPoint {
  date: string;
  [group: string]: string | number;
}

interface RaaSGroupSummary {
  name: string;
  activity_score: number;
  color: string;
}

interface RaaSApiResponse {
  timeline?: RaaSDataPoint[];
  groups?: RaaSGroupSummary[];
}

const GROUP_COLORS = [
  '#22D3EE', // cyan (brand)
  '#F97316', // orange (accent)
  '#A78BFA', // violet
  '#34D399', // emerald
  '#FB923C', // amber
  '#F472B6', // pink
];

export function RaaSGroupTimeline() {
  const [data, setData] = useState<RaaSDataPoint[]>([]);
  const [groups, setGroups] = useState<RaaSGroupSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  async function load() {
    setLoading(true);
    setError(false);
    try {
      const apiKey = typeof window !== 'undefined' ? localStorage.getItem('aegis_api_key') : null;
      const res = await fetch('/api/v1/ransomware/raas-groups', {
        headers: apiKey ? { 'X-API-Key': apiKey } : {},
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json: RaaSApiResponse = await res.json();
      setData(json.timeline ?? []);
      setGroups(
        (json.groups ?? []).map((g, i) => ({
          ...g,
          color: g.color ?? GROUP_COLORS[i % GROUP_COLORS.length],
        }))
      );
    } catch {
      setData([]);
      setGroups([]);
      setError(true);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-6">
        <div className="h-4 bg-white/[0.04] rounded w-40 mb-4 animate-pulse" />
        <div className="h-[180px] bg-white/[0.04] rounded-xl animate-pulse" />
      </div>
    );
  }

  const groupKeys = groups.length > 0
    ? groups.map((g) => g.name)
    : data.length > 0
      ? Object.keys(data[0]).filter((k) => k !== 'date')
      : [];

  return (
    <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl overflow-hidden">
      <div className="flex items-center justify-between px-5 py-4 border-b border-white/[0.06]">
        <div className="flex items-center gap-2">
          <TrendingUp className="w-4 h-4 text-[#22D3EE]" />
          <span className="text-[13px] font-semibold text-foreground">RaaS Group Activity</span>
        </div>
        <button
          onClick={load}
          className="p-1.5 rounded-lg text-muted-foreground/60 hover:text-foreground hover:bg-white/[0.06] transition-colors"
          title="Refresh"
        >
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
      </div>

      {data.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-10 px-6 text-center">
          <div className="w-10 h-10 rounded-xl bg-white/[0.04] flex items-center justify-center mb-3">
            <TrendingUp className="w-5 h-5 text-muted-foreground/40" />
          </div>
          <p className="text-[13px] text-muted-foreground">
            {error ? 'Could not reach the RaaS intel endpoint.' : 'No RaaS groups tracked yet — refresh feeds via Settings.'}
          </p>
          {error && (
            <p className="text-[11px] text-muted-foreground/60 mt-1">
              Endpoint: <span className="font-mono">/api/v1/ransomware/raas-groups</span>
            </p>
          )}
        </div>
      ) : (
        <div className="px-2 py-4">
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={data} margin={{ top: 4, right: 12, bottom: 0, left: -20 }}>
              <defs>
                {groupKeys.map((key, i) => {
                  const color = groups.find((g) => g.name === key)?.color ?? GROUP_COLORS[i % GROUP_COLORS.length];
                  return (
                    <linearGradient key={key} id={`grad-${key}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={color} stopOpacity={0.25} />
                      <stop offset="95%" stopColor={color} stopOpacity={0.02} />
                    </linearGradient>
                  );
                })}
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
              <XAxis
                dataKey="date"
                tick={{ fontSize: 10, fill: 'rgba(255,255,255,0.4)', fontFamily: 'var(--font-mono)' }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fontSize: 10, fill: 'rgba(255,255,255,0.4)', fontFamily: 'var(--font-mono)' }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  background: '#18181B',
                  border: '1px solid rgba(255,255,255,0.08)',
                  borderRadius: '10px',
                  fontSize: '12px',
                  color: 'rgba(255,255,255,0.85)',
                }}
                cursor={{ stroke: 'rgba(255,255,255,0.08)' }}
              />
              <Legend
                wrapperStyle={{ fontSize: '11px', color: 'rgba(255,255,255,0.5)', paddingTop: '8px' }}
              />
              {groupKeys.map((key, i) => {
                const color = groups.find((g) => g.name === key)?.color ?? GROUP_COLORS[i % GROUP_COLORS.length];
                return (
                  <Area
                    key={key}
                    type="monotone"
                    dataKey={key}
                    stroke={color}
                    strokeWidth={1.5}
                    fill={`url(#grad-${key})`}
                    dot={false}
                    activeDot={{ r: 3, strokeWidth: 0, fill: color }}
                  />
                );
              })}
            </AreaChart>
          </ResponsiveContainer>

          {groups.length > 0 && (
            <div className="flex flex-wrap gap-2 px-3 pt-3 border-t border-white/[0.04] mt-2">
              {groups.map((g) => (
                <div key={g.name} className="flex items-center gap-1.5">
                  <span
                    className="w-2 h-2 rounded-full shrink-0"
                    style={{ background: g.color }}
                  />
                  <span className="text-[10px] text-muted-foreground/70">{g.name}</span>
                  <span
                    className={cn(
                      'text-[9px] font-mono px-1.5 py-0.5 rounded',
                      g.activity_score >= 80
                        ? 'text-[var(--danger)] bg-[var(--danger)]/10'
                        : g.activity_score >= 50
                          ? 'text-[var(--warning)] bg-[var(--warning)]/10'
                          : 'text-muted-foreground/50 bg-white/[0.04]'
                    )}
                  >
                    {g.activity_score}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
