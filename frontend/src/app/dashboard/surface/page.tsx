'use client';

import { useState, useEffect } from 'react';
import { Radar01Icon } from 'hugeicons-react';
import { Plus, Filter, Server, Globe, Cloud, Code, Wifi } from 'lucide-react';
import { DataTable } from '@/components/shared/DataTable';
import { SeverityBadge } from '@/components/shared/SeverityBadge';
import { StatusIndicator } from '@/components/shared/StatusIndicator';
import { Modal } from '@/components/shared/Modal';
import { LoadingState } from '@/components/shared/LoadingState';
import { api } from '@/lib/api';
import { cn, formatDate } from '@/lib/utils';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  LineChart,
  Line,
} from 'recharts';

interface PortEntry {
  port: number;
  service?: string;
}

interface AssetRow {
  id: string;
  hostname: string;
  ip_address: string;
  asset_type: string;
  ports: (number | PortEntry)[];
  risk_score: number;
  status: string;
  last_scan_at: string | null;
  [key: string]: unknown;
}

interface VulnRow {
  id: string;
  title: string;
  severity: string;
  cvss_score: number | null;
  cve_id: string | null;
  status: string;
  found_at: string;
  asset_id: string;
  [key: string]: unknown;
}

const tooltipStyle = {
  backgroundColor: '#0A0A0A',
  border: '1px solid rgba(255,255,255,0.04)',
  borderRadius: '8px',
  color: '#E5E5E5',
  fontSize: '12px',
  fontFamily: 'Azeret Mono, monospace',
  padding: '8px 12px',
};

const typeIcons: Record<string, typeof Server> = {
  server: Server,
  web: Globe,
  cloud: Cloud,
  api: Code,
  dns: Wifi,
};

function riskColor(score: number): string {
  if (score >= 7) return 'text-[#EF4444]';
  if (score >= 4) return 'text-[#F59E0B]';
  return 'text-[#22C55E]';
}

/** Strip fake "www.X.X.X.X" or "mail.X.X.X.X" hostname prefixes */
function cleanHostname(hostname: string): string {
  const fakePattern = /^(www|mail)\.(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/;
  const match = hostname.match(fakePattern);
  if (match) return match[2];
  return hostname;
}

function buildSeverityDist(vulns: VulnRow[]) {
  const counts: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  vulns.forEach((v) => {
    const key = v.severity.charAt(0).toUpperCase() + v.severity.slice(1).toLowerCase();
    if (key in counts) counts[key] += 1;
  });
  const colorMap: Record<string, string> = {
    Critical: '#EF4444',
    High: '#F97316',
    Medium: '#F59E0B',
    Low: '#3B82F6',
  };
  return Object.entries(counts)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value, color: colorMap[name] }));
}

function buildWeeklyTrend(vulns: VulnRow[]) {
  const days: string[] = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    days.push(d.toLocaleDateString('en-US', { weekday: 'short' }));
  }
  const counts = new Array(7).fill(0);
  const now = Date.now();
  vulns.forEach((v) => {
    const diffDays = Math.floor((now - new Date(v.found_at).getTime()) / 86400000);
    const idx = 6 - diffDays;
    if (idx >= 0 && idx < 7) counts[idx] += 1;
  });
  return days.map((date, i) => ({ date, vulns: counts[i] }));
}

export default function SurfacePage() {
  const [assets, setAssets] = useState<AssetRow[]>([]);
  const [vulns, setVulns] = useState<VulnRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [showScanModal, setShowScanModal] = useState(false);
  const [scanTarget, setScanTarget] = useState('');
  const [scanType, setScanType] = useState('full');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [tab, setTab] = useState<'assets' | 'vulns'>('assets');

  useEffect(() => {
    async function load() {
      try {
        const [a, v] = await Promise.allSettled([
          api.surface.assets(),
          api.surface.vulnerabilities(),
        ]);
        setAssets(a.status === 'fulfilled' ? a.value as AssetRow[] : []);
        setVulns(v.status === 'fulfilled' ? v.value as VulnRow[] : []);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const handleScan = async () => {
    if (!scanTarget.trim()) return;
    try {
      await api.surface.scan(scanTarget, scanType);
    } catch {
      // best effort
    }
    setShowScanModal(false);
    setScanTarget('');
  };

  const filteredVulns = severityFilter === 'all'
    ? vulns
    : vulns.filter((v) => v.severity === severityFilter);

  const assetColumns = [
    {
      key: 'hostname', label: 'Hostname', sortable: true,
      render: (row: AssetRow) => (
        <div className="flex items-center gap-2.5">
          {(() => {
            const Icon = typeIcons[row.asset_type] || Server;
            return <Icon className="w-3.5 h-3.5 text-[#737373]" />;
          })()}
          <span className="font-mono text-[#22D3EE] text-[13px]">{cleanHostname(row.hostname)}</span>
        </div>
      ),
    },
    { key: 'ip_address', label: 'IP Address', sortable: true, render: (row: AssetRow) => <span className="font-mono text-[#737373] text-[13px]">{row.ip_address}</span> },
    { key: 'asset_type', label: 'Type', sortable: true, render: (row: AssetRow) => <span className="capitalize text-[#737373] text-[13px]">{row.asset_type}</span> },
    {
      key: 'ports', label: 'Ports', render: (row: AssetRow) => {
        let portsList = row.ports;
        if (typeof portsList === 'string') {
          try { portsList = JSON.parse(portsList); } catch { portsList = []; }
        }
        if (!Array.isArray(portsList)) portsList = [];
        const formatted = portsList.map((p: number | PortEntry) =>
          typeof p === 'object' && p !== null
            ? (p as PortEntry).service ? `${(p as PortEntry).port} (${(p as PortEntry).service})` : String((p as PortEntry).port)
            : String(p)
        ).join(', ');
        return <span className="font-mono text-[11px] text-[#737373]">{formatted || '\u2014'}</span>;
      }
    },
    {
      key: 'risk_score', label: 'Risk', sortable: true,
      render: (row: AssetRow) => {
        if (!row.risk_score || row.risk_score === 0) {
          return <span className="text-[#525252] text-[13px] font-mono">{'\u2014'}</span>;
        }
        return (
          <span className={cn('font-mono font-bold text-[15px] tabular-nums', riskColor(row.risk_score))}>
            {row.risk_score.toFixed(1)}
          </span>
        );
      },
    },
    { key: 'status', label: 'Status', render: (row: AssetRow) => <StatusIndicator status={row.status} label={row.status} /> },
    { key: 'last_scan_at', label: 'Last Scan', sortable: true, render: (row: AssetRow) => <span className="text-[#737373] text-[11px] font-mono">{formatDate(row.last_scan_at)}</span> },
  ];

  const vulnColumns = [
    { key: 'title', label: 'Vulnerability', sortable: true, render: (row: VulnRow) => <span className="text-[13px] text-[#E5E5E5] font-medium">{row.title}</span> },
    { key: 'severity', label: 'Severity', sortable: true, render: (row: VulnRow) => <SeverityBadge severity={row.severity} /> },
    { key: 'cvss_score', label: 'CVSS', sortable: true, render: (row: VulnRow) => <span className="font-mono text-[13px] text-[#E5E5E5]">{row.cvss_score?.toFixed(1) || '-'}</span> },
    { key: 'cve_id', label: 'CVE', render: (row: VulnRow) => <span className="font-mono text-[#737373] text-[11px]">{row.cve_id || '-'}</span> },
    { key: 'status', label: 'Status', render: (row: VulnRow) => <StatusIndicator status={row.status} label={row.status} /> },
    { key: 'found_at', label: 'Found', sortable: true, render: (row: VulnRow) => <span className="text-[#737373] text-[11px] font-mono">{formatDate(row.found_at)}</span> },
  ];

  if (loading) return <LoadingState message="Loading attack surface data..." />;

  const severityDist = buildSeverityDist(vulns);
  const trendData = buildWeeklyTrend(vulns);
  const hasVulns = vulns.length > 0;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-[22px] sm:text-[28px] font-bold text-[#E5E5E5] tracking-tight">Attack Surface</h1>
          <p className="text-sm text-[#737373] mt-1 hidden sm:block">Asset discovery, vulnerability management, and risk assessment</p>
        </div>
        <button
          onClick={() => setShowScanModal(true)}
          className="flex items-center gap-2 bg-white/[0.05] hover:bg-white/[0.08] text-[#E5E5E5] border border-white/[0.04] font-medium px-3 sm:px-4 py-2.5 rounded-xl transition-colors text-[13px] shrink-0"
        >
          <Plus className="w-4 h-4" />
          <span className="hidden sm:inline">New Scan</span>
          <span className="sm:hidden">Scan</span>
        </button>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Weekly Trend Chart */}
        <div className="lg:col-span-2 bg-[#0A0A0A] border border-white/[0.04] rounded-xl overflow-hidden">
          <div className="px-4 sm:px-6 py-4 border-b border-white/[0.04]">
            <span className="text-[13px] font-medium text-[#E5E5E5] uppercase tracking-wider">Weekly Trend</span>
          </div>
          <div className="p-4 sm:p-6 h-44 sm:h-52">
            {!hasVulns ? (
              <div className="h-full flex items-center justify-center">
                <p className="text-[#525252] text-[13px]">No vulnerability data yet</p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData}>
                  <defs>
                    <linearGradient id="vulnGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#EF4444" stopOpacity={0.15} />
                      <stop offset="100%" stopColor="#EF4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="date" tick={{ fill: '#737373', fontSize: 11, fontFamily: 'Azeret Mono' }} axisLine={{ stroke: 'rgba(255,255,255,0.04)' }} tickLine={false} />
                  <YAxis tick={{ fill: '#737373', fontSize: 11, fontFamily: 'Azeret Mono' }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ stroke: 'rgba(255,255,255,0.04)' }} />
                  <Area type="monotone" dataKey="vulns" stroke="#EF4444" fill="url(#vulnGrad)" strokeWidth={1.5} name="Vulnerabilities" />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="bg-[#0A0A0A] border border-white/[0.04] rounded-xl overflow-hidden">
          <div className="px-4 sm:px-6 py-4 border-b border-white/[0.04]">
            <span className="text-[13px] font-medium text-[#E5E5E5] uppercase tracking-wider">Risk Distribution</span>
          </div>
          <div className="p-4 sm:p-6 flex flex-col items-center">
            {severityDist.length === 0 ? (
              <div className="h-36 flex items-center justify-center">
                <p className="text-[#525252] text-[13px]">No data yet</p>
              </div>
            ) : (
              <>
                <div className="w-36 h-36">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={severityDist} cx="50%" cy="50%" innerRadius={35} outerRadius={60} dataKey="value" stroke="none" paddingAngle={3}>
                        {severityDist.map((entry, index) => (
                          <Cell key={index} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={tooltipStyle} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="w-full mt-4 space-y-2">
                  {severityDist.map((e) => (
                    <div key={e.name} className="flex items-center justify-between">
                      <div className="flex items-center gap-2.5">
                        <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: e.color }} />
                        <span className="text-[13px] text-[#737373]">{e.name}</span>
                      </div>
                      <span className="text-[13px] text-[#E5E5E5] font-mono font-medium tabular-nums">{e.value}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Detection Volume Trend */}
      <div className="bg-[#0A0A0A] border border-white/[0.04] rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-4 sm:px-6 py-4 border-b border-white/[0.04]">
          <div>
            <span className="text-[13px] font-medium text-[#E5E5E5] uppercase tracking-wider">Detection Volume</span>
            <p className="text-[11px] text-[#737373] mt-0.5 hidden sm:block">Vulnerabilities found per day this week</p>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-1 rounded-full bg-[#22D3EE]" />
            <span className="text-[11px] text-[#737373] font-medium">Detections</span>
          </div>
        </div>
        <div className="p-4 sm:p-6 h-40 sm:h-48">
          {!hasVulns ? (
            <div className="h-full flex items-center justify-center">
              <p className="text-[#525252] text-[13px]">No detection data yet</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trendData}>
                <XAxis
                  dataKey="date"
                  tick={{ fill: '#737373', fontSize: 11, fontFamily: 'Azeret Mono' }}
                  axisLine={{ stroke: 'rgba(255,255,255,0.04)' }}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: '#737373', fontSize: 11, fontFamily: 'Azeret Mono' }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={tooltipStyle}
                  cursor={{ stroke: 'rgba(255,255,255,0.04)' }}
                />
                <Line
                  type="monotone"
                  dataKey="vulns"
                  name="Detections"
                  stroke="#22D3EE"
                  strokeWidth={1.5}
                  dot={{ fill: '#0A0A0A', stroke: '#22D3EE', strokeWidth: 2, r: 3 }}
                  activeDot={{ fill: '#22D3EE', stroke: '#0A0A0A', strokeWidth: 2, r: 4 }}
                />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Tab Bar */}
      <div className="border-b border-white/[0.04]">
        <div className="flex items-center gap-4">
          <button
            onClick={() => setTab('assets')}
            className={cn(
              'pb-3 text-[13px] font-medium border-b-2 transition-colors -mb-px',
              tab === 'assets' ? 'border-[#22D3EE] text-[#22D3EE]' : 'border-transparent text-[#737373] hover:text-[#E5E5E5]'
            )}
          >
            <div className="flex items-center gap-2">
              <Radar01Icon size={16} />
              Assets ({assets.length})
            </div>
          </button>
          <button
            onClick={() => setTab('vulns')}
            className={cn(
              'pb-3 text-[13px] font-medium border-b-2 transition-colors -mb-px',
              tab === 'vulns' ? 'border-[#22D3EE] text-[#22D3EE]' : 'border-transparent text-[#737373] hover:text-[#E5E5E5]'
            )}
          >
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4" />
              Vulnerabilities ({filteredVulns.length})
            </div>
          </button>
        </div>
        {tab === 'vulns' && (
          <div className="flex items-center gap-1.5 pb-3 flex-wrap">
            {['all', 'critical', 'high', 'medium', 'low'].map((s) => (
              <button
                key={s}
                onClick={() => setSeverityFilter(s)}
                className={cn(
                  'px-2 sm:px-2.5 py-1 rounded-lg text-[11px] font-medium transition-colors capitalize',
                  severityFilter === s ? 'bg-[#22D3EE]/10 text-[#22D3EE]' : 'text-[#737373] hover:text-[#E5E5E5]'
                )}
              >
                {s}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Data Table */}
      {tab === 'assets' ? (
        <DataTable<AssetRow>
          columns={assetColumns}
          data={assets}
          emptyMessage="No assets discovered yet. Start a scan to discover your attack surface."
        />
      ) : (
        <DataTable<VulnRow>
          columns={vulnColumns}
          data={filteredVulns}
          emptyMessage="No vulnerabilities found. Run a scan to assess your security posture."
        />
      )}

      {/* Scan Modal */}
      <Modal open={showScanModal} onClose={() => setShowScanModal(false)} title="Launch New Scan">
        <div className="space-y-4">
          <div>
            <label className="text-[11px] font-medium text-[#737373] uppercase tracking-wider block mb-1.5">Target</label>
            <input
              type="text"
              value={scanTarget}
              onChange={(e) => setScanTarget(e.target.value)}
              placeholder="example.com or 10.0.0.0/24"
              className="w-full bg-[#0A0A0A] border border-white/[0.04] rounded-xl px-4 py-2.5 text-sm text-[#E5E5E5] placeholder:text-[#525252] focus:outline-none focus:border-[#22D3EE]/30 font-mono"
            />
          </div>
          <div>
            <label className="text-[11px] font-medium text-[#737373] uppercase tracking-wider block mb-1.5">Scan Type</label>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              className="w-full bg-[#0A0A0A] border border-white/[0.04] rounded-xl px-4 py-2.5 text-sm text-[#E5E5E5] focus:outline-none focus:border-[#22D3EE]/30"
            >
              <option value="full">Full Scan (Discovery + Vulnerabilities)</option>
              <option value="discovery">Discovery Only (Assets + Ports)</option>
              <option value="vuln">Vulnerability Scan Only</option>
              <option value="nuclei">Nuclei Templates Only</option>
            </select>
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button onClick={() => setShowScanModal(false)} className="px-4 py-2 text-[13px] text-[#737373] hover:text-[#E5E5E5] transition-colors rounded-xl">
              Cancel
            </button>
            <button onClick={handleScan} className="flex items-center gap-2 bg-[#22D3EE] hover:bg-[#06B6D4] text-[#09090B] font-semibold px-4 py-2 rounded-xl transition-colors text-[13px]">
              <Radar01Icon size={16} />
              Launch Scan
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
