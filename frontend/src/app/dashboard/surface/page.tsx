'use client';

import { useState, useEffect, useMemo, useCallback } from 'react';
import { Radar01Icon } from 'hugeicons-react';
import { Filter, Server, Globe, Cloud, Code, Wifi, Search, RefreshCw } from 'lucide-react';
import { Card, CardHeader, CardContent, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';
import { DataTable } from '@/components/shared/DataTable';
import { SeverityBadge } from '@/components/shared/SeverityBadge';
import { StatusIndicator } from '@/components/shared/StatusIndicator';
import { Modal } from '@/components/shared/Modal';
import { LoadingState } from '@/components/shared/LoadingState';
import { KPI, StatusBadge } from '@/components/aegis';
import { AssetRiskPanel, type AssetRiskItem, type RiskBand, type AssetExposure } from '@/components/dashboard/AssetRiskPanel';
import { AssetInspectionDrawer, type AssetData, type VulnData } from '@/components/surface/AssetInspectionDrawer';
import { VulnInspectionDrawer, type VulnDataFull } from '@/components/surface/VulnInspectionDrawer';
import { api } from '@/lib/api';
import { cn, formatDate } from '@/lib/utils';
import {
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
  XAxis,
  YAxis,
} from 'recharts';
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from '@/components/ui/chart';

interface PortEntry {
  port: number;
  protocol?: string;
  service?: string;
  version?: string;
  state?: string;
}

interface AssetRow {
  id: string;
  hostname: string;
  ip_address: string;
  asset_type: string;
  ports: (number | PortEntry)[];
  technologies?: string[];
  risk_score: number;
  status: string;
  last_scan_at: string | null;
  risk_band?: string;
  risk_method?: string;
  risk_ai_used?: boolean;
  exposure?: string;
  exposure_multiplier?: number;
  base_score?: number;
  vuln_term?: number;
  risk_drivers?: Array<{
    port: number;
    protocol: string;
    service: string;
    klass: string;
    label: string;
    weight: number;
    host_wide: boolean;
    contribution: number;
  }>;
  service_classes?: Array<{ klass: string; label: string; weight: number; count: number }>;
  vulnerability_count?: number;
  [key: string]: unknown;
}

interface VulnRow {
  id: string;
  asset_id: string;
  title: string;
  description?: string | null;
  severity: string;
  cvss_score: number | null;
  cve_id: string | null;
  status: string;
  ai_risk_score?: number | null;
  remediation?: string | null;
  found_at: string;
  [key: string]: unknown;
}

interface ScanItem {
  id: string;
  target: string;
  type: string;
  status: string;
  progress: number;
  assets_found: number;
  started_at: string | null;
  completed_at: string | null;
}

const trendChartConfig = {
  vulns: { label: 'Vulnerabilities', color: '#22D3EE' },
} satisfies ChartConfig;

const severityChartConfig = {
  Critical: { label: 'Critical', color: 'var(--danger, #EF4444)' },
  High:     { label: 'High',     color: '#F97316' },
  Medium:   { label: 'Medium',   color: '#F59E0B' },
  Low:      { label: 'Low',      color: '#22D3EE' },
} satisfies ChartConfig;

const typeIcons: Record<string, typeof Server> = {
  server: Server,
  web: Globe,
  cloud: Cloud,
  api: Code,
  dns: Wifi,
};

function riskColor(score: number): string {
  if (score >= 8) return 'text-[var(--danger)] font-bold';
  if (score >= 6) return 'text-[#F97316] font-bold';
  if (score >= 4) return 'text-[var(--warning)] font-bold';
  return 'text-[var(--success)] font-semibold';
}

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
    Critical: 'var(--danger, #EF4444)',
    High:     '#F97316',
    Medium:   '#F59E0B',
    Low:      '#22D3EE',
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
    if (!v.found_at) return;
    const diffDays = Math.floor((now - new Date(v.found_at).getTime()) / 86400000);
    const idx = 6 - diffDays;
    if (idx >= 0 && idx < 7) counts[idx] += 1;
  });
  return days.map((date, i) => ({ date, vulns: counts[i] }));
}

function buildExposureDist(assets: AssetRow[]) {
  const counts: Record<string, number> = { Public: 0, Tailnet: 0, LAN: 0, Loopback: 0, Unknown: 0 };
  assets.forEach((a) => {
    const exp = (a.exposure || 'unknown').toLowerCase();
    if (exp === 'public') counts.Public += 1;
    else if (exp === 'tailnet') counts.Tailnet += 1;
    else if (exp === 'lan') counts.LAN += 1;
    else if (exp === 'local') counts.Loopback += 1;
    else counts.Unknown += 1;
  });
  return Object.entries(counts)
    .filter(([, val]) => val > 0)
    .map(([name, count]) => ({ name, count }));
}

export default function SurfacePage() {
  const [assets, setAssets] = useState<AssetRow[]>([]);
  const [vulns, setVulns] = useState<VulnRow[]>([]);
  const [scans, setScans] = useState<ScanItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [showScanModal, setShowScanModal] = useState(false);
  const [scanTarget, setScanTarget] = useState('');
  const [scanType, setScanType] = useState('full');
  const [triggeringScan, setTriggeringScan] = useState(false);

  // Filters & State
  const [searchQuery, setSearchQuery] = useState('');
  const [assetTypeFilter, setAssetTypeFilter] = useState<string>('all');
  const [riskBandFilter, setRiskBandFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [tab, setTab] = useState<string>('assets');

  // Drawers state
  const [selectedAsset, setSelectedAsset] = useState<AssetRow | null>(null);
  const [assetDrawerOpen, setAssetDrawerOpen] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState<VulnDataFull | null>(null);
  const [vulnDrawerOpen, setVulnDrawerOpen] = useState(false);

  const loadData = useCallback(async () => {
    try {
      const [a, v, s] = await Promise.allSettled([
        api.surface.assets(),
        api.surface.vulnerabilities(),
        api.surface.scans(),
      ]);
      setAssets(a.status === 'fulfilled' ? (a.value as AssetRow[]) : []);
      setVulns(v.status === 'fulfilled' ? (v.value as VulnRow[]) : []);
      setScans(s.status === 'fulfilled' ? (s.value as ScanItem[]) : []);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Polling for active scan progress
  const hasActiveScan = scans.some((s) => s.status === 'running' || s.status === 'queued');
  useEffect(() => {
    if (!hasActiveScan) return;
    const interval = setInterval(() => {
      api.surface.scans().then((s) => setScans(s as ScanItem[])).catch(() => {});
      api.surface.assets().then((a) => setAssets(a as AssetRow[])).catch(() => {});
      api.surface.vulnerabilities().then((v) => setVulns(v as VulnRow[])).catch(() => {});
    }, 3000);
    return () => clearInterval(interval);
  }, [hasActiveScan]);

  const handleLaunchScan = async (targetOverride?: string) => {
    const targetToScan = targetOverride || scanTarget;
    if (!targetToScan.trim()) return;
    setTriggeringScan(true);
    try {
      await api.surface.scan(targetToScan, scanType);
      setShowScanModal(false);
      setScanTarget('');
      await loadData();
    } catch {
      // ignore error
    } finally {
      setTriggeringScan(false);
    }
  };

  // Status update handler from VulnDrawer
  const handleVulnStatusUpdated = (vulnId: string, newStatus: string) => {
    setVulns((prev) =>
      prev.map((v) => (v.id === vulnId ? { ...v, status: newStatus } : v))
    );
    if (selectedVuln && selectedVuln.id === vulnId) {
      setSelectedVuln((prev) => (prev ? { ...prev, status: newStatus } : null));
    }
  };

  // Filtered Assets logic
  const filteredAssets = useMemo(() => {
    return assets.filter((a) => {
      // Search
      const query = searchQuery.toLowerCase().trim();
      if (query) {
        const matchesHost = a.hostname.toLowerCase().includes(query);
        const matchesIp = a.ip_address.toLowerCase().includes(query);
        const matchesTech = a.technologies?.some((t) => t.toLowerCase().includes(query));
        if (!matchesHost && !matchesIp && !matchesTech) return false;
      }
      // Asset Type
      if (assetTypeFilter !== 'all' && a.asset_type !== assetTypeFilter) {
        return false;
      }
      // Risk Band
      if (riskBandFilter !== 'all') {
        const score = a.risk_score || 0;
        if (riskBandFilter === 'critical' && score < 8) return false;
        if (riskBandFilter === 'high' && (score < 6 || score >= 8)) return false;
        if (riskBandFilter === 'medium' && (score < 4 || score >= 6)) return false;
        if (riskBandFilter === 'low' && score >= 4) return false;
      }
      return true;
    });
  }, [assets, searchQuery, assetTypeFilter, riskBandFilter]);

  // Filtered Vulnerabilities
  const filteredVulns = useMemo(() => {
    return vulns.filter((v) => {
      const query = searchQuery.toLowerCase().trim();
      if (query) {
        const matchesTitle = v.title.toLowerCase().includes(query);
        const matchesCve = v.cve_id?.toLowerCase().includes(query);
        if (!matchesTitle && !matchesCve) return false;
      }
      if (severityFilter !== 'all' && v.severity !== severityFilter) {
        return false;
      }
      return true;
    });
  }, [vulns, searchQuery, severityFilter]);

  // Telemetry Calculations
  const activeAssets = assets.filter((a) => a.status === 'active').length;
  const inactiveAssets = assets.length - activeAssets;
  const avgRisk = assets.length > 0
    ? assets.reduce((acc, a) => acc + (a.risk_score || 0), 0) / assets.length
    : 0;
  const fleetRiskBand = avgRisk >= 8 ? 'Critical' : avgRisk >= 6 ? 'High' : avgRisk >= 4 ? 'Medium' : 'Contained';
  const highRiskAssets = assets.filter((a) => (a.risk_score || 0) >= 6);
  const highRiskPct = assets.length > 0 ? ((highRiskAssets.length / assets.length) * 100).toFixed(0) : '0';
  const openVulns = vulns.filter((v) => v.status === 'open');
  const criticalVulns = openVulns.filter((v) => v.severity === 'critical').length;
  const highVulns = openVulns.filter((v) => v.severity === 'high').length;
  const activeScans = scans.filter((s) => s.status === 'running' || s.status === 'queued');
  const runningScan = activeScans[0];

  // AssetRiskItems mapping for AssetRiskPanel
  const assetRiskItems: AssetRiskItem[] = useMemo(() => {
    return assets.map((a) => {
      const normalizedPorts: AssetRow['ports'] = (a.ports || []).map((p) => {
        if (typeof p === 'number') return { port: p, protocol: 'tcp', service: 'unknown' };
        return p;
      });
      return {
        id: a.id,
        hostname: a.hostname,
        ip_address: a.ip_address,
        asset_type: a.asset_type,
        ports: normalizedPorts as AssetRiskItem['ports'],
        technologies: a.technologies || [],
        status: a.status,
        risk_score: a.risk_score || 0,
        last_scan_at: a.last_scan_at,
        risk_band: (a.risk_band || 'contained') as RiskBand,
        risk_method: a.risk_method || 'service_weighted_v1',
        risk_ai_used: !!a.risk_ai_used,
        exposure: (a.exposure || 'unknown') as AssetExposure,
        exposure_multiplier: a.exposure_multiplier ?? 0.6,
        base_score: a.base_score ?? 0.0,
        vuln_term: a.vuln_term ?? 0.0,
        risk_drivers: a.risk_drivers || [],
        service_classes: a.service_classes || [],
        host_wide_count: 0,
        owned_count: 0,
      };
    });
  }, [assets]);

  // Asset Table Columns
  const assetColumns = [
    {
      key: 'hostname',
      label: 'Hostname',
      sortable: true,
      render: (row: AssetRow) => {
        const Icon = typeIcons[row.asset_type] || Server;
        return (
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-white/[0.04] text-cyan-400">
              <Icon className="w-3.5 h-3.5" />
            </div>
            <span className="font-mono text-foreground font-semibold text-[13px]">
              {cleanHostname(row.hostname)}
            </span>
          </div>
        );
      },
    },
    {
      key: 'ip_address',
      label: 'IP Address',
      sortable: true,
      render: (row: AssetRow) => (
        <span className="font-mono text-muted-foreground text-[13px]">{row.ip_address || '—'}</span>
      ),
    },
    {
      key: 'asset_type',
      label: 'Type',
      sortable: true,
      render: (row: AssetRow) => (
        <span className="capitalize text-muted-foreground text-[13px]">{row.asset_type}</span>
      ),
    },
    {
      key: 'ports',
      label: 'Open Ports',
      render: (row: AssetRow) => {
        let portsList = row.ports;
        if (typeof portsList === 'string') {
          try { portsList = JSON.parse(portsList); } catch { portsList = []; }
        }
        if (!Array.isArray(portsList)) portsList = [];
        const formatted = portsList
          .slice(0, 4)
          .map((p: number | PortEntry) =>
            typeof p === 'object' && p !== null
              ? (p as PortEntry).service ? `${(p as PortEntry).port}/${(p as PortEntry).service}` : String((p as PortEntry).port)
              : String(p)
          )
          .join(', ');
        const extraCount = portsList.length > 4 ? ` +${portsList.length - 4}` : '';
        return (
          <span className="font-mono text-[11px] text-muted-foreground">
            {formatted ? `${formatted}${extraCount}` : '—'}
          </span>
        );
      },
    },
    {
      key: 'risk_score',
      label: 'Risk Score',
      sortable: true,
      render: (row: AssetRow) => (
        <span className={cn('font-mono font-bold text-[14px] tabular-nums', riskColor(row.risk_score || 0))}>
          {(row.risk_score || 0).toFixed(1)}
        </span>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      render: (row: AssetRow) => <StatusIndicator status={row.status} label={row.status} />,
    },
    {
      key: 'last_scan_at',
      label: 'Last Scan',
      sortable: true,
      render: (row: AssetRow) => (
        <span className="text-muted-foreground text-[11px] font-mono">{formatDate(row.last_scan_at)}</span>
      ),
    },
  ];

  // Vuln Table Columns
  const vulnColumns = [
    {
      key: 'title',
      label: 'Vulnerability',
      sortable: true,
      render: (row: VulnRow) => (
        <span className="text-[13px] text-foreground font-medium hover:text-primary transition-colors cursor-pointer">
          {row.title}
        </span>
      ),
    },
    {
      key: 'severity',
      label: 'Severity',
      sortable: true,
      render: (row: VulnRow) => <SeverityBadge severity={row.severity} />,
    },
    {
      key: 'cvss_score',
      label: 'CVSS',
      sortable: true,
      render: (row: VulnRow) => (
        <span className="font-mono text-[13px] font-semibold text-foreground">
          {row.cvss_score !== undefined && row.cvss_score !== null ? row.cvss_score.toFixed(1) : '—'}
        </span>
      ),
    },
    {
      key: 'cve_id',
      label: 'CVE ID',
      render: (row: VulnRow) => (
        <span className="font-mono text-muted-foreground text-[11px]">{row.cve_id || '—'}</span>
      ),
    },
    {
      key: 'status',
      label: 'Status',
      render: (row: VulnRow) => (
        <StatusBadge
          variant={row.status === 'open' ? 'danger' : row.status === 'remediated' ? 'accent' : 'muted'}
          size="sm"
        >
          {row.status}
        </StatusBadge>
      ),
    },
    {
      key: 'found_at',
      label: 'Found Date',
      sortable: true,
      render: (row: VulnRow) => (
        <span className="text-muted-foreground text-[11px] font-mono">{formatDate(row.found_at)}</span>
      ),
    },
  ];

  if (loading) return <LoadingState message="Loading attack surface command center..." />;

  const severityDist = buildSeverityDist(vulns);
  const trendData = buildWeeklyTrend(vulns);
  const hasVulns = vulns.length > 0;

  return (
    <div className="space-y-6 animate-fade-in font-sans">
      
      {/* Header */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-[24px] sm:text-[28px] font-bold text-foreground tracking-tight font-outfit">
              Command Center — Attack Surface
            </h1>
            {hasActiveScan && (
              <Badge className="bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono animate-pulse">
                Scan Active
              </Badge>
            )}
          </div>
          <p className="text-sm text-muted-foreground mt-1 hidden sm:block font-outfit">
            Real-time asset telemetry, exposure analysis, and automated vulnerability triage
          </p>
        </div>

        <Button
          onClick={() => setShowScanModal(true)}
          className="bg-[#22D3EE] hover:bg-[#22D3EE]/90 text-black font-semibold gap-2 shadow-[0_0_20px_rgba(34,211,238,0.2)]"
        >
          <Radar01Icon size={16} />
          <span>Launch Scan</span>
        </Button>
      </div>

      {/* R1: Live Scan Progress HUD Widget */}
      {runningScan && (
        <div className="p-4 rounded-2xl bg-card border border-cyan-500/40 shadow-[0_0_25px_rgba(34,211,238,0.1)] flex items-center justify-between gap-4 flex-wrap animate-fade-in">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 animate-spin">
              <RefreshCw className="w-5 h-5" />
            </div>
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-cyan-400 font-outfit flex items-center gap-2">
                Active Scan in Progress — {runningScan.target}
              </div>
              <div className="text-xs font-mono text-muted-foreground mt-0.5">
                Type: {runningScan.type} • Assets Discovered: {runningScan.assets_found}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4 w-full sm:w-64">
            <div className="flex-1 bg-white/[0.06] h-2 rounded-full overflow-hidden">
              <div
                className="bg-[#22D3EE] h-full transition-all duration-500"
                style={{ width: `${runningScan.progress || 50}%` }}
              />
            </div>
            <span className="font-mono text-xs font-bold text-cyan-400">
              {runningScan.progress || 50}%
            </span>
          </div>
        </div>
      )}

      {/* R1: 5 KPI Telemetry Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <KPI
          label="Total Assets"
          value={assets.length}
          sub={`${activeAssets} Active · ${inactiveAssets} Inactive`}
          tone="accent"
          warm
        />
        <KPI
          label="Avg Risk Score"
          value={avgRisk.toFixed(1)}
          sub={`Fleet Level: ${fleetRiskBand}`}
          tone={avgRisk >= 6 ? 'danger' : avgRisk >= 4 ? 'warning' : 'success'}
        />
        <KPI
          label="High Risk Exposure"
          value={highRiskAssets.length}
          sub={`${highRiskPct}% of total fleet`}
          tone="danger"
        />
        <KPI
          label="Open Vulnerabilities"
          value={openVulns.length}
          sub={`${criticalVulns} Critical · ${highVulns} High`}
          tone="warning"
        />
        <KPI
          label="Active Scans"
          value={activeScans.length}
          sub={runningScan ? `Scanning ${runningScan.target}` : 'Idle'}
          tone="neutral"
        />
      </div>

      {/* R1: Interactive Risk Distribution & Trend Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        
        {/* Weekly Trend Chart */}
        <Card className="lg:col-span-2 overflow-hidden rounded-2xl border border-white/[0.06] bg-card py-0">
          <CardHeader className="border-b border-border/80 px-6 py-4">
            <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground font-outfit">
              Weekly Vulnerability Trend
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6 h-52">
            {!hasVulns ? (
              <div className="h-full flex items-center justify-center">
                <p className="text-muted-foreground/50 text-xs font-mono">No vulnerability data yet</p>
              </div>
            ) : (
              <ChartContainer config={trendChartConfig} className="h-full w-full aspect-auto">
                <AreaChart data={trendData}>
                  <defs>
                    <linearGradient id="cyanGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#22D3EE" stopOpacity={0.25} />
                      <stop offset="100%" stopColor="#22D3EE" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="date" tick={{ fontSize: 11, fontFamily: 'Azeret Mono' }} tickLine={false} />
                  <YAxis tick={{ fontSize: 11, fontFamily: 'Azeret Mono' }} axisLine={false} tickLine={false} />
                  <ChartTooltip content={<ChartTooltipContent indicator="line" />} />
                  <Area type="monotone" dataKey="vulns" stroke="#22D3EE" fill="url(#cyanGrad)" strokeWidth={2} />
                </AreaChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        {/* Severity Distribution PieChart */}
        <Card className="overflow-hidden rounded-2xl border border-white/[0.06] bg-card py-0">
          <CardHeader className="border-b border-border/80 px-6 py-4">
            <CardTitle className="text-xs font-bold uppercase tracking-wider text-muted-foreground font-outfit">
              Risk Distribution
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6 flex flex-col items-center">
            {severityDist.length === 0 ? (
              <div className="h-36 flex items-center justify-center">
                <p className="text-muted-foreground/50 text-xs font-mono">No risk distribution data</p>
              </div>
            ) : (
              <>
                <div className="w-36 h-36">
                  <ChartContainer config={severityChartConfig} className="h-full w-full aspect-auto">
                    <PieChart>
                      <ChartTooltip content={<ChartTooltipContent hideLabel nameKey="name" />} />
                      <Pie data={severityDist} cx="50%" cy="50%" innerRadius={36} outerRadius={60} dataKey="value" nameKey="name" stroke="none" paddingAngle={4}>
                        {severityDist.map((entry, index) => (
                          <Cell key={index} fill={entry.color} />
                        ))}
                      </Pie>
                    </PieChart>
                  </ChartContainer>
                </div>
                <div className="w-full mt-4 space-y-2">
                  {severityDist.map((e) => (
                    <div key={e.name} className="flex items-center justify-between">
                      <div className="flex items-center gap-2.5">
                        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: e.color }} />
                        <span className="text-xs text-muted-foreground">{e.name}</span>
                      </div>
                      <span className="text-xs text-foreground font-mono font-bold tabular-nums">{e.value}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </CardContent>
        </Card>

      </div>

      {/* AssetRiskPanel integration for deep deterministic risk breakdown */}
      <AssetRiskPanel assets={assetRiskItems} loading={loading} />

      {/* R1: Asset Type Filter Bar & Search & Risk Band Filters */}
      <div className="space-y-4 pt-2">
        <div className="p-4 rounded-2xl bg-card border border-white/[0.06] flex flex-col md:flex-row items-center justify-between gap-4">
          
          {/* Search Box */}
          <div className="relative w-full md:w-72">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <Input
              type="text"
              placeholder="Search hostname, IP, CVE..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 font-mono text-xs bg-white/[0.02] border-white/[0.08] focus:border-[#22D3EE]"
            />
          </div>

          {/* Filters Group */}
          <div className="flex items-center gap-3 flex-wrap w-full md:w-auto">
            {/* Type Filters */}
            <div className="flex items-center gap-1 bg-white/[0.02] p-1 rounded-xl border border-white/[0.06]">
              {[
                { id: 'all', label: 'All Types' },
                { id: 'server', label: 'IP/Server' },
                { id: 'web', label: 'Web' },
                { id: 'dns', label: 'Domain/DNS' },
                { id: 'cloud', label: 'Cloud' },
              ].map((t) => (
                <button
                  key={t.id}
                  onClick={() => setAssetTypeFilter(t.id)}
                  className={cn(
                    'px-3 py-1.5 text-xs font-semibold rounded-lg transition-colors font-outfit',
                    assetTypeFilter === t.id
                      ? 'bg-[#22D3EE]/10 text-[#22D3EE] border border-[#22D3EE]/30'
                      : 'text-muted-foreground hover:text-foreground'
                  )}
                >
                  {t.label}
                </button>
              ))}
            </div>

            {/* Risk Band Filters */}
            <select
              value={riskBandFilter}
              onChange={(e) => setRiskBandFilter(e.target.value)}
              className="bg-card border border-white/[0.08] rounded-xl px-3 py-2 text-xs font-mono text-foreground focus:outline-none focus:border-[#22D3EE]"
            >
              <option value="all">All Risk Bands</option>
              <option value="critical">Critical (≥8.0)</option>
              <option value="high">High (≥6.0)</option>
              <option value="medium">Medium (≥4.0)</option>
              <option value="low">Low (&lt;4.0)</option>
            </select>
          </div>
        </div>

        {/* Tab Section: Assets vs Vulnerabilities */}
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList variant="line" className="border-b border-border/80">
            <TabsTrigger value="assets" className="font-outfit text-xs uppercase tracking-wider font-semibold">
              <Radar01Icon size={16} />
              Discovered Assets ({filteredAssets.length})
            </TabsTrigger>
            <TabsTrigger value="vulns" className="font-outfit text-xs uppercase tracking-wider font-semibold">
              <Filter className="w-4 h-4" />
              Vulnerabilities ({filteredVulns.length})
            </TabsTrigger>
          </TabsList>

          <TabsContent value="assets" className="pt-3">
            <DataTable<AssetRow>
              columns={assetColumns}
              data={filteredAssets}
              onRowClick={(row) => {
                setSelectedAsset(row);
                setAssetDrawerOpen(true);
              }}
              emptyMessage="No assets match the current filter criteria."
            />
          </TabsContent>

          <TabsContent value="vulns" className="pt-3 space-y-4">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-mono text-muted-foreground uppercase mr-2">Severity Filter:</span>
              {['all', 'critical', 'high', 'medium', 'low'].map((s) => (
                <Badge
                  key={s}
                  variant={severityFilter === s ? 'default' : 'ghost'}
                  className={cn(
                    'cursor-pointer capitalize font-mono text-xs py-1 px-3',
                    severityFilter === s ? 'bg-[#22D3EE]/10 text-[#22D3EE] border border-[#22D3EE]/30' : 'text-muted-foreground hover:text-foreground'
                  )}
                  onClick={() => setSeverityFilter(s)}
                >
                  {s}
                </Badge>
              ))}
            </div>

            <DataTable<VulnRow>
              columns={vulnColumns}
              data={filteredVulns}
              onRowClick={(row) => {
                const parentAsset = assets.find((a) => a.id === row.asset_id);
                setSelectedVuln({
                  id: row.id,
                  asset_id: row.asset_id,
                  title: row.title,
                  description: row.description,
                  severity: row.severity,
                  cvss_score: row.cvss_score,
                  cve_id: row.cve_id,
                  status: row.status,
                  ai_risk_score: row.ai_risk_score,
                  remediation: row.remediation,
                  found_at: row.found_at,
                  asset_hostname: parentAsset?.hostname,
                  asset_ip: parentAsset?.ip_address,
                });
                setVulnDrawerOpen(true);
              }}
              emptyMessage="No vulnerabilities match the selected filters."
            />
          </TabsContent>
        </Tabs>
      </div>

      {/* R2: Asset Inspection Drawer */}
      <AssetInspectionDrawer
        asset={selectedAsset as AssetData | null}
        open={assetDrawerOpen}
        onClose={() => setAssetDrawerOpen(false)}
        associatedVulns={vulns as VulnData[]}
        onTriggerScan={(target) => handleLaunchScan(target)}
        onSelectVuln={(v) => {
          const parentAsset = assets.find((a) => a.id === v.asset_id);
          setSelectedVuln({
            id: v.id,
            asset_id: v.asset_id,
            title: v.title,
            description: v.description,
            severity: v.severity,
            cvss_score: v.cvss_score,
            cve_id: v.cve_id,
            status: v.status,
            found_at: v.found_at,
            asset_hostname: parentAsset?.hostname,
            asset_ip: parentAsset?.ip_address,
          });
          setAssetDrawerOpen(false);
          setVulnDrawerOpen(true);
        }}
      />

      {/* R2: Vulnerability Inspection Drawer */}
      <VulnInspectionDrawer
        vuln={selectedVuln}
        open={vulnDrawerOpen}
        onClose={() => setVulnDrawerOpen(false)}
        onStatusUpdated={handleVulnStatusUpdated}
      />

      {/* Scan Trigger Modal */}
      <Modal open={showScanModal} onClose={() => setShowScanModal(false)} title="Launch Attack Surface Scan">
        <div className="space-y-4">
          <div>
            <label className="text-xs font-bold text-muted-foreground uppercase tracking-wider block mb-1.5 font-outfit">
              Target IP / Hostname / Subnet
            </label>
            <Input
              type="text"
              value={scanTarget}
              onChange={(e) => setScanTarget(e.target.value)}
              placeholder="e.g. example.com or 192.168.1.0/24"
              className="font-mono text-sm bg-card border-white/[0.08]"
            />
          </div>
          <div>
            <label className="text-xs font-bold text-muted-foreground uppercase tracking-wider block mb-1.5 font-outfit">
              Scan Configuration Profile
            </label>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              className="w-full bg-card border border-white/[0.08] rounded-xl px-4 py-2.5 text-sm text-foreground focus:outline-none focus:border-[#22D3EE] font-mono"
            >
              <option value="full">Full Scan (Asset Discovery + Vulnerability Audit)</option>
              <option value="discovery">Discovery Scan (Host & Port Enumeration)</option>
              <option value="vuln">Vulnerability Audit Only</option>
            </select>
          </div>
          <div className="flex justify-end gap-3 pt-3">
            <Button variant="ghost" onClick={() => setShowScanModal(false)}>
              Cancel
            </Button>
            <Button
              disabled={triggeringScan || !scanTarget.trim()}
              onClick={() => handleLaunchScan()}
              className="bg-[#22D3EE] hover:bg-[#22D3EE]/90 text-black font-semibold gap-2"
            >
              <Radar01Icon size={16} />
              {triggeringScan ? 'Launching...' : 'Start Scan'}
            </Button>
          </div>
        </div>
      </Modal>

    </div>
  );
}
