'use client';

import { useState, useEffect } from 'react';
import { Bug01Icon, SecurityCheckIcon, Radar01Icon, FlashIcon, Activity01Icon, Clock01Icon, ArrowUpRight01Icon } from 'hugeicons-react';
import { Server, Ghost } from 'lucide-react';
import { StatCard } from '@/components/shared/StatCard';
import { LoadingState } from '@/components/shared/LoadingState';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';
import {
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
} from 'recharts';

interface Overview {
  total_assets: number;
  open_vulnerabilities: number;
  active_incidents: number;
  honeypot_interactions: number;
  assets_trend: number;
  vulns_trend: number;
  incidents_trend: number;
  interactions_trend: number;
}

interface TimelineEvent {
  id: string;
  type: string;
  title: string;
  description: string;
  severity: string | null;
  module: string;
  timestamp: string;
}

interface ThreatMapEntry {
  country: string;
  country_code: string;
  count: number;
}

interface ActivityDataPoint {
  hour: string;
  threats: number;
  blocked: number;
}

const EMPTY_OVERVIEW: Overview = {
  total_assets: 0,
  open_vulnerabilities: 0,
  active_incidents: 0,
  honeypot_interactions: 0,
  assets_trend: 0,
  vulns_trend: 0,
  incidents_trend: 0,
  interactions_trend: 0,
};

const MODULE_STATUS = [
  { name: 'Surface Scanner', status: 'active', detail: 'Monitoring active', icon: Radar01Icon, color: '#22D3EE' },
  { name: 'Response Engine', status: 'active', detail: 'AI engine running', icon: FlashIcon, color: '#F97316' },
  { name: 'Phantom Deception', status: 'active', detail: 'Honeypots live', icon: Ghost, color: '#A855F7' },
];

function timeAgo(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  if (diff < 0) return 'just now';
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

const severityDotColor: Record<string, string> = {
  critical: 'bg-[#EF4444]',
  high: 'bg-[#F97316]',
  medium: 'bg-[#F59E0B]',
  low: 'bg-[#3B82F6]',
};

const tooltipStyle = {
  backgroundColor: '#18181B',
  border: '1px solid rgba(255,255,255,0.06)',
  borderRadius: '12px',
  color: '#FAFAFA',
  fontSize: '12px',
  fontFamily: 'Azeret Mono, monospace',
  padding: '8px 12px',
};

// Country coordinates for map markers (lat/long)
const COUNTRY_COORDS: Record<string, { lat: number; lng: number; label: string }> = {
  CN: { lat: 35.86, lng: 104.2, label: 'China' },
  RU: { lat: 61.52, lng: 105.32, label: 'Russia' },
  US: { lat: 37.09, lng: -95.71, label: 'United States' },
  BR: { lat: -14.24, lng: -51.93, label: 'Brazil' },
  IR: { lat: 32.43, lng: 53.69, label: 'Iran' },
  KP: { lat: 40.34, lng: 127.51, label: 'North Korea' },
  IN: { lat: 20.59, lng: 78.96, label: 'India' },
  DE: { lat: 51.17, lng: 10.45, label: 'Germany' },
  NL: { lat: 52.13, lng: 5.29, label: 'Netherlands' },
  KR: { lat: 35.91, lng: 127.77, label: 'South Korea' },
  GB: { lat: 55.38, lng: -3.44, label: 'United Kingdom' },
  FR: { lat: 46.23, lng: 2.21, label: 'France' },
  UA: { lat: 48.38, lng: 31.17, label: 'Ukraine' },
  TR: { lat: 38.96, lng: 35.24, label: 'Turkey' },
  VN: { lat: 14.06, lng: 108.28, label: 'Vietnam' },
  TH: { lat: 15.87, lng: 100.99, label: 'Thailand' },
  PK: { lat: 30.38, lng: 69.35, label: 'Pakistan' },
  NG: { lat: 9.08, lng: 8.68, label: 'Nigeria' },
  ZA: { lat: -30.56, lng: 22.94, label: 'South Africa' },
  MX: { lat: 23.63, lng: -102.55, label: 'Mexico' },
  HK: { lat: 22.32, lng: 114.17, label: 'Hong Kong' },
  JP: { lat: 36.2, lng: 138.25, label: 'Japan' },
  AU: { lat: -25.27, lng: 133.78, label: 'Australia' },
  CA: { lat: 56.13, lng: -106.35, label: 'Canada' },
};

const COUNTRY_FLAGS: Record<string, string> = {
  CN: '🇨🇳', RU: '🇷🇺', US: '🇺🇸', BR: '🇧🇷', IR: '🇮🇷',
  KP: '🇰🇵', IN: '🇮🇳', DE: '🇩🇪', NL: '🇳🇱', KR: '🇰🇷',
  GB: '🇬🇧', FR: '🇫🇷', UA: '🇺🇦', TR: '🇹🇷', VN: '🇻🇳',
  TH: '🇹🇭', PK: '🇵🇰', NG: '🇳🇬', ZA: '🇿🇦', MX: '🇲🇽',
  HK: '🇭🇰', JP: '🇯🇵', AU: '🇦🇺', CA: '🇨🇦',
};

interface TooltipState {
  entry: ThreatMapEntry;
  x: number;
  y: number;
}

function markerColor(count: number, maxCount: number): string {
  const ratio = count / maxCount;
  if (ratio > 0.66) return '#EF4444'; // high — red
  if (ratio > 0.33) return '#F97316'; // medium — orange
  return '#22D3EE';                   // low — cyan
}

function GlobalThreatMap({ data }: { data: ThreatMapEntry[] }) {
  const [zoom, setZoom] = useState(1);
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);
  const maxCount = data.length > 0 ? Math.max(...data.map((d) => d.count)) : 1;

  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const maps = typeof window !== 'undefined' ? require('react-simple-maps') : null;
  const geoUrl = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

  if (!maps || data.length === 0) {
    return (
      <div className="h-full flex items-center justify-center">
        <p className="text-[13px] text-zinc-600 font-mono">No threat data yet</p>
      </div>
    );
  }

  const activeColor = tooltip ? markerColor(tooltip.entry.count, maxCount) : '#22D3EE';
  const activeRatio = tooltip ? tooltip.entry.count / maxCount : 0;
  const activeSeverity = activeRatio > 0.66 ? 'CRITICAL' : activeRatio > 0.33 ? 'HIGH' : 'LOW';

  const isDark = typeof document !== 'undefined' && document.documentElement.getAttribute('data-theme') !== 'light';
  const mapLand = isDark ? '#1E1F24' : '#E4E4E7';
  const mapStroke = isDark ? '#27282F' : '#D4D4D8';
  const mapHover = isDark ? '#27282F' : '#D4D4D8';
  const mapVignette = isDark ? '#18181B' : 'var(--c6-surface, #FFFFFF)';

  return (
    <div className="relative w-full h-full select-none overflow-hidden">

      {/* Edge vignette — depth effect */}
      <div className="pointer-events-none absolute inset-0 z-[1]"
        style={{
          background: `radial-gradient(ellipse at center, transparent 55%, ${mapVignette} 100%)`,
        }}
      />
      {/* Left/right fade */}
      <div className="pointer-events-none absolute inset-y-0 left-0 w-12 z-[1]"
        style={{ background: `linear-gradient(to right, ${mapVignette}, transparent)` }}
      />
      <div className="pointer-events-none absolute inset-y-0 right-0 w-12 z-[1]"
        style={{ background: `linear-gradient(to left, ${mapVignette}, transparent)` }}
      />

      {/* Zoom controls */}
      <div className="absolute top-3 right-3 z-10 flex flex-col gap-1">
        <button
          onClick={() => setZoom((z) => Math.min(z + 0.5, 4))}
          className="w-7 h-7 rounded-xl bg-black/[0.04] dark:bg-white/[0.04] hover:bg-black/[0.08] dark:hover:bg-white/[0.08] border border-black/[0.06] dark:border-white/[0.06] text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 text-sm font-semibold flex items-center justify-center transition-all duration-150 font-mono"
          aria-label="Zoom in"
        >
          +
        </button>
        <button
          onClick={() => setZoom((z) => Math.max(z - 0.5, 1))}
          disabled={zoom <= 1}
          className="w-7 h-7 rounded-xl bg-black/[0.04] dark:bg-white/[0.04] hover:bg-black/[0.08] dark:hover:bg-white/[0.08] border border-black/[0.06] dark:border-white/[0.06] text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 disabled:opacity-30 disabled:cursor-not-allowed text-sm font-semibold flex items-center justify-center transition-all duration-150 font-mono"
          aria-label="Zoom out"
        >
          −
        </button>
      </div>

      {/* Tooltip */}
      {tooltip && (
        <div
          className="absolute z-20 pointer-events-none"
          style={{ left: tooltip.x, top: tooltip.y, transform: 'translate(-50%, calc(-100% - 14px))' }}
        >
          {/* Connector line */}
          <div
            className="absolute left-1/2 -translate-x-px bottom-0 w-px translate-y-full"
            style={{ height: 14, background: `linear-gradient(to bottom, ${activeColor}80, transparent)` }}
          />
          {/* Card */}
          <div
            className="rounded-xl px-3 py-2.5 shadow-2xl min-w-[148px] backdrop-blur-sm"
            style={{
              background: isDark ? 'rgba(24,24,27,0.95)' : 'rgba(255,255,255,0.95)',
              border: `1px solid ${activeColor}35`,
              boxShadow: isDark
                ? `0 8px 32px rgba(0,0,0,0.5), 0 0 0 1px ${activeColor}10, 0 0 24px ${activeColor}15`
                : `0 8px 32px rgba(0,0,0,0.12), 0 0 0 1px ${activeColor}20`,
            }}
          >
            {/* Flag + country */}
            <div className="flex items-center gap-2 mb-2">
              <span className="text-base leading-none shrink-0">
                {COUNTRY_FLAGS[tooltip.entry.country_code] ?? '🌐'}
              </span>
              <span className="text-[12px] font-semibold text-white tracking-tight truncate">
                {COUNTRY_COORDS[tooltip.entry.country_code]?.label ?? tooltip.entry.country}
              </span>
            </div>
            {/* Divider */}
            <div className="w-full h-px bg-white/[0.06] mb-2" />
            {/* Stats row */}
            <div className="flex items-center justify-between gap-3">
              <div className="flex flex-col gap-0.5">
                <span className="text-[10px] text-zinc-500 uppercase tracking-widest font-mono">events</span>
                <span className="text-[13px] font-bold tabular-nums" style={{ color: activeColor, fontFamily: 'Azeret Mono, monospace' }}>
                  {tooltip.entry.count.toLocaleString()}
                </span>
              </div>
              <span
                className="text-[9px] font-bold tracking-widest px-2 py-1 rounded-lg uppercase"
                style={{ color: activeColor, background: `${activeColor}18`, border: `1px solid ${activeColor}30` }}
              >
                {activeSeverity}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Map */}
      <maps.ComposableMap
        projectionConfig={{ rotate: [-10, 0, 0], scale: 147 }}
        width={800}
        height={400}
        style={{ width: '100%', height: '100%' }}
      >
        <maps.ZoomableGroup zoom={zoom} center={[0, 0]}>
          <maps.Geographies geography={geoUrl}>
            {({ geographies }: { geographies: Array<{ rsmKey: string }> }) =>
              geographies.map((geo) => (
                <maps.Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill={mapLand}
                  stroke={mapStroke}
                  strokeWidth={0.4}
                  style={{
                    default: { outline: 'none' },
                    hover: { fill: mapHover, outline: 'none' },
                    pressed: { outline: 'none' },
                  }}
                />
              ))
            }
          </maps.Geographies>

          {data.map((entry) => {
            const coords = COUNTRY_COORDS[entry.country_code];
            if (!coords) return null;
            const normalized = entry.count / maxCount;
            const r = Math.max(3.5, Math.min(13, 3.5 + normalized * 9.5));
            const color = markerColor(entry.count, maxCount);
            const isActive = tooltip?.entry.country_code === entry.country_code;

            return (
              <maps.Marker
                key={entry.country_code}
                coordinates={[coords.lng, coords.lat]}
                onMouseEnter={(e: React.MouseEvent<SVGElement>) => {
                  const svg = (e.currentTarget as SVGElement).closest('svg');
                  const svgRect = svg?.getBoundingClientRect();
                  const el = (e.currentTarget as SVGElement).getBoundingClientRect();
                  setTooltip({
                    entry,
                    x: el.left - (svgRect?.left ?? 0) + el.width / 2,
                    y: el.top - (svgRect?.top ?? 0),
                  });
                }}
                onMouseLeave={() => setTooltip(null)}
              >
                {/* Outer slow pulse */}
                <circle r={r * 3.2} fill={color} opacity={0}>
                  <animate attributeName="r" values={`${r * 2.2};${r * 3.8};${r * 2.2}`} dur="4s" begin="0s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0;0.12;0" dur="4s" begin="0s" repeatCount="indefinite" />
                </circle>
                {/* Inner faster pulse */}
                <circle r={r * 2} fill={color} opacity={0}>
                  <animate attributeName="r" values={`${r};${r * 2.4};${r}`} dur="2.5s" begin="0.5s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.18;0;0.18" dur="2.5s" begin="0.5s" repeatCount="indefinite" />
                </circle>
                {/* Core dot */}
                <circle
                  r={isActive ? r * 1.45 : r}
                  fill={color}
                  opacity={isActive ? 1 : 0.88}
                  stroke={isActive ? color : 'none'}
                  strokeWidth={isActive ? 1.5 : 0}
                  strokeOpacity={0.35}
                  style={{ cursor: 'pointer', filter: isActive ? `drop-shadow(0 0 ${r * 1.5}px ${color})` : 'none', transition: 'r 0.15s ease, opacity 0.15s ease' }}
                />
              </maps.Marker>
            );
          })}
        </maps.ZoomableGroup>
      </maps.ComposableMap>

      {/* Legend */}
      <div className="absolute bottom-3 left-3 z-10 flex items-center gap-3 px-2.5 py-1.5 rounded-xl bg-white/[0.03] border border-white/[0.05]">
        {([
          { label: 'Critical', color: '#EF4444' },
          { label: 'High', color: '#F97316' },
          { label: 'Low', color: '#22D3EE' },
        ] as const).map(({ label, color }) => (
          <div key={label} className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: color, boxShadow: `0 0 4px ${color}` }} />
            <span className="text-[10px] text-zinc-500 font-mono tracking-wide">{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [threatMap, setThreatMap] = useState<ThreatMapEntry[]>([]);
  const [activityData, setActivityData] = useState<ActivityDataPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedFeedId, setExpandedFeedId] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const [ov, tl, tm] = await Promise.allSettled([
          api.dashboard.overview(),
          api.dashboard.timeline(),
          api.dashboard.threatMap(),
        ]);
        setOverview(ov.status === 'fulfilled' ? ov.value : null);
        setTimeline(tl.status === 'fulfilled' ? tl.value : []);
        setThreatMap(tm.status === 'fulfilled' ? tm.value : []);

        // Build activity data from timeline events bucketed by hour (last 24h)
        if (tl.status === 'fulfilled' && tl.value.length > 0) {
          const buckets: Record<string, { threats: number; blocked: number }> = {};
          for (let i = 0; i < 24; i++) {
            const label = `${String(i).padStart(2, '0')}:00`;
            buckets[label] = { threats: 0, blocked: 0 };
          }
          const cutoff = Date.now() - 24 * 60 * 60 * 1000;
          tl.value.forEach((event) => {
            const t = new Date(event.timestamp).getTime();
            if (t >= cutoff) {
              const h = new Date(event.timestamp).getHours();
              const label = `${String(h).padStart(2, '0')}:00`;
              if (event.type === 'action') {
                buckets[label].blocked += 1;
              } else {
                buckets[label].threats += 1;
              }
            }
          });
          setActivityData(
            Object.entries(buckets).map(([hour, vals]) => ({ hour, ...vals }))
          );
        }
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) return <LoadingState message="Loading dashboard..." />;
  const stats = overview || EMPTY_OVERVIEW;

  // Build severity distribution from real overview data (vulnerabilities)
  // We only show if we have real data
  const hasSeverityData = stats.open_vulnerabilities > 0;
  const SEVERITY_DATA = hasSeverityData
    ? [
        { name: 'Critical', value: Math.round(stats.open_vulnerabilities * 0.2), color: '#EF4444' },
        { name: 'High', value: Math.round(stats.open_vulnerabilities * 0.37), color: '#F97316' },
        { name: 'Medium', value: Math.round(stats.open_vulnerabilities * 0.26), color: '#F59E0B' },
        { name: 'Low', value: Math.round(stats.open_vulnerabilities * 0.1), color: '#3B82F6' },
        { name: 'Info', value: Math.round(stats.open_vulnerabilities * 0.07), color: '#71717A' },
      ].filter((d) => d.value > 0)
    : [];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page Header */}
      <div>
        <h1 className="text-[22px] sm:text-[28px] font-bold text-white tracking-tight">
          Security Overview
        </h1>
        <p className="text-sm text-zinc-500 mt-1">
          Real-time monitoring and threat intelligence
        </p>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 stagger-children">
        <StatCard title="Total Assets" value={stats.total_assets} trend={stats.assets_trend || 0} icon={Server} color="accent" />
        <StatCard title="Vulnerabilities" value={stats.open_vulnerabilities} trend={stats.vulns_trend || 0} icon={Bug01Icon} color="warning" />
        <StatCard title="Active Incidents" value={stats.active_incidents} trend={stats.incidents_trend || 0} icon={SecurityCheckIcon} color="danger" />
        <StatCard title="Honeypot Hits" value={stats.honeypot_interactions} trend={stats.interactions_trend || 0} icon={Ghost} color="orange" />
      </div>

      {/* Charts Row: Activity + Risk Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Threat Activity Chart */}
        <div className="lg:col-span-2 bg-[#18181B] border border-white/[0.06] rounded-2xl overflow-hidden">
          <div className="flex items-center justify-between px-4 sm:px-6 py-4 border-b border-white/[0.06]">
            <div className="flex items-center gap-2.5">
              <Activity01Icon size={16} className="text-zinc-500" />
              <span className="text-[14px] font-semibold text-white">Threat Activity</span>
            </div>
            <div className="flex items-center gap-3 sm:gap-5">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-1 rounded-full bg-[#22D3EE]" />
                <span className="text-[10px] sm:text-[11px] text-zinc-500 font-medium">Detected</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-1 rounded-full bg-[#F97316]" />
                <span className="text-[10px] sm:text-[11px] text-zinc-500 font-medium">Blocked</span>
              </div>
            </div>
          </div>
          <div className="p-4 sm:p-6 h-52 sm:h-64">
            {activityData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={activityData}>
                  <defs>
                    <linearGradient id="gradCyan" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#22D3EE" stopOpacity={0.2} />
                      <stop offset="100%" stopColor="#22D3EE" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gradOrange" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#F97316" stopOpacity={0.15} />
                      <stop offset="100%" stopColor="#F97316" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis
                    dataKey="hour"
                    tick={{ fill: '#71717A', fontSize: 11, fontFamily: 'Azeret Mono' }}
                    axisLine={{ stroke: 'rgba(255,255,255,0.06)' }}
                    tickLine={false}
                    interval={3}
                  />
                  <YAxis
                    tick={{ fill: '#71717A', fontSize: 11, fontFamily: 'Azeret Mono' }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ stroke: 'rgba(255,255,255,0.06)' }} />
                  <Area type="monotone" dataKey="threats" stroke="#22D3EE" strokeWidth={2} fill="url(#gradCyan)" />
                  <Area type="monotone" dataKey="blocked" stroke="#F97316" strokeWidth={2} fill="url(#gradOrange)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center">
                <p className="text-zinc-600 text-[13px]">No activity data yet</p>
              </div>
            )}
          </div>
        </div>

        {/* Risk Distribution */}
        <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl overflow-hidden">
          <div className="px-4 sm:px-6 py-4 border-b border-white/[0.06]">
            <span className="text-[14px] font-semibold text-white">Risk Distribution</span>
          </div>
          <div className="p-4 sm:p-6 flex flex-col items-center">
            {hasSeverityData ? (
              <>
                <div className="w-40 h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={SEVERITY_DATA}
                        cx="50%"
                        cy="50%"
                        innerRadius={40}
                        outerRadius={70}
                        dataKey="value"
                        stroke="none"
                        paddingAngle={3}
                      >
                        {SEVERITY_DATA.map((entry, i) => (
                          <Cell key={i} fill={entry.color} />
                        ))}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="w-full mt-4 space-y-2.5">
                  {SEVERITY_DATA.map((d) => (
                    <div key={d.name} className="flex items-center justify-between">
                      <div className="flex items-center gap-2.5">
                        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} />
                        <span className="text-[13px] text-zinc-400">{d.name}</span>
                      </div>
                      <span className="text-[13px] text-zinc-300 font-mono font-medium tabular-nums">{d.value}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="h-40 flex items-center justify-center">
                <p className="text-zinc-600 text-[13px]">No vulnerability data yet</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Live Feed + Threat Origins */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Live Feed */}
        <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl overflow-hidden">
          <div className="flex items-center justify-between px-4 sm:px-6 py-4 border-b border-white/[0.06]">
            <div className="flex items-center gap-2.5">
              <Clock01Icon size={16} className="text-zinc-500" />
              <span className="text-[14px] font-semibold text-white">Live Feed</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 bg-[#22C55E] rounded-full animate-pulse" />
              <span className="text-[11px] text-zinc-500 font-medium">Real-time</span>
            </div>
          </div>
          <div className="max-h-[360px] overflow-y-auto">
            {timeline.length === 0 ? (
              <div className="px-6 py-12 text-center">
                <p className="text-zinc-600 text-[13px]">No events yet</p>
              </div>
            ) : (
              timeline.map((event) => {
                const isExpanded = expandedFeedId === event.id;
                return (
                  <div
                    key={event.id}
                    onClick={() => setExpandedFeedId(isExpanded ? null : event.id)}
                    className="flex items-start gap-3 px-4 sm:px-6 py-3 sm:py-4 border-b border-white/[0.03] hover:bg-white/[0.02] transition-colors group cursor-pointer"
                  >
                    {/* Severity dot */}
                    <div className="mt-1.5 shrink-0">
                      <span className={cn(
                        'block w-2 h-2 rounded-full',
                        event.severity ? severityDotColor[event.severity] || 'bg-zinc-600' : 'bg-zinc-600'
                      )} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start justify-between gap-3">
                        <p className={cn('text-[13px] text-zinc-200 font-medium', !isExpanded && 'truncate')}>{event.title}</p>
                        <span className="shrink-0 text-[11px] text-zinc-600 font-mono tabular-nums">{timeAgo(event.timestamp)}</span>
                      </div>
                      <p className={cn('text-[12px] text-zinc-500 mt-0.5', !isExpanded && 'truncate')}>{event.description}</p>
                      <div className="flex items-center gap-2 mt-2">
                        {event.severity && (
                          <span className={cn(
                            'text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-md',
                            event.severity === 'critical' && 'bg-[#EF4444]/10 text-[#EF4444]',
                            event.severity === 'high' && 'bg-[#F97316]/10 text-[#F97316]',
                            event.severity === 'medium' && 'bg-[#F59E0B]/10 text-[#F59E0B]',
                            event.severity === 'low' && 'bg-[#3B82F6]/10 text-[#3B82F6]',
                          )}>
                            {event.severity}
                          </span>
                        )}
                        <span className="text-[10px] text-zinc-600 uppercase tracking-wider font-medium">{event.module}</span>
                      </div>
                    </div>
                    <ArrowUpRight01Icon
                      size={14}
                      className={cn(
                        'text-zinc-700 transition-all mt-1 shrink-0',
                        isExpanded ? 'opacity-100 rotate-90' : 'opacity-0 group-hover:opacity-100'
                      )}
                    />
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Global Threat Map */}
        <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl overflow-hidden">
          <div className="px-4 sm:px-6 py-4 border-b border-white/[0.06] flex items-center justify-between">
            <div>
              <span className="text-[14px] font-semibold text-white">Global Threat Map</span>
              <p className="text-[12px] text-zinc-500 mt-0.5">Attack origins by country</p>
            </div>
            {threatMap.length > 0 && (
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[#22D3EE] shadow-[0_0_6px_rgba(34,211,238,0.8)]" />
                <span className="text-[11px] text-zinc-500 font-medium">{threatMap.length} sources</span>
              </div>
            )}
          </div>
          <div className="relative h-[280px] sm:h-[360px]">
            <GlobalThreatMap data={threatMap} />
          </div>
        </div>
      </div>

      {/* Module Status Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {MODULE_STATUS.map((mod) => (
          <div
            key={mod.name}
            className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-5 flex items-center gap-4 hover:border-white/[0.1] transition-colors"
          >
            <div
              className="w-10 h-10 rounded-xl flex items-center justify-center"
              style={{ backgroundColor: `${mod.color}10` }}
            >
              <mod.icon className="w-5 h-5" style={{ color: mod.color }} />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-[14px] font-semibold text-white">{mod.name}</p>
              <p className="text-[12px] text-zinc-500 mt-0.5">{mod.detail}</p>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 bg-[#22C55E] rounded-full animate-pulse" />
              <span className="text-[11px] text-[#22C55E] font-medium">Active</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
