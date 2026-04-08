'use client';

import { useState } from 'react';

export interface ThreatMapEntry {
  country: string;
  country_code: string;
  count: number;
}

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
  CN: 'CN', RU: 'RU', US: 'US', BR: 'BR', IR: 'IR',
  KP: 'KP', IN: 'IN', DE: 'DE', NL: 'NL', KR: 'KR',
  GB: 'GB', FR: 'FR', UA: 'UA', TR: 'TR', VN: 'VN',
  TH: 'TH', PK: 'PK', NG: 'NG', ZA: 'ZA', MX: 'MX',
  HK: 'HK', JP: 'JP', AU: 'AU', CA: 'CA',
};

interface TooltipState {
  entry: ThreatMapEntry;
  x: number;
  y: number;
}

function markerColor(count: number, maxCount: number): string {
  const ratio = count / maxCount;
  if (ratio > 0.66) return '#EF4444';
  if (ratio > 0.33) return '#F97316';
  return '#22D3EE';
}

export function GlobalThreatMap({ data }: { data: ThreatMapEntry[] }) {
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
      <div className="pointer-events-none absolute inset-0 z-[1]"
        style={{
          background: `radial-gradient(ellipse at center, transparent 55%, ${mapVignette} 100%)`,
        }}
      />
      <div className="pointer-events-none absolute inset-y-0 left-0 w-12 z-[1]"
        style={{ background: `linear-gradient(to right, ${mapVignette}, transparent)` }}
      />
      <div className="pointer-events-none absolute inset-y-0 right-0 w-12 z-[1]"
        style={{ background: `linear-gradient(to left, ${mapVignette}, transparent)` }}
      />

      <div className="absolute top-3 right-3 z-10 flex flex-col gap-1">
        <button
          onClick={() => setZoom((z) => Math.min(z + 0.5, 4))}
          className="w-7 h-7 rounded-xl bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.06] text-zinc-400 hover:text-zinc-200 text-sm font-semibold flex items-center justify-center transition-all duration-150 font-mono"
          aria-label="Zoom in"
        >
          +
        </button>
        <button
          onClick={() => setZoom((z) => Math.max(z - 0.5, 1))}
          disabled={zoom <= 1}
          className="w-7 h-7 rounded-xl bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.06] text-zinc-400 hover:text-zinc-200 disabled:opacity-30 disabled:cursor-not-allowed text-sm font-semibold flex items-center justify-center transition-all duration-150 font-mono"
          aria-label="Zoom out"
        >
          −
        </button>
      </div>

      {tooltip && (
        <div
          className="absolute z-20 pointer-events-none"
          style={{ left: tooltip.x, top: tooltip.y, transform: 'translate(-50%, calc(-100% - 14px))' }}
        >
          <div
            className="absolute left-1/2 -translate-x-px bottom-0 w-px translate-y-full"
            style={{ height: 14, background: `linear-gradient(to bottom, ${activeColor}80, transparent)` }}
          />
          <div
            className="rounded-xl px-3 py-2.5 shadow-2xl min-w-[148px] backdrop-blur-sm"
            style={{
              background: 'rgba(24,24,27,0.95)',
              border: `1px solid ${activeColor}35`,
              boxShadow: `0 8px 32px rgba(0,0,0,0.5), 0 0 0 1px ${activeColor}10, 0 0 24px ${activeColor}15`,
            }}
          >
            <div className="flex items-center gap-2 mb-2">
              <span className="text-[10px] leading-none shrink-0 font-mono text-zinc-400">
                {COUNTRY_FLAGS[tooltip.entry.country_code] ?? '--'}
              </span>
              <span className="text-[12px] font-semibold text-white tracking-tight truncate">
                {COUNTRY_COORDS[tooltip.entry.country_code]?.label ?? tooltip.entry.country}
              </span>
            </div>
            <div className="w-full h-px bg-white/[0.06] mb-2" />
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
                <circle r={r * 3.2} fill={color} opacity={0}>
                  <animate attributeName="r" values={`${r * 2.2};${r * 3.8};${r * 2.2}`} dur="4s" begin="0s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0;0.12;0" dur="4s" begin="0s" repeatCount="indefinite" />
                </circle>
                <circle r={r * 2} fill={color} opacity={0}>
                  <animate attributeName="r" values={`${r};${r * 2.4};${r}`} dur="2.5s" begin="0.5s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.18;0;0.18" dur="2.5s" begin="0.5s" repeatCount="indefinite" />
                </circle>
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
