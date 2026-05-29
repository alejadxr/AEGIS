'use client';

import { useState, useEffect } from 'react';

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

function markerColor(count: number, maxCount: number): string {
  const ratio = count / maxCount;
  if (ratio > 0.66) return 'var(--danger)';
  if (ratio > 0.33) return 'var(--brand-accent)';
  return 'var(--brand)';
}

interface TooltipState {
  entry: ThreatMapEntry;
  x: number;
  y: number;
  color: string;
}

export function GlobalThreatMap({ data }: { data: ThreatMapEntry[] }) {
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);
  const [isDark, setIsDark] = useState(true);
  const maxCount = data.length > 0 ? Math.max(...data.map((d) => d.count)) : 1;

  useEffect(() => {
    const check = () => {
      setIsDark(
        document.documentElement.getAttribute('data-theme') === 'dark' ||
          document.documentElement.classList.contains('dark'),
      );
    };
    check();
    const obs = new MutationObserver(check);
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme', 'class'] });
    return () => obs.disconnect();
  }, []);

  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const maps = typeof window !== 'undefined' ? require('react-simple-maps') : null;
  const geoUrl = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

  const mapBg = isDark ? '#0D0D0F' : '#F4F4F5';
  const mapLand = isDark ? '#1A1A1F' : '#D4D4D8';
  const mapStroke = isDark ? '#2A2A32' : '#A1A1AA';
  const tooltipBg = isDark ? 'rgba(13,13,15,0.97)' : 'rgba(244,244,245,0.97)';
  const tooltipText = isDark ? '#FAFAFA' : '#18181B';
  const tooltipMuted = isDark ? '#52525B' : '#71717A';

  if (!maps || data.length === 0) {
    return (
      <div className="h-full flex items-center justify-center">
        <p
          className="text-[11px] text-muted-foreground/60"
          style={{ fontFamily: 'Azeret Mono, monospace', letterSpacing: '0.15em' }}
        >
          // NO THREAT DATA
        </p>
      </div>
    );
  }

  // CRT scanline + dot grid CSS (overlay only — no rewrite of SVG)
  const scanlineStyle: React.CSSProperties = {
    position: 'absolute',
    inset: 0,
    pointerEvents: 'none',
    zIndex: 2,
    backgroundImage: [
      // Horizontal scanlines every 3px
      'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.18) 2px, rgba(0,0,0,0.18) 3px)',
      // Dot grid every 8px
      'radial-gradient(circle, rgba(255,255,255,0.04) 1px, transparent 1px)',
    ].join(', '),
    backgroundSize: '100% 3px, 8px 8px',
    mixBlendMode: 'overlay',
  };

  const vignette: React.CSSProperties = {
    position: 'absolute',
    inset: 0,
    pointerEvents: 'none',
    zIndex: 3,
    background: `radial-gradient(ellipse at center, transparent 50%, ${mapBg}CC 100%)`,
  };

  return (
    <div
      className="relative w-full h-full select-none overflow-x-auto overflow-y-hidden"
      style={{ background: mapBg }}
    >
      {/* CRT scanline + dot grid overlay */}
      <div style={scanlineStyle} aria-hidden />
      {/* Vignette fade */}
      <div style={vignette} aria-hidden />

      {/* Pixel map */}
      <maps.ComposableMap
        projectionConfig={{ rotate: [-10, 0, 0], scale: 147 }}
        width={800}
        height={400}
        style={{
          width: '100%',
          height: '100%',
          imageRendering: 'pixelated',
        }}
      >
        <maps.Geographies geography={geoUrl}>
          {({ geographies }: { geographies: Array<{ rsmKey: string }> }) =>
            geographies.map((geo) => (
              <maps.Geography
                key={geo.rsmKey}
                geography={geo}
                fill={mapLand}
                stroke={mapStroke}
                strokeWidth={0.5}
                style={{
                  default: { outline: 'none' },
                  hover: { fill: mapLand, outline: 'none' },
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
          // Pixel size: 3–7px square, steps of 2
          const px = 3 + Math.round(normalized * 2) * 2;
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
                  color,
                });
              }}
              onMouseLeave={() => setTooltip(null)}
            >
              {/* Outer pixel glow ring — square */}
              {isActive && (
                <rect
                  x={-px * 2}
                  y={-px * 2}
                  width={px * 4}
                  height={px * 4}
                  fill={color}
                  opacity={0.12}
                  style={{ shapeRendering: 'crispEdges' }}
                />
              )}
              {/* Pulse ring — square, animated */}
              <rect
                x={-px * 1.5}
                y={-px * 1.5}
                width={px * 3}
                height={px * 3}
                fill="none"
                stroke={color}
                strokeWidth={0.8}
                opacity={0}
                style={{ shapeRendering: 'crispEdges' }}
              >
                <animate attributeName="opacity" values="0.5;0;0.5" dur="2.5s" repeatCount="indefinite" />
                <animate attributeName="x" values={`${-px * 1.5};${-px * 2};${-px * 1.5}`} dur="2.5s" repeatCount="indefinite" />
                <animate attributeName="y" values={`${-px * 1.5};${-px * 2};${-px * 1.5}`} dur="2.5s" repeatCount="indefinite" />
                <animate attributeName="width" values={`${px * 3};${px * 4};${px * 3}`} dur="2.5s" repeatCount="indefinite" />
                <animate attributeName="height" values={`${px * 3};${px * 4};${px * 3}`} dur="2.5s" repeatCount="indefinite" />
              </rect>
              {/* Core pixel square marker */}
              <rect
                x={-px / 2}
                y={-px / 2}
                width={px}
                height={px}
                fill={color}
                opacity={isActive ? 1 : 0.9}
                style={{
                  cursor: 'pointer',
                  shapeRendering: 'crispEdges',
                  filter: isActive ? `drop-shadow(0 0 ${px}px ${color})` : undefined,
                }}
              />
              {/* Monospace label — only for high count */}
              {normalized > 0.33 && (
                <text
                  x={px + 3}
                  y={3}
                  fontSize={6}
                  fill={color}
                  opacity={0.85}
                  fontFamily="Azeret Mono, monospace"
                  style={{ userSelect: 'none', pointerEvents: 'none' }}
                >
                  {entry.count.toString().padStart(3, '0')}
                </text>
              )}
            </maps.Marker>
          );
        })}
      </maps.ComposableMap>

      {/* Tooltip */}
      {tooltip && (
        <div
          className="absolute z-20 pointer-events-none"
          style={{
            left: tooltip.x,
            top: tooltip.y,
            transform: 'translate(-50%, calc(-100% - 10px))',
          }}
        >
          {/* Connector line */}
          <div
            className="absolute left-1/2 -translate-x-px bottom-0 w-px translate-y-full"
            style={{ height: 10, background: `linear-gradient(to bottom, ${tooltip.color}90, transparent)` }}
          />
          <div
            style={{
              background: tooltipBg,
              border: `1px solid ${tooltip.color}40`,
              fontFamily: 'Azeret Mono, monospace',
              boxShadow: `0 0 0 1px ${tooltip.color}18, 0 8px 24px rgba(0,0,0,0.35)`,
              borderRadius: 4,
              padding: '8px 10px',
              minWidth: 120,
            }}
          >
            <div
              style={{
                fontSize: 9,
                letterSpacing: '0.18em',
                textTransform: 'uppercase',
                color: tooltipMuted,
                marginBottom: 4,
              }}
            >
              {tooltip.entry.country_code}
            </div>
            <div
              style={{ fontSize: 11, fontWeight: 700, color: tooltipText, marginBottom: 6, letterSpacing: '0.04em' }}
            >
              {COUNTRY_COORDS[tooltip.entry.country_code]?.label ?? tooltip.entry.country}
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <span style={{ fontSize: 16, fontWeight: 900, color: tooltip.color, letterSpacing: '-0.02em' }}>
                {String(tooltip.entry.count).padStart(4, '0')}
              </span>
              <span style={{ fontSize: 9, color: tooltipMuted, letterSpacing: '0.1em', textTransform: 'uppercase' }}>
                events
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Legend */}
      <div
        className="absolute bottom-3 left-3 z-10 flex items-center gap-3 px-2.5 py-1.5"
        style={{
          background: isDark ? 'rgba(13,13,15,0.75)' : 'rgba(244,244,245,0.75)',
          border: '1px solid rgba(255,255,255,0.06)',
          borderRadius: 3,
          fontFamily: 'Azeret Mono, monospace',
        }}
      >
        {([
          { label: 'CRIT', color: 'var(--danger)' },
          { label: 'HIGH', color: 'var(--brand-accent)' },
          { label: 'LOW', color: 'var(--brand)' },
        ] as const).map(({ label, color }) => (
          <div key={label} className="flex items-center gap-1.5">
            {/* Square pixel dot for legend */}
            <svg width="6" height="6" viewBox="0 0 6 6" style={{ shapeRendering: 'crispEdges', flexShrink: 0 }}>
              <rect x="0" y="0" width="6" height="6" fill={color} />
            </svg>
            <span style={{ fontSize: 9, color: 'var(--muted-foreground)', letterSpacing: '0.12em' }}>{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
