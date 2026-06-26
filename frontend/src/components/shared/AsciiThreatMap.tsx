'use client';

import { useMemo } from 'react';

export interface ThreatMapEntry {
  country: string;
  country_code: string;
  count: number;
}

export interface ThreatMapSource {
  country: string;
  ip: string;
  attacks: number;
  last_seen?: string;
  city?: string;
}

export interface AsciiThreatMapProps {
  data?: ThreatMapEntry[];
  sources?: ThreatMapSource[];
  className?: string;
}

const VBW = 1000;
const VBH = 500;
function project(lon: number, lat: number): [number, number] {
  const x = ((lon + 180) / 360) * VBW;
  const y = ((90 - lat) / 180) * VBH;
  return [x, y];
}

const CC_TO_LATLON: Record<string, [number, number]> = {
  AD: [1.6, 42.5], AE: [54.4, 23.4], AF: [67.7, 33.9], AG: [-61.8, 17.1], AL: [20.2, 41.2],
  AM: [45.0, 40.1], AO: [17.9, -11.2], AR: [-63.6, -38.4], AT: [14.6, 47.5], AU: [133.8, -25.3],
  AZ: [47.6, 40.1], BA: [17.7, 43.9], BB: [-59.5, 13.2], BD: [90.4, 23.7], BE: [4.5, 50.5],
  BF: [-1.6, 12.2], BG: [25.5, 42.7], BH: [50.6, 26.0], BI: [29.9, -3.4], BJ: [2.3, 9.3],
  BN: [114.7, 4.5], BO: [-63.6, -16.3], BR: [-51.9, -14.2], BS: [-77.4, 25.0], BT: [90.4, 27.5],
  BW: [24.7, -22.3], BY: [27.95, 53.7], BZ: [-88.5, 17.2], CA: [-106.3, 56.1], CD: [21.8, -4.0],
  CF: [20.9, 6.6], CG: [15.8, -0.2], CH: [8.2, 46.8], CI: [-5.5, 7.5], CL: [-71.5, -35.7],
  CM: [12.4, 7.4], CN: [104.2, 35.9], CO: [-74.3, 4.6], CR: [-83.8, 9.7], CU: [-77.8, 21.5],
  CV: [-24.0, 16.0], CY: [33.4, 35.1], CZ: [15.5, 49.8], DE: [10.5, 51.2], DJ: [42.6, 11.8],
  DK: [9.5, 56.3], DM: [-61.4, 15.4], DO: [-70.2, 18.7], DZ: [1.7, 28.0], EC: [-78.2, -1.8],
  EE: [25.0, 58.6], EG: [30.8, 26.8], ER: [39.8, 15.2], ES: [-3.7, 40.5], ET: [40.5, 9.1],
  FI: [25.7, 61.9], FJ: [178.1, -16.6], FR: [2.2, 46.2], GA: [11.6, -0.8], GB: [-3.4, 55.4],
  GD: [-61.7, 12.1], GE: [43.4, 42.3], GH: [-1.0, 7.9], GL: [-42.6, 71.7], GM: [-15.3, 13.4],
  GN: [-9.7, 9.9], GQ: [10.3, 1.7], GR: [21.8, 39.0], GT: [-90.2, 15.8], GW: [-15.2, 11.8],
  GY: [-58.9, 4.9], HK: [114.1, 22.4], HN: [-86.2, 15.2], HR: [15.2, 45.1], HT: [-72.3, 18.9],
  HU: [19.5, 47.2], ID: [113.9, -0.8], IE: [-8.2, 53.4], IL: [34.8, 31.0], IN: [78.96, 20.59],
  IQ: [43.7, 33.2], IR: [53.7, 32.4], IS: [-19.0, 64.9], IT: [12.6, 41.9], JM: [-77.3, 18.1],
  JO: [36.2, 30.6], JP: [138.3, 36.2], KE: [37.9, -0.0], KG: [74.8, 41.2], KH: [104.9, 12.6],
  KM: [43.9, -11.9], KN: [-62.8, 17.3], KP: [127.5, 40.3], KR: [127.8, 35.9], KW: [47.5, 29.3],
  KZ: [66.9, 48.0], LA: [102.5, 19.9], LB: [35.9, 33.9], LC: [-61.0, 13.9], LI: [9.5, 47.2],
  LK: [80.8, 7.9], LR: [-9.4, 6.4], LS: [28.2, -29.6], LT: [23.9, 55.2], LU: [6.1, 49.8],
  LV: [24.6, 56.9], LY: [17.2, 26.3], MA: [-7.1, 31.8], MC: [7.4, 43.7], MD: [28.4, 47.4],
  ME: [19.4, 42.7], MG: [46.9, -18.8], MK: [21.7, 41.6], ML: [-3.9, 17.6], MM: [95.9, 21.9],
  MN: [103.8, 46.9], MO: [113.5, 22.2], MR: [-10.9, 21.0], MT: [14.4, 35.9], MU: [57.5, -20.3],
  MV: [73.2, 3.2], MW: [34.3, -13.3], MX: [-102.6, 23.6], MY: [101.9, 4.2], MZ: [35.5, -18.7],
  NA: [18.5, -22.9], NC: [165.6, -20.9], NE: [8.1, 17.6], NG: [8.7, 9.1], NI: [-85.2, 12.9],
  NL: [5.3, 52.1], NO: [8.5, 60.5], NP: [84.1, 28.4], NZ: [174.9, -40.9], OM: [55.9, 21.5],
  PA: [-80.8, 8.5], PE: [-75.0, -9.2], PG: [143.9, -6.3], PH: [121.8, 12.9], PK: [69.3, 30.4],
  PL: [19.1, 51.9], PR: [-66.6, 18.2], PS: [35.2, 31.9], PT: [-8.2, 39.4], PY: [-58.4, -23.4],
  QA: [51.2, 25.4], RE: [55.5, -21.1], RO: [25.0, 45.9], RS: [21.0, 44.0], RU: [105.3, 61.5],
  RW: [29.9, -1.9], SA: [45.1, 23.9], SB: [160.2, -9.6], SC: [55.5, -4.7], SD: [30.2, 12.9],
  SE: [18.6, 60.1], SG: [103.8, 1.4], SI: [14.9, 46.2], SK: [19.7, 48.7], SL: [-11.8, 8.5],
  SM: [12.5, 43.9], SN: [-14.5, 14.5], SO: [46.2, 5.2], SR: [-56.0, 3.9], SS: [31.3, 6.9],
  SV: [-88.9, 13.8], SY: [38.0, 34.8], SZ: [31.5, -26.5], TD: [18.7, 15.5], TG: [0.8, 8.6],
  TH: [100.9, 15.9], TJ: [71.3, 38.9], TL: [125.7, -8.9], TM: [59.6, 38.9], TN: [9.5, 33.9],
  TR: [35.2, 38.9], TT: [-61.2, 10.7], TW: [121.0, 23.7], TZ: [34.9, -6.4], UA: [31.2, 48.4],
  UG: [32.3, 1.4], US: [-95.7, 37.1], UY: [-55.8, -32.5], UZ: [64.6, 41.4], VE: [-66.6, 6.4],
  VN: [108.3, 14.1], YE: [48.5, 15.6], ZA: [22.9, -30.6], ZM: [27.8, -13.1], ZW: [29.2, -19.0],
};

function pathFor(coords: Array<[number, number]>): string {
  return coords.map(([lon, lat], i) => {
    const [x, y] = project(lon, lat);
    return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ') + ' Z';
}

const NORTH_AMERICA: Array<[number, number]> = [
  [-168, 66], [-156, 71], [-140, 70], [-128, 70], [-110, 73], [-95, 75], [-82, 73],
  [-70, 70], [-60, 66], [-55, 60], [-58, 52], [-64, 47], [-66, 44], [-70, 42],
  [-74, 39], [-76, 36], [-80, 32], [-82, 29], [-80, 26], [-83, 25], [-88, 30],
  [-94, 29], [-97, 26], [-97, 22], [-98, 18], [-95, 16], [-90, 14], [-86, 12],
  [-83, 9], [-79, 9], [-77, 8], [-83, 11], [-87, 15], [-94, 17], [-105, 20],
  [-110, 23], [-115, 28], [-118, 33], [-122, 37], [-124, 42], [-124, 48],
  [-130, 54], [-136, 58], [-145, 60], [-152, 59], [-158, 56], [-162, 58], [-166, 60], [-168, 66],
];
const SOUTH_AMERICA: Array<[number, number]> = [
  [-77, 9], [-72, 10], [-66, 8], [-60, 5], [-52, 2], [-50, -4], [-44, -7], [-38, -10],
  [-35, -8], [-37, -14], [-40, -22], [-46, -24], [-52, -30], [-58, -34], [-62, -39],
  [-67, -45], [-71, -52], [-72, -55], [-68, -54], [-65, -50], [-69, -42], [-71, -36],
  [-73, -30], [-71, -22], [-70, -18], [-72, -14], [-76, -10], [-79, -6], [-80, -2],
  [-78, 1], [-77, 5], [-77, 9],
];
const AFRICA: Array<[number, number]> = [
  [-17, 14], [-10, 27], [-6, 35], [0, 36], [9, 36], [12, 33], [22, 32], [33, 31],
  [34, 27], [37, 22], [40, 15], [44, 12], [49, 11], [51, 11], [49, 6], [42, 1],
  [40, -2], [40, -10], [40, -15], [37, -20], [33, -26], [30, -28], [25, -33],
  [20, -34], [18, -33], [16, -28], [13, -22], [9, -14], [13, -8], [12, -3],
  [11, 0], [9, 4], [4, 6], [-4, 5], [-7, 4], [-11, 7], [-14, 11], [-17, 14],
];
const EUROPE: Array<[number, number]> = [
  [-9, 38], [-6, 36], [-2, 36], [3, 39], [9, 40], [12, 38], [16, 38], [20, 40],
  [24, 36], [26, 36], [28, 36], [30, 37], [40, 37], [40, 43], [38, 46], [33, 48],
  [27, 52], [22, 55], [16, 58], [10, 59], [5, 58], [-1, 51], [-5, 50], [-9, 53], [-9, 38],
];
const RUSSIA: Array<[number, number]> = [
  [27, 60], [40, 67], [50, 68], [60, 70], [70, 71], [80, 73], [95, 76], [110, 74],
  [130, 73], [150, 72], [170, 70], [175, 68], [178, 65], [170, 62], [160, 60],
  [150, 60], [140, 55], [135, 53], [130, 48], [125, 47], [115, 49], [105, 50],
  [90, 51], [80, 50], [70, 48], [60, 48], [50, 50], [42, 48], [35, 51], [30, 55], [27, 60],
];
const MIDDLE_EAST: Array<[number, number]> = [
  [34, 37], [40, 38], [46, 38], [50, 36], [55, 32], [58, 25], [56, 20], [50, 16],
  [44, 12], [40, 15], [36, 22], [33, 28], [34, 31], [34, 37],
];
const INDIA: Array<[number, number]> = [
  [68, 35], [75, 34], [80, 30], [85, 27], [90, 26], [92, 22], [88, 21], [82, 19],
  [80, 15], [78, 11], [76, 8], [73, 13], [70, 17], [70, 23], [68, 28], [68, 35],
];
const CHINA: Array<[number, number]> = [
  [73, 48], [85, 47], [95, 43], [105, 42], [115, 42], [120, 41], [125, 40], [120, 35],
  [122, 30], [120, 24], [115, 22], [108, 20], [105, 22], [100, 22], [98, 25],
  [98, 30], [90, 32], [82, 35], [78, 40], [73, 42], [73, 48],
];
const SE_ASIA: Array<[number, number]> = [
  [98, 18], [103, 14], [106, 11], [109, 11], [109, 15], [107, 18], [104, 21], [101, 20], [98, 18],
];
const INDONESIA: Array<[number, number]> = [
  [95, 5], [104, 3], [108, -2], [114, -4], [120, -4], [124, -5], [128, -3], [130, -1],
  [127, 1], [118, 4], [110, 1], [102, 5], [95, 5],
];
const PHILIPPINES: Array<[number, number]> = [
  [120, 18], [122, 16], [125, 11], [126, 7], [123, 6], [121, 11], [120, 18],
];
const JAPAN: Array<[number, number]> = [
  [130, 32], [134, 33], [138, 35], [141, 39], [142, 43], [145, 44], [144, 41],
  [140, 38], [136, 35], [132, 33], [130, 32],
];
const KOREA: Array<[number, number]> = [
  [126, 38], [128, 37], [129, 36], [129, 33], [127, 34], [125, 36], [126, 38],
];
const AUSTRALIA: Array<[number, number]> = [
  [114, -22], [122, -19], [130, -13], [135, -12], [142, -10], [146, -18], [150, -25],
  [153, -28], [151, -34], [144, -38], [138, -36], [133, -32], [128, -32], [120, -34],
  [115, -34], [113, -27], [114, -22],
];
const NZ_NORTH: Array<[number, number]> = [
  [173, -34], [177, -36], [178, -39], [175, -41], [172, -40], [173, -38], [173, -34],
];
const NZ_SOUTH: Array<[number, number]> = [
  [168, -42], [173, -42], [174, -46], [170, -47], [167, -45], [168, -42],
];
const GREENLAND: Array<[number, number]> = [
  [-55, 83], [-30, 84], [-20, 81], [-22, 75], [-30, 70], [-40, 64], [-50, 62],
  [-54, 67], [-58, 72], [-60, 78], [-55, 83],
];
const ICELAND: Array<[number, number]> = [
  [-24, 66], [-19, 67], [-14, 66], [-14, 64], [-20, 63], [-23, 64], [-24, 66],
];
const UK: Array<[number, number]> = [
  [-5, 58], [-2, 58], [1, 53], [-1, 51], [-3, 50], [-5, 51], [-5, 55], [-5, 58],
];
const IRELAND: Array<[number, number]> = [
  [-10, 55], [-6, 55], [-6, 52], [-10, 52], [-10, 55],
];
const ITALY: Array<[number, number]> = [
  [7, 46], [13, 46], [15, 42], [18, 40], [16, 39], [14, 37], [12, 38], [9, 41], [7, 44], [7, 46],
];
const MADAGASCAR: Array<[number, number]> = [
  [44, -12], [50, -14], [50, -25], [44, -25], [43, -20], [44, -12],
];
const CUBA: Array<[number, number]> = [
  [-85, 22], [-77, 22], [-75, 20], [-78, 20], [-83, 21], [-85, 22],
];
const HISPANIOLA: Array<[number, number]> = [
  [-74, 19], [-69, 20], [-68, 18], [-71, 18], [-74, 18], [-74, 19],
];
const SCANDINAVIA: Array<[number, number]> = [
  [5, 60], [11, 64], [15, 68], [22, 70], [29, 70], [29, 65], [24, 60], [18, 58], [11, 58], [8, 58], [5, 60],
];

const ALL_LANDS = [
  NORTH_AMERICA, SOUTH_AMERICA, AFRICA, EUROPE, RUSSIA, MIDDLE_EAST, INDIA,
  CHINA, SE_ASIA, INDONESIA, PHILIPPINES, JAPAN, KOREA, AUSTRALIA,
  NZ_NORTH, NZ_SOUTH, GREENLAND, ICELAND, UK, IRELAND, ITALY,
  MADAGASCAR, CUBA, HISPANIOLA, SCANDINAVIA,
];

type MarkerPoint = {
  cc: string;
  count: number;
  x: number;
  y: number;
  ratio: number;
  tier: 'low' | 'med' | 'high';
  label?: boolean;
};

export function AsciiThreatMap({ data, sources, className }: AsciiThreatMapProps) {
  const aggregated = useMemo<Map<string, number>>(() => {
    const m = new Map<string, number>();
    if (data) for (const r of data) if (r?.country_code) m.set(r.country_code, (m.get(r.country_code) || 0) + r.count);
    if (sources) for (const s of sources) if (s?.country) m.set(s.country, (m.get(s.country) || 0) + (s.attacks || 0));
    return m;
  }, [data, sources]);

  const total = useMemo(() => { let t = 0; aggregated.forEach((v) => { t += v; }); return t; }, [aggregated]);
  const peak = useMemo(() => { let p = 0; aggregated.forEach((v) => { if (v > p) p = v; }); return p || 1; }, [aggregated]);

  const points: MarkerPoint[] = useMemo(() => {
    const out: MarkerPoint[] = [];
    aggregated.forEach((count, cc) => {
      const coords = CC_TO_LATLON[cc];
      if (!coords) return;
      const [x, y] = project(coords[0], coords[1]);
      const ratio = Math.min(1, count / peak);
      const tier: 'low' | 'med' | 'high' = ratio > 0.66 ? 'high' : ratio > 0.33 ? 'med' : 'low';
      out.push({ cc, count, x, y, ratio, tier });
    });
    const topByCount = [...out].sort((a, b) => b.count - a.count).slice(0, 5);
    for (const p of topByCount) p.label = true;
    return out;
  }, [aggregated, peak]);

  const countries = aggregated.size;
  const isEmpty = countries === 0;

  return (
    <div className={`relative w-full h-full bg-card rounded-2xl overflow-hidden border border-border/40 ${className || ''}`}>
      <div className="absolute top-3 left-3 z-10 flex items-center gap-2 px-2.5 py-1 rounded-md bg-background/70 border border-border/60 backdrop-blur-sm">
        <span className="w-1.5 h-1.5 rounded-full bg-[#22D3EE] animate-pulse" />
        <span className="text-[10px] font-mono uppercase tracking-[0.16em] text-foreground/85">
          {countries} {countries === 1 ? 'country' : 'countries'} · {total.toLocaleString()} attacks
        </span>
      </div>

      <svg
        viewBox={`0 0 ${VBW} ${VBH}`}
        className="w-full h-full block"
        preserveAspectRatio="xMidYMid meet"
        style={{ background: 'radial-gradient(ellipse at center, #1A1D24 0%, #131519 100%)' }}
      >
        <defs>
          <pattern id="aegis-dot-grid" x="0" y="0" width="22" height="22" patternUnits="userSpaceOnUse">
            <circle cx="11" cy="11" r="0.6" fill="rgba(255,255,255,0.04)" />
          </pattern>
          <filter id="aegis-halo-glow" x="-100%" y="-100%" width="300%" height="300%">
            <feGaussianBlur stdDeviation="6" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        <rect width={VBW} height={VBH} fill="url(#aegis-dot-grid)" />

        <g fill="rgba(34,211,238,0.10)" stroke="rgba(34,211,238,0.55)" strokeWidth="1.1" strokeLinejoin="round">
          {ALL_LANDS.map((coords, i) => <path key={i} d={pathFor(coords)} />)}
        </g>

        <g>
          {points.map((p) => {
            const color = p.tier === 'high' ? '#F87171' : p.tier === 'med' ? '#F97316' : '#22D3EE';
            const r = 6 + p.ratio * 18;
            return (
              <circle key={`h-${p.cc}`} cx={p.x} cy={p.y} r={r} fill={color} opacity={0.18} filter="url(#aegis-halo-glow)" />
            );
          })}
        </g>

        <g>
          {points.map((p) => {
            const color = p.tier === 'high' ? '#F87171' : p.tier === 'med' ? '#F97316' : '#22D3EE';
            const r = 3 + p.ratio * 6;
            const pulse = p.tier === 'high';
            return (
              <circle
                key={`d-${p.cc}`}
                cx={p.x} cy={p.y} r={r}
                fill={color}
                stroke="rgba(0,0,0,0.55)" strokeWidth={1}
                style={pulse ? { animation: 'aegis-threat-pulse 1.8s ease-in-out infinite' } : undefined}
              >
                <title>{`${p.cc}: ${p.count.toLocaleString()} attacks`}</title>
              </circle>
            );
          })}
        </g>

        <g fontFamily="Azeret Mono, ui-monospace, monospace" fontSize={14} fontWeight={600} fill="rgba(255,255,255,0.92)">
          {points.filter((p) => p.label).map((p) => {
            const rightEdge = p.x > VBW * 0.82;
            const topEdge = p.y < 30;
            const lx = rightEdge ? p.x - 14 : p.x + 14;
            const ly = topEdge ? p.y + 18 : p.y - 12;
            return (
              <text
                key={`l-${p.cc}`}
                x={lx} y={ly}
                textAnchor={rightEdge ? 'end' : 'start'}
                stroke="#16181D" strokeWidth={3} paintOrder="stroke"
              >
                {p.cc}
                <tspan dx="6" fontSize={11} fontWeight={500} fill="rgba(255,255,255,0.55)">
                  {p.count >= 1000 ? `${(p.count / 1000).toFixed(1)}k` : p.count}
                </tspan>
              </text>
            );
          })}
        </g>
      </svg>

      {isEmpty && (
        <div className="absolute inset-0 grid place-items-center pointer-events-none">
          <span
            className="text-[12px] font-mono uppercase tracking-[0.22em] text-[#22D3EE]/70"
            style={{ textShadow: '0 0 14px rgba(34,211,238,0.45)' }}
          >
            NO THREAT DATA
          </span>
        </div>
      )}

      <style jsx>{`
        @keyframes aegis-threat-pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.55; }
        }
      `}</style>
    </div>
  );
}

export { AsciiThreatMap as GlobalThreatMap };
