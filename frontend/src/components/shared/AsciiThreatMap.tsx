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

const PX_W = 200;
const PX_H = 128;
const COLS = PX_W / 2;
const ROWS = PX_H / 4;

// Equirectangular projection. Y inverted: latitude decreases as pixel y grows.
function lonLatToPx(lon: number, lat: number): [number, number] {
  const x = ((lon + 180) / 360) * PX_W;
  const y = ((90 - lat) / 180) * PX_H;
  return [x, y];
}

function lonLatToCell(lon: number, lat: number): [number, number] {
  const [x, y] = lonLatToPx(lon, lat);
  return [x / 2, y / 4];
}

type Polygon = Array<[number, number]>;

const CONTINENTS: Polygon[] = [
  [
    [-168, 66], [-156, 71], [-140, 70], [-128, 70], [-110, 73], [-95, 75], [-82, 73],
    [-70, 70], [-60, 66], [-55, 60], [-58, 52], [-64, 47], [-66, 44], [-70, 42],
    [-74, 39], [-76, 36], [-80, 32], [-82, 29], [-80, 26], [-83, 25], [-88, 30],
    [-94, 29], [-97, 26], [-97, 22], [-98, 18], [-95, 16], [-90, 14], [-86, 12],
    [-83, 9], [-79, 9], [-77, 8], [-83, 11], [-87, 15], [-94, 17], [-105, 20],
    [-110, 23], [-115, 28], [-118, 33], [-122, 37], [-124, 42], [-124, 48],
    [-130, 54], [-136, 58], [-145, 60], [-152, 59], [-158, 56], [-162, 58],
    [-166, 60], [-168, 66],
  ],
  [
    [-55, 83], [-30, 83], [-22, 78], [-22, 70], [-30, 62], [-42, 60], [-50, 60],
    [-54, 66], [-58, 72], [-55, 78], [-55, 83],
  ],
  [
    [-78, 12], [-72, 12], [-62, 10], [-55, 6], [-50, 1], [-46, -1], [-40, -6],
    [-37, -10], [-36, -15], [-39, -22], [-44, -25], [-50, -32], [-55, -35],
    [-58, -38], [-62, -41], [-65, -45], [-69, -50], [-72, -54], [-70, -56],
    [-67, -53], [-66, -48], [-70, -42], [-72, -37], [-72, -30], [-71, -22],
    [-72, -16], [-76, -12], [-79, -6], [-80, -2], [-80, 2], [-78, 6], [-78, 12],
  ],
  [
    [-17, 21], [-12, 28], [-6, 35], [2, 36], [10, 33], [18, 31], [25, 31],
    [33, 31], [34, 28], [36, 22], [38, 18], [42, 12], [49, 12], [51, 11],
    [50, 5], [48, 1], [42, -1], [40, -7], [39, -12], [40, -18], [38, -22],
    [34, -27], [28, -33], [22, -34], [18, -34], [15, -28], [12, -22], [10, -16],
    [13, -10], [12, -4], [9, 2], [8, 5], [4, 6], [-3, 5], [-8, 6], [-13, 8],
    [-17, 14], [-17, 21],
  ],
  [
    [-10, 36], [-9, 43], [-4, 44], [0, 43], [3, 42], [8, 44], [12, 46], [13, 45],
    [17, 45], [18, 42], [20, 40], [23, 38], [27, 37], [27, 41], [30, 42],
    [32, 45], [36, 47], [40, 48], [44, 50], [50, 53], [55, 58], [58, 62],
    [60, 66], [55, 69], [44, 71], [35, 71], [28, 70], [22, 68], [16, 67],
    [12, 65], [10, 63], [5, 60], [8, 56], [10, 54], [4, 52], [-2, 51],
    [-5, 52], [-6, 56], [-8, 58], [-7, 55], [-9, 52], [-10, 50], [-5, 48],
    [-2, 45], [-9, 43], [-10, 36],
  ],
  [
    [-10, 51], [-6, 55], [-3, 58], [-1, 58], [1, 53], [-2, 51], [-5, 50],
    [-10, 51],
  ],
  [
    [27, 60], [40, 67], [55, 70], [70, 73], [85, 75], [105, 78], [125, 75],
    [140, 73], [155, 71], [170, 68], [178, 65], [175, 62], [160, 60], [150, 58],
    [140, 55], [135, 50], [130, 45], [120, 45], [110, 48], [100, 50], [90, 50],
    [80, 48], [70, 46], [60, 45], [52, 42], [48, 42], [44, 42], [42, 46],
    [40, 50], [35, 52], [30, 55], [27, 60],
  ],
  [
    [34, 37], [40, 38], [46, 39], [50, 38], [52, 35], [56, 28], [58, 24],
    [56, 18], [52, 14], [48, 14], [44, 16], [40, 20], [37, 25], [34, 30],
    [33, 33], [34, 37],
  ],
  [
    [68, 35], [73, 35], [78, 33], [82, 30], [88, 28], [92, 25], [95, 22],
    [92, 20], [89, 22], [86, 21], [82, 17], [80, 13], [78, 9], [76, 11],
    [73, 16], [70, 21], [67, 25], [65, 28], [66, 32], [68, 35],
  ],
  [
    [95, 28], [100, 35], [105, 40], [115, 42], [122, 41], [125, 43], [128, 41],
    [124, 38], [122, 35], [121, 31], [120, 28], [117, 24], [113, 22], [108, 21],
    [105, 19], [108, 16], [108, 12], [105, 10], [102, 12], [100, 14], [98, 16],
    [98, 20], [97, 23], [95, 26], [95, 28],
  ],
  [
    [126, 38], [128, 40], [130, 38], [129, 35], [127, 34], [126, 38],
  ],
  [
    [130, 33], [134, 35], [138, 36], [141, 39], [142, 42], [145, 44], [141, 45],
    [138, 41], [135, 38], [132, 35], [130, 33],
  ],
  [
    [95, 5], [100, 6], [105, 5], [110, 4], [115, 5], [118, 6], [120, 4],
    [123, 0], [122, -3], [118, -5], [114, -8], [110, -8], [105, -7], [100, -3],
    [97, 1], [95, 5],
  ],
  [
    [131, -2], [138, -3], [144, -4], [150, -6], [148, -9], [142, -10], [136, -9],
    [132, -7], [131, -2],
  ],
  [
    [113, -22], [118, -20], [122, -18], [128, -15], [135, -13], [142, -11],
    [145, -15], [149, -20], [153, -25], [152, -30], [148, -36], [142, -38],
    [138, -36], [132, -32], [126, -32], [120, -34], [115, -34], [114, -28],
    [113, -22],
  ],
  [
    [171, -41], [174, -38], [177, -39], [176, -42], [174, -45], [170, -46],
    [167, -45], [168, -42], [171, -41],
  ],
  [
    [-24, 64], [-18, 66], [-14, 66], [-14, 64], [-18, 63], [-22, 63], [-24, 64],
  ],
];

function pointInPolygon(x: number, y: number, poly: Polygon): boolean {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i];
    const [xj, yj] = poly[j];
    const intersect = yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi || 1e-9) + xi;
    if (intersect) inside = !inside;
  }
  return inside;
}

function rasterize(): boolean[][] {
  const grid: boolean[][] = Array.from({ length: PX_H }, () => new Array<boolean>(PX_W).fill(false));
  for (let py = 0; py < PX_H; py++) {
    const lat = 90 - (py / PX_H) * 180;
    for (let px = 0; px < PX_W; px++) {
      const lon = (px / PX_W) * 360 - 180;
      for (const poly of CONTINENTS) {
        if (pointInPolygon(lon, lat, poly)) {
          grid[py][px] = true;
          break;
        }
      }
    }
  }
  return grid;
}

const BRAILLE_BASE = 0x2800;
const DOT_BITS: ReadonlyArray<ReadonlyArray<number>> = [
  [0x01, 0x08],
  [0x02, 0x10],
  [0x04, 0x20],
  [0x40, 0x80],
];

export function pixelGridToBraille(grid: boolean[][]): string[] {
  const h = grid.length;
  const w = grid[0]?.length ?? 0;
  const rows = Math.ceil(h / 4);
  const cols = Math.ceil(w / 2);
  const out: string[] = [];
  for (let cr = 0; cr < rows; cr++) {
    let line = '';
    for (let cc = 0; cc < cols; cc++) {
      let code = 0;
      for (let dy = 0; dy < 4; dy++) {
        for (let dx = 0; dx < 2; dx++) {
          const py = cr * 4 + dy;
          const px = cc * 2 + dx;
          if (py < h && px < w && grid[py][px]) {
            code |= DOT_BITS[dy][dx];
          }
        }
      }
      line += String.fromCharCode(BRAILLE_BASE + code);
    }
    out.push(line);
  }
  return out;
}

let _brailleMap: string[] | null = null;
function getBrailleMap(): string[] {
  if (!_brailleMap) _brailleMap = pixelGridToBraille(rasterize());
  return _brailleMap;
}

const CC_TO_LATLON: Readonly<Record<string, [number, number]>> = {
  US: [-98, 39], CA: [-106, 56], MX: [-102, 23], CU: [-79, 22], BS: [-77, 25], GT: [-90, 15],
  BZ: [-88, 17], HN: [-86, 15], NI: [-85, 13], CR: [-84, 10], PA: [-80, 9], DO: [-70, 19],
  HT: [-72, 19], JM: [-77, 18], PR: [-66, 18], TT: [-61, 11], BB: [-59, 13], GL: [-42, 72],
  CO: [-74, 4], VE: [-66, 8], GY: [-58, 5], SR: [-56, 4], BR: [-53, -10], PE: [-76, -10],
  EC: [-78, -2], BO: [-65, -17], CL: [-71, -35], AR: [-64, -38], PY: [-58, -23], UY: [-56, -33],
  FK: [-59, -52],
  GB: [-2, 54], IE: [-8, 53], FR: [2, 47], ES: [-4, 40], PT: [-8, 40], IT: [12, 43], DE: [10, 51],
  NL: [5, 52], BE: [4, 50], CH: [8, 47], AT: [14, 47], PL: [19, 52], CZ: [15, 50], SK: [19, 49],
  HU: [19, 47], RO: [25, 46], BG: [25, 43], GR: [22, 39], TR: [35, 39], NO: [10, 62], SE: [16, 62],
  FI: [26, 64], DK: [10, 56], IS: [-19, 65], EE: [26, 59], LV: [25, 57], LT: [24, 56], BY: [28, 53],
  UA: [31, 49], MD: [29, 47], RS: [21, 44], HR: [16, 45], BA: [18, 44], SI: [15, 46], MK: [22, 42],
  AL: [20, 41], ME: [19, 42], LU: [6, 50], MT: [14, 36], CY: [33, 35], LI: [9, 47], MC: [7, 44],
  SM: [12, 44], VA: [12, 42], AD: [2, 43], GI: [-5, 36], FO: [-7, 62], AX: [20, 60],
  RU: [100, 60],
  KZ: [67, 48], UZ: [64, 41], TM: [59, 39], KG: [75, 41], TJ: [71, 39], AF: [66, 34], PK: [70, 30],
  IN: [79, 22], NP: [84, 28], BT: [90, 27], BD: [90, 24], LK: [81, 7], MV: [73, 4],
  CN: [104, 35], MN: [104, 47], JP: [138, 36], KR: [128, 36], KP: [127, 40], TW: [121, 24],
  HK: [114, 22], MO: [113, 22], VN: [108, 16], LA: [102, 18], TH: [101, 15], KH: [105, 13],
  MM: [97, 21], MY: [102, 4], SG: [104, 1], ID: [118, -2], BN: [115, 4], PH: [122, 13],
  TL: [125, -8],
  SA: [45, 25], YE: [48, 15], OM: [56, 21], AE: [54, 24], QA: [51, 25], BH: [50, 26],
  KW: [47, 29], JO: [36, 31], IL: [35, 31], LB: [35, 33], SY: [38, 35], IQ: [44, 33],
  IR: [53, 32], GE: [43, 42], AM: [45, 40], AZ: [47, 40], PS: [35, 32],
  EG: [30, 27], LY: [17, 27], DZ: [3, 28], TN: [9, 34], MA: [-7, 32], EH: [-13, 25],
  MR: [-10, 20], ML: [-4, 17], SN: [-15, 14], GM: [-15, 13], GN: [-10, 11], GW: [-15, 12],
  SL: [-12, 8], LR: [-9, 6], CI: [-5, 8], GH: [-1, 8], TG: [1, 8], BJ: [2, 9],
  NE: [8, 17], BF: [-2, 12], NG: [8, 10], CM: [12, 6], CF: [21, 7], TD: [19, 15],
  SD: [30, 16], SS: [31, 7], ER: [39, 15], ET: [40, 9], DJ: [42, 12], SO: [46, 6],
  KE: [38, 1], UG: [32, 1], RW: [30, -2], BI: [30, -3], TZ: [35, -6], CD: [23, -3],
  CG: [15, -1], GA: [12, -1], GQ: [10, 2], ST: [7, 1], AO: [18, -12], ZM: [28, -14],
  ZW: [30, -19], BW: [24, -22], NA: [18, -22], ZA: [25, -29], LS: [28, -29], SZ: [31, -26],
  MZ: [35, -18], MW: [34, -13], MG: [47, -19], MU: [57, -20], SC: [55, -5], KM: [44, -12],
  CV: [-24, 16], RE: [56, -21], YT: [45, -13], SH: [-6, -16],
  AU: [134, -25], NZ: [173, -41], PG: [144, -6], FJ: [178, -17], NC: [165, -21], VU: [167, -16],
  SB: [160, -10], TO: [-175, -21], WS: [-172, -14], TV: [178, -8], NR: [167, 0], KI: [-168, 1],
  PW: [134, 7], FM: [150, 7], MH: [171, 7], CK: [-159, -21], NU: [-169, -19], TK: [-172, -9],
  PF: [-149, -17], WF: [-178, -13], AS: [-170, -14], GU: [144, 13], MP: [145, 15], NF: [167, -29],
  AG: [-61, 17], DM: [-61, 15], GD: [-61, 12], KN: [-62, 17], LC: [-60, 13], VC: [-61, 13],
  KY: [-80, 19], AI: [-63, 18], BL: [-62, 17], BM: [-64, 32], BQ: [-68, 12], CW: [-69, 12],
  MF: [-63, 18], MS: [-62, 16], SX: [-63, 18], TC: [-71, 21], VG: [-64, 18], VI: [-64, 18],
  AW: [-69, 12], GF: [-53, 3], GP: [-61, 16], MQ: [-61, 14], PM: [-56, 46],
  GS: [-36, -54], BV: [3, -54], TF: [69, -49], HM: [73, -53], IO: [71, -6], CC: [96, -12],
  CX: [105, -10], UM: [-176, 19], JE: [-2, 49], GG: [-2, 49], IM: [-4, 54],
  AQ: [0, -82],
};

interface MarkerPoint {
  cc: string;
  count: number;
  cx: number;
  cy: number;
  ratio: number;
}

function tierColour(ratio: number): { fill: string; glow: string; pulse: boolean } {
  if (ratio > 0.66) return { fill: '#F87171', glow: 'rgba(248,113,113,0.55)', pulse: true };
  if (ratio > 0.33) return { fill: '#F97316', glow: 'rgba(249,115,22,0.45)', pulse: false };
  return { fill: '#22D3EE', glow: 'rgba(34,211,238,0.40)', pulse: false };
}

const CELL_W = 8;
const CELL_H = 14;
const VIEWBOX_W = COLS * CELL_W;
const VIEWBOX_H = ROWS * CELL_H;

export function AsciiThreatMap({ data, sources, className }: AsciiThreatMapProps) {
  const brailleRows = useMemo(() => getBrailleMap(), []);

  const { points, total, countryCount } = useMemo(() => {
    const agg = new Map<string, number>();
    if (sources && sources.length) {
      for (const s of sources) {
        if (!s.country) continue;
        agg.set(s.country, (agg.get(s.country) ?? 0) + (s.attacks || 0));
      }
    }
    if (data && data.length) {
      for (const e of data) {
        if (!e.country_code) continue;
        agg.set(e.country_code, (agg.get(e.country_code) ?? 0) + (e.count || 0));
      }
    }
    let totalCount = 0;
    let maxC = 0;
    for (const n of agg.values()) {
      totalCount += n;
      if (n > maxC) maxC = n;
    }
    const pts: MarkerPoint[] = Array.from(agg.entries())
      .map(([cc, count]) => {
        const ll = CC_TO_LATLON[cc];
        if (!ll) return null;
        const [col, row] = lonLatToCell(ll[0], ll[1]);
        const ratio = maxC ? count / maxC : 0;
        return {
          cc,
          count,
          cx: col * CELL_W + CELL_W / 2,
          cy: row * CELL_H + CELL_H / 2,
          ratio,
        };
      })
      .filter((p): p is MarkerPoint => p !== null)
      .sort((a, b) => a.ratio - b.ratio);
    return { points: pts, total: totalCount, countryCount: agg.size };
  }, [data, sources]);

  const ariaLabel =
    total === 0
      ? 'World threat map — no threats detected'
      : `World threat map — ${total} threats across ${countryCount} countries`;

  return (
    <div
      className={`relative w-full h-full overflow-hidden rounded-xl border border-white/[0.06] bg-[#16181D] ${className ?? ''}`}
      role="img"
      aria-label={ariaLabel}
    >
      <svg
        viewBox={`0 0 ${VIEWBOX_W} ${VIEWBOX_H}`}
        preserveAspectRatio="xMidYMid meet"
        className="block w-full h-full"
        aria-hidden
      >
        <g
          fontFamily="Azeret Mono, ui-monospace, Menlo, Consolas, monospace"
          fontSize={CELL_H}
          fill="rgba(34,211,238,0.40)"
          dominantBaseline="hanging"
        >
          {/* textLength + lengthAdjust forces each row to span exactly VIEWBOX_W,
              guaranteeing per-glyph alignment with the dot grid regardless of
              the font's natural advance width. */}
          {brailleRows.map((row, i) => (
            <text
              key={i}
              x={0}
              y={i * CELL_H}
              textLength={VIEWBOX_W}
              lengthAdjust="spacingAndGlyphs"
            >
              {row}
            </text>
          ))}
        </g>

        <g>
          {points.map(({ cc, cx, cy, ratio }) => {
            const { glow } = tierColour(ratio);
            const radius = 3.5 + ratio * 5;
            return (
              <circle
                key={`halo-${cc}`}
                cx={cx}
                cy={cy}
                r={radius * 2.6}
                fill={glow}
                opacity={0.4}
              />
            );
          })}
        </g>

        <g>
          {points.map(({ cc, cx, cy, ratio, count }) => {
            const { fill, pulse } = tierColour(ratio);
            const radius = 3.5 + ratio * 5;
            return (
              <circle
                key={cc}
                cx={cx}
                cy={cy}
                r={radius}
                fill={fill}
                stroke="rgba(0,0,0,0.55)"
                strokeWidth={1}
                style={pulse ? { animation: 'aegis-threat-pulse 1.8s ease-in-out infinite' } : undefined}
              >
                <title>{`${cc}: ${count} ${count === 1 ? 'incident' : 'incidents'}`}</title>
              </circle>
            );
          })}
        </g>
      </svg>

      {total === 0 ? (
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
          <p
            className="text-[11px] uppercase tracking-[0.2em] text-cyan-400/70 font-mono"
            style={{ textShadow: '0 0 10px rgba(34,211,238,0.4)' }}
          >
            {'// NO THREAT DATA'}
          </p>
        </div>
      ) : (
        <div className="absolute left-3 top-3 inline-flex items-center gap-3 rounded-md border border-cyan-500/30 bg-[#16181D]/80 backdrop-blur px-2.5 py-1 text-[10px] font-mono uppercase tracking-wider text-cyan-100/80">
          <span>
            <span className="text-cyan-300">{countryCount}</span> countries
          </span>
          <span className="opacity-40">·</span>
          <span>
            <span className="text-cyan-300">{total.toLocaleString()}</span> attacks
          </span>
        </div>
      )}

      {total > 0 && (
        <div className="absolute right-3 bottom-3 rounded-md border border-cyan-500/30 bg-[#16181D]/85 backdrop-blur px-2.5 py-1.5 text-[10px] font-mono uppercase tracking-wider min-w-[140px]">
          <div className="text-cyan-300/80 mb-1.5 pb-1 border-b border-cyan-500/20 flex items-center justify-between gap-3">
            <span>top sources</span>
            <span className="text-cyan-100/50 tabular-nums">{Math.min(5, points.length)}</span>
          </div>
          <div className="space-y-1">
            {points
              .slice()
              .reverse()
              .slice(0, 5)
              .map(({ cc, count, ratio }) => {
                const { fill } = tierColour(ratio);
                return (
                  <div key={cc} className="flex items-center justify-between gap-3 text-cyan-100/80">
                    <span className="flex items-center gap-2">
                      <span
                        className="inline-block w-1.5 h-1.5 rounded-full"
                        style={{ backgroundColor: fill, boxShadow: `0 0 6px ${fill}` }}
                      />
                      <span>{cc}</span>
                    </span>
                    <span className="tabular-nums text-cyan-100/95">{count.toLocaleString()}</span>
                  </div>
                );
              })}
          </div>
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
