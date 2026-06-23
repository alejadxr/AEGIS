'use client';

/**
 * AsciiThreatMap — retro CRT-style world map (v1.6.3+).
 *
 * Replaces the SVG `react-simple-maps` map with a pure ASCII world rendered
 * in a monospace `<pre>` block. Threat markers are absolutely-positioned
 * coloured glyphs at the (col, row) coordinates of each country's centroid.
 *
 * Why: cleaner load (no SVG path data, no 50 KB world topojson), retro
 * aesthetic that matches the rest of the AEGIS dashboard, and far cheaper
 * to render at scale.
 *
 * Drop-in replacement for the GlobalThreatMap export — same prop contract.
 */

import { useEffect, useMemo, useRef, useState } from 'react';

export interface ThreatMapEntry {
  country: string;
  country_code: string;
  count: number;
}

export interface AsciiThreatMapProps {
  data: ThreatMapEntry[];
}

// ASCII world map (84 columns × 22 rows). Each country has a known (col, row)
// position. Continents are drawn with `.,;:'~` for land and ` ` for ocean.
// Cardinal references: top-left ≈ (col 4-12, row 1-3) = Alaska/Greenland;
// bottom-right ≈ (col 70-78, row 16-19) = Oceania.
const ASCII_MAP: readonly string[] = [
  '                                                                                    ',
  '          ,_      ,,,,,,,,,,                       __                                ',
  '       ,;~  ~~~,,,        ~~,,            ,,~~,,~~~  ~~,_      ~~,    ~~_  _,        ',
  '     ,~              ~~~,_   ~,_       ,~~              ~,,_  ,~ ~~~~~  ~~ ~ ,_      ',
  '   ,~                    ~~_  ~~~~~~~~~                    ~~~~          ~~_  ~_     ',
  '   ~                       ~_          ,;~~~,~~~      _,,~~       ___       ~_  ~,   ',
  '    ~,                      ~          ;     `   ,~~~~,_  ~~,_,~~~   ~~~~_    `~_~_  ',
  '     ~,                      ~,       ;          `       ~,    ;          ~~,    ~,, ',
  '      ~~_                     ~       ~                   ~_   ~,            ~,    ~ ',
  '        ~_                    ~,       ~,                  ~_   ~,    ,~_      ~,    ',
  '         ~                     ~,        ~,                 ~_   ~,_,~  ~_      ~,_  ',
  '          ~,                    ~,         ~,                ~,   ~     ~_       ~~~ ',
  '            ~_                   ~,         ~,                ~,   ~,    ~_       ~  ',
  '             ~,                   ~_         ~,                ~_   ~,   _,~,       ~',
  '              ~,                    ~,        ~,                ~_   ~,_,~ ~,       ~',
  '              ~~,                    ~,        ~,                ~~_      ~,_       ~',
  '               ~~,                    ~,       ~~_                  ~~,_   ~,~~,    ~',
  '                  ~,                  ~~_       ~~,_                    ~~~,~~~     ~',
  '                    ~~,                 ~~_       ~~~,                                ',
  '                       ~~~_                ~~,_      ~~~,_                            ',
  '                            ~~~_              ~~~_       ~~~_                        ',
  '                                                                                    ',
];

// Country centroids in (col, row) of the ASCII map above. Rows are 0-indexed.
// Coordinates derived empirically by overlaying centroid lat/lng onto an 84×22
// canvas. Coverage: every ISO-3166 code we render — same set as v1.6.2 (~249).
// Missing codes fall through to a discreet bucket at (col 1, row 21) so they
// still get counted in the total badge even if not pinned to a continent.
const CC_POS: Readonly<Record<string, [number, number]>> = {
  // North America
  US: [16, 6], CA: [18, 3], MX: [16, 9], CU: [22, 8], BS: [22, 7], GT: [19, 9], BZ: [19, 9],
  HN: [20, 9], NI: [20, 10], CR: [20, 10], PA: [22, 10], DO: [24, 8], HT: [23, 8], JM: [22, 8],
  PR: [25, 8], TT: [26, 10], BB: [26, 9], GL: [30, 2],
  // South America
  CO: [24, 11], VE: [25, 10], GY: [26, 10], SR: [27, 10], BR: [29, 13], PE: [24, 13],
  EC: [23, 11], BO: [26, 14], CL: [25, 17], AR: [27, 17], PY: [27, 15], UY: [28, 16],
  FK: [27, 19],
  // Europe
  GB: [40, 4], IE: [39, 4], FR: [42, 6], ES: [40, 7], PT: [39, 7], IT: [44, 7], DE: [44, 5],
  NL: [43, 5], BE: [43, 5], CH: [44, 6], AT: [45, 6], PL: [46, 5], CZ: [45, 6], SK: [46, 6],
  HU: [46, 7], RO: [47, 7], BG: [48, 7], GR: [47, 8], TR: [50, 8], NO: [44, 3], SE: [45, 3],
  FI: [47, 3], DK: [44, 4], IS: [38, 3], EE: [47, 4], LV: [47, 4], LT: [47, 5], BY: [48, 5],
  UA: [49, 6], MD: [49, 7], RS: [46, 7], HR: [45, 7], BA: [46, 7], SI: [45, 7], MK: [47, 8],
  AL: [46, 8], ME: [46, 8], LU: [43, 6], MT: [44, 8], CY: [50, 9], LI: [44, 6], MC: [43, 6],
  SM: [44, 7], VA: [44, 7], AD: [42, 7], GI: [40, 8], FO: [40, 3], AX: [46, 3],
  // Russia (spans Europe + Asia)
  RU: [60, 4],
  // Asia
  KZ: [56, 6], UZ: [55, 7], TM: [54, 7], KG: [58, 6], TJ: [57, 7], AF: [55, 8], PK: [56, 9],
  IN: [58, 10], NP: [60, 9], BT: [61, 9], BD: [61, 10], LK: [59, 12], MV: [58, 12],
  CN: [64, 7], MN: [64, 5], JP: [73, 7], KR: [70, 7], KP: [70, 6], TW: [69, 9], HK: [68, 9],
  MO: [68, 9], VN: [66, 10], LA: [66, 10], TH: [65, 10], KH: [66, 11], MM: [63, 10],
  MY: [66, 12], SG: [65, 12], ID: [69, 13], BN: [68, 12], PH: [70, 11], TL: [71, 13],
  SA: [52, 9], YE: [53, 11], OM: [55, 10], AE: [54, 10], QA: [54, 10], BH: [54, 9],
  KW: [53, 9], JO: [51, 9], IL: [51, 9], LB: [51, 9], SY: [52, 8], IQ: [53, 8], IR: [54, 8],
  GE: [51, 7], AM: [51, 7], AZ: [52, 7], PS: [51, 9],
  // Africa
  EG: [49, 9], LY: [46, 9], DZ: [42, 9], TN: [44, 9], MA: [41, 9], EH: [40, 10],
  MR: [40, 11], ML: [42, 11], SN: [39, 11], GM: [39, 11], GN: [40, 12], GW: [39, 11],
  SL: [40, 12], LR: [40, 12], CI: [41, 12], GH: [42, 12], TG: [43, 12], BJ: [43, 12],
  NE: [44, 11], BF: [42, 11], NG: [44, 12], CM: [45, 12], CF: [46, 12], TD: [46, 11],
  SD: [48, 11], SS: [48, 12], ER: [50, 11], ET: [50, 12], DJ: [50, 11], SO: [52, 12],
  KE: [50, 13], UG: [49, 13], RW: [49, 13], BI: [49, 13], TZ: [50, 14], CD: [47, 13],
  CG: [46, 13], GA: [45, 13], GQ: [44, 13], ST: [44, 13], AO: [46, 14], ZM: [48, 15],
  ZW: [48, 15], BW: [48, 16], NA: [46, 16], ZA: [47, 17], LS: [48, 17], SZ: [48, 17],
  MZ: [50, 15], MW: [50, 15], MG: [52, 16], MU: [54, 16], SC: [54, 13], KM: [52, 14],
  CV: [37, 11], RE: [54, 16], YT: [53, 15], SH: [44, 17],
  // Oceania
  AU: [73, 16], NZ: [80, 18], PG: [72, 13], FJ: [82, 15], NC: [78, 15], VU: [78, 15],
  SB: [76, 14], TO: [83, 16], WS: [82, 15], TV: [78, 14], NR: [76, 13], KI: [78, 13],
  PW: [70, 12], FM: [74, 13], MH: [78, 13], CK: [82, 16], NU: [82, 16], TK: [82, 14],
  PF: [82, 17], WF: [80, 15], AS: [82, 15], GU: [73, 12], MP: [73, 12], NF: [78, 16],
  // Caribbean / smaller
  AG: [26, 9], DM: [26, 9], GD: [26, 9], KN: [26, 9], LC: [26, 9], VC: [26, 9],
  KY: [22, 8], AI: [26, 9], BL: [26, 9], BM: [25, 6], BQ: [25, 10], CW: [25, 10],
  MF: [26, 9], MS: [26, 9], SX: [26, 9], TC: [23, 8], VG: [26, 8], VI: [26, 8],
  AW: [25, 10], GF: [28, 11], GP: [26, 9], MQ: [26, 9], PM: [25, 5],
  // Other / oceans
  GS: [30, 19], BV: [38, 19], TF: [56, 19], HM: [62, 19], IO: [58, 12], CC: [66, 13],
  CX: [69, 13], NF_X: [78, 16], UM: [80, 12], JE: [40, 5], GG: [40, 5], IM: [40, 4],
  // Antarctica region
  AQ: [42, 21],
};

function severityColor(count: number, max: number): string {
  if (count === 0) return 'transparent';
  const ratio = count / max;
  if (ratio > 0.66) return 'var(--danger, #ef4444)';
  if (ratio > 0.33) return 'var(--brand-accent, #f97316)';
  return 'var(--brand, #22d3ee)';
}

export function AsciiThreatMap({ data }: AsciiThreatMapProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [cellW, setCellW] = useState(7);
  const [cellH, setCellH] = useState(14);

  // Measure rendered character cell size so the markers track the <pre>.
  useEffect(() => {
    const el = containerRef.current?.querySelector('pre');
    if (!el) return;
    // Sample a single character box by measuring the first text node.
    const span = document.createElement('span');
    span.textContent = 'M';
    span.style.cssText = 'visibility:hidden;position:absolute;';
    el.appendChild(span);
    const r = span.getBoundingClientRect();
    if (r.width) setCellW(r.width);
    if (r.height) setCellH(r.height);
    span.remove();
  }, []);

  const { points, total, maxCount, byCountry } = useMemo(() => {
    const agg = new Map<string, number>();
    for (const entry of data) {
      if (!entry.country_code) continue;
      agg.set(entry.country_code, (agg.get(entry.country_code) || 0) + entry.count);
    }
    let totalCount = 0;
    let maxC = 0;
    for (const n of agg.values()) {
      totalCount += n;
      if (n > maxC) maxC = n;
    }
    const pts = Array.from(agg.entries())
      .map(([cc, count]) => {
        const pos = CC_POS[cc] || [1, 21];
        return { cc, count, col: pos[0], row: pos[1] };
      })
      .sort((a, b) => a.count - b.count); // smaller first so big dots render on top
    return { points: pts, total: totalCount, maxCount: maxC, byCountry: agg };
  }, [data]);

  if (total === 0) {
    return (
      <div
        ref={containerRef}
        className="relative w-full h-full overflow-hidden bg-black/30 border border-border/40 rounded-lg p-4"
        role="img"
        aria-label="World threat map — no threats detected"
      >
        <pre
          className="text-[10px] leading-tight text-cyan-500/35 select-none m-0"
          style={{ fontFamily: 'Azeret Mono, ui-monospace, monospace', letterSpacing: '0.05em' }}
          aria-hidden
        >
          {ASCII_MAP.join('\n')}
        </pre>
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
          <p
            className="text-[11px] uppercase tracking-[0.2em] text-cyan-400/70 font-mono"
            style={{ textShadow: '0 0 8px rgba(34,211,238,0.4)' }}
          >
            {'// NO THREAT DATA'}
          </p>
        </div>
        <div
          className="absolute inset-0 pointer-events-none opacity-20"
          style={{
            background:
              'repeating-linear-gradient(0deg, rgba(34,211,238,0.10) 0px, rgba(34,211,238,0.10) 1px, transparent 1px, transparent 3px)',
          }}
        />
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="relative w-full h-full overflow-hidden bg-black/30 border border-border/40 rounded-lg p-4"
      role="img"
      aria-label={`World threat map — ${total} threats across ${byCountry.size} countries`}
    >
      {/* The ASCII base map (decorative — markers carry the real data) */}
      <pre
        className="text-[10px] leading-tight text-cyan-500/35 select-none m-0"
        style={{ fontFamily: 'Azeret Mono, ui-monospace, monospace', letterSpacing: '0.05em' }}
        aria-hidden
      >
        {ASCII_MAP.join('\n')}
      </pre>

      {/* Threat markers — absolutely positioned over the <pre> using measured cell size */}
      <div className="absolute inset-4 pointer-events-none" aria-hidden>
        {points.map(({ cc, count, col, row }) => {
          const color = severityColor(count, maxCount);
          // Scale dot 6-14px based on count ratio
          const ratio = count / maxCount;
          const size = Math.max(6, Math.round(6 + ratio * 8));
          return (
            <div
              key={cc}
              className="absolute"
              style={{
                left: `${col * cellW}px`,
                top: `${row * cellH}px`,
                width: `${size}px`,
                height: `${size}px`,
                marginLeft: `-${size / 2}px`,
                marginTop: `-${size / 2}px`,
                borderRadius: '50%',
                background: color,
                boxShadow: `0 0 ${size * 1.5}px ${color}, 0 0 ${size * 2.5}px ${color}`,
                animation: ratio > 0.66 ? 'aegis-threat-pulse 1.4s ease-in-out infinite' : undefined,
              }}
              title={`${cc}: ${count} ${count === 1 ? 'incident' : 'incidents'}`}
            />
          );
        })}
      </div>

      {/* Per-country count overlay (bottom-right legend) */}
      <div
        className="absolute right-3 bottom-3 max-h-[40%] overflow-y-auto bg-black/40 border border-cyan-500/30 rounded px-2 py-1 text-[9px] font-mono uppercase tracking-wider pointer-events-auto"
        style={{ minWidth: '90px' }}
      >
        <div className="text-cyan-300/80 mb-1 border-b border-cyan-500/20 pb-1">
          {byCountry.size} CN · {total} ATK
        </div>
        {points
          .slice()
          .reverse()
          .slice(0, 8)
          .map(({ cc, count }) => (
            <div key={cc} className="flex items-center justify-between gap-2 text-cyan-100/70">
              <span>{cc}</span>
              <span className="tabular-nums">{count}</span>
            </div>
          ))}
      </div>

      {/* CRT scanline overlay */}
      <div
        className="absolute inset-0 pointer-events-none opacity-20"
        style={{
          background:
            'repeating-linear-gradient(0deg, rgba(34,211,238,0.10) 0px, rgba(34,211,238,0.10) 1px, transparent 1px, transparent 3px)',
        }}
      />

      <style jsx>{`
        @keyframes aegis-threat-pulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.6; transform: scale(1.4); }
        }
      `}</style>
    </div>
  );
}

// Compatibility alias — drop-in for the old SVG-based component.
export { AsciiThreatMap as GlobalThreatMap };
