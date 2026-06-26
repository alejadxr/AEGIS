'use client';

import { useMemo } from 'react';

// ============================================================================
// Public API (preserved — do not break callers)
// ============================================================================

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

// ============================================================================
// Projection grid — mapscii-style 2x4 Braille cells.
// 240x120 effective pixels -> 120 cols x 30 rows of Braille glyphs (2:1).
// ============================================================================

const PX_W = 240;
const PX_H = 120;
const COLS = PX_W / 2; // 120 braille cells wide
const ROWS = PX_H / 4; // 30  braille cells tall

// Equirectangular projection (lon: -180..+180 -> 0..PX_W; lat: +90..-90 -> 0..PX_H).
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

// ============================================================================
// Hand-traced coastline polygons.
// Each polygon is rasterised independently — overlap is harmless (a pixel is
// LAND if ANY polygon contains it). This lets us add island detail (Sumatra,
// Madagascar, UK, NZ, ...) without surgery on the main continent outlines.
// ============================================================================

const CONTINENTS: Polygon[] = [
  // ── NORTH AMERICA (Alaska -> Pacific -> Mexico -> Central America ->
  //    Gulf -> Florida -> Eastern Seaboard -> Maritimes -> Hudson -> Arctic)
  [
    [-168, 66], [-162, 70], [-158, 71], [-141, 70], [-141, 60], [-138, 59],
    [-135, 57], [-130, 54], [-126, 50], [-124, 48], [-124, 43], [-123, 39],
    [-122, 37], [-120, 35], [-117, 33], [-115, 32], [-114, 30], [-112, 26],
    [-110, 23], [-106, 22], [-101, 18], [-97, 16], [-94, 16], [-91, 14],
    [-87, 13], [-84, 10], [-81, 8], [-78, 8], [-77, 10], [-83, 13],
    [-87, 16], [-88, 18], [-88, 21], [-90, 21], [-91, 19], [-95, 19],
    [-97, 22], [-97, 26], [-94, 29], [-90, 30], [-87, 30], [-84, 30],
    [-83, 29], [-82, 27], [-81, 25], [-80, 25], [-80, 27], [-81, 31],
    [-79, 33], [-77, 34], [-75, 38], [-74, 39], [-72, 41], [-70, 43],
    [-67, 45], [-65, 45], [-60, 46], [-55, 48], [-53, 50], [-56, 52],
    [-60, 54], [-63, 57], [-67, 60], [-69, 62], [-77, 62], [-79, 60],
    [-83, 58], [-88, 58], [-92, 57], [-95, 60], [-94, 64], [-95, 68],
    [-105, 70], [-115, 70], [-125, 71], [-135, 70], [-148, 70], [-156, 71],
    [-168, 66],
  ],

  // ── GREENLAND
  [
    [-50, 60], [-45, 60], [-38, 64], [-30, 67], [-22, 70], [-22, 75],
    [-25, 78], [-30, 81], [-45, 83], [-55, 83], [-62, 81], [-65, 78],
    [-58, 73], [-52, 68], [-50, 60],
  ],

  // ── ICELAND
  [
    [-24, 64], [-21, 66], [-14, 66], [-13, 64], [-19, 63], [-23, 63],
    [-24, 64],
  ],

  // ── CUBA
  [
    [-84, 22], [-78, 22], [-74, 20], [-77, 21], [-83, 23], [-84, 22],
  ],

  // ── HISPANIOLA (DR + Haiti)
  [
    [-74, 19], [-68, 19], [-68, 18], [-74, 18], [-74, 19],
  ],

  // ── SOUTH AMERICA
  [
    [-78, 12], [-72, 12], [-62, 11], [-55, 6], [-50, 4], [-44, 0],
    [-39, -4], [-35, -8], [-37, -13], [-39, -18], [-42, -22], [-48, -28],
    [-55, -33], [-60, -39], [-65, -44], [-68, -49], [-72, -54], [-70, -55],
    [-67, -53], [-66, -48], [-71, -42], [-72, -36], [-71, -28], [-71, -20],
    [-73, -16], [-77, -12], [-79, -8], [-80, -4], [-80, 0], [-78, 4],
    [-77, 8], [-78, 12],
  ],

  // ── AFRICA (mainland)
  [
    [-17, 21], [-13, 27], [-7, 33], [0, 35], [10, 32], [20, 31], [27, 31],
    [33, 31], [35, 27], [37, 22], [39, 17], [42, 13], [46, 12], [49, 12],
    [51, 11], [50, 8], [47, 5], [44, 4], [42, 0], [40, -5], [40, -10],
    [40, -16], [38, -22], [33, -27], [28, -33], [22, -34], [18, -34],
    [15, -30], [13, -25], [12, -19], [12, -13], [12, -7], [9, -2],
    [9, 3], [6, 4], [-2, 5], [-7, 5], [-13, 9], [-17, 14], [-17, 21],
  ],

  // ── MADAGASCAR
  [
    [44, -12], [47, -13], [50, -17], [50, -22], [47, -25], [44, -22],
    [44, -16], [43, -13], [44, -12],
  ],

  // ── EUROPE: IBERIA
  [
    [-10, 36], [-9, 39], [-9, 43], [-3, 43], [3, 43], [3, 38], [-5, 36],
    [-10, 36],
  ],

  // ── EUROPE: WESTERN MAINLAND (France/Benelux/Germany/Denmark)
  [
    [-5, 43], [-1, 45], [-4, 48], [-1, 49], [3, 51], [6, 53], [9, 54],
    [11, 54], [12, 56], [10, 57], [9, 56], [9, 54], [6, 51], [5, 50],
    [4, 48], [6, 46], [8, 45], [6, 44], [-1, 43], [-5, 43],
  ],

  // ── EUROPE: ITALY (boot)
  [
    [7, 44], [10, 45], [13, 46], [13, 44], [15, 41], [17, 41], [18, 40],
    [17, 38], [15, 39], [14, 38], [11, 41], [10, 42], [7, 44],
  ],

  // ── EUROPE: BALKANS / GREECE
  [
    [13, 46], [17, 47], [22, 46], [27, 44], [28, 42], [25, 38], [22, 37],
    [21, 38], [19, 40], [17, 42], [14, 45], [13, 46],
  ],

  // ── EUROPE: SCANDINAVIA
  [
    [5, 58], [8, 60], [12, 65], [17, 68], [21, 70], [25, 71], [28, 70],
    [25, 67], [22, 63], [19, 60], [18, 58], [14, 56], [11, 55], [8, 56],
    [5, 58],
  ],

  // ── EUROPE: EASTERN PLAIN + WESTERN RUSSIA
  [
    [12, 50], [18, 54], [25, 56], [32, 58], [40, 60], [48, 61], [55, 60],
    [55, 54], [50, 48], [42, 46], [33, 46], [27, 46], [22, 47], [16, 49],
    [12, 50],
  ],

  // ── ASIA: SIBERIAN ARCTIC BELT
  [
    [55, 50], [60, 55], [70, 60], [80, 65], [90, 72], [100, 73], [110, 73],
    [120, 71], [130, 70], [140, 68], [150, 65], [160, 60], [165, 60],
    [170, 64], [180, 66], [180, 70], [160, 72], [140, 73], [120, 74],
    [100, 75], [80, 70], [70, 67], [60, 60], [55, 50],
  ],

  // ── ASIA: SIBERIAN SOUTH BELT (Mongolia / Russian Far East)
  [
    [55, 50], [70, 50], [85, 50], [100, 48], [115, 48], [128, 50],
    [135, 50], [142, 50], [148, 53], [150, 55], [145, 56], [140, 55],
    [130, 53], [120, 53], [110, 52], [100, 50], [90, 50], [80, 50],
    [70, 52], [60, 52], [55, 50],
  ],

  // ── ASIA: CHINA / EAST ASIA SEABOARD
  [
    [75, 38], [82, 42], [90, 45], [100, 47], [115, 47], [125, 45],
    [128, 42], [127, 38], [125, 35], [122, 32], [121, 30], [119, 26],
    [117, 23], [114, 22], [110, 22], [108, 21], [105, 22], [101, 26],
    [95, 28], [90, 30], [85, 34], [80, 36], [75, 38],
  ],

  // ── KOREA
  [
    [126, 38], [129, 37], [129, 35], [127, 34], [125, 37], [126, 38],
  ],

  // ── JAPAN — HONSHU
  [
    [131, 33], [134, 34], [137, 35], [140, 38], [141, 40], [140, 41],
    [137, 38], [134, 35], [131, 33],
  ],

  // ── JAPAN — HOKKAIDO
  [
    [140, 42], [143, 42], [145, 44], [142, 45], [140, 44], [140, 42],
  ],

  // ── JAPAN — KYUSHU + SHIKOKU
  [
    [130, 31], [131, 32], [134, 33], [133, 34], [131, 33], [130, 31],
  ],

  // ── TAIWAN
  [
    [120, 22], [121, 22], [122, 25], [121, 25], [120, 22],
  ],

  // ── INDIA (subcontinent)
  [
    [68, 24], [72, 24], [76, 23], [80, 22], [85, 22], [88, 22], [88, 20],
    [85, 18], [82, 16], [80, 12], [78, 9], [77, 8], [76, 10], [73, 16],
    [72, 20], [70, 22], [68, 24],
  ],

  // ── SRI LANKA
  [
    [80, 6], [82, 7], [82, 9], [80, 9], [80, 6],
  ],

  // ── SE ASIA MAINLAND (Myanmar/Thailand/Cambodia/Vietnam/Malaysia)
  [
    [92, 22], [97, 22], [99, 20], [102, 21], [105, 22], [108, 21],
    [108, 17], [107, 14], [105, 11], [104, 11], [102, 13], [102, 8],
    [102, 5], [104, 2], [102, 2], [100, 5], [99, 9], [98, 13], [97, 16],
    [95, 20], [93, 22], [92, 22],
  ],

  // ── SUMATRA
  [
    [95, 5], [99, 4], [103, 0], [105, -3], [102, -5], [99, -3], [96, 1],
    [95, 5],
  ],

  // ── JAVA + BALI (slim east-west sliver)
  [
    [105, -6], [110, -7], [114, -7], [115, -8], [108, -8], [105, -7],
    [105, -6],
  ],

  // ── BORNEO
  [
    [109, 5], [115, 6], [119, 3], [119, -2], [114, -4], [109, -1], [109, 5],
  ],

  // ── SULAWESI
  [
    [119, 1], [122, 2], [125, 0], [124, -3], [121, -5], [120, -2], [119, 1],
  ],

  // ── NEW GUINEA
  [
    [131, -1], [138, -2], [144, -4], [150, -7], [148, -10], [142, -10],
    [136, -9], [132, -7], [131, -1],
  ],

  // ── PHILIPPINES (single blob)
  [
    [120, 12], [122, 8], [125, 7], [126, 10], [125, 14], [122, 16],
    [120, 14], [120, 12],
  ],

  // ── AUSTRALIA
  [
    [113, -22], [115, -20], [118, -19], [125, -14], [132, -11], [137, -11],
    [142, -11], [145, -14], [149, -20], [153, -25], [152, -30], [149, -34],
    [144, -38], [140, -37], [136, -35], [132, -32], [126, -32], [120, -34],
    [115, -34], [114, -28], [113, -22],
  ],

  // ── NEW ZEALAND — NORTH ISLAND
  [
    [173, -35], [177, -37], [177, -39], [173, -39], [173, -35],
  ],

  // ── NEW ZEALAND — SOUTH ISLAND
  [
    [167, -41], [171, -41], [174, -45], [170, -46], [167, -44], [167, -41],
  ],

  // ── ARABIAN PENINSULA
  [
    [35, 30], [40, 30], [43, 29], [47, 30], [50, 28], [51, 24], [55, 22],
    [56, 18], [52, 14], [48, 12], [43, 13], [43, 18], [40, 22], [38, 25],
    [35, 28], [35, 30],
  ],

  // ── MIDDLE EAST (Turkey/Caucasus/Iran)
  [
    [27, 37], [33, 40], [40, 41], [45, 41], [50, 40], [55, 38], [60, 35],
    [62, 30], [60, 27], [55, 27], [50, 28], [47, 30], [42, 33], [38, 35],
    [33, 35], [30, 36], [27, 37],
  ],

  // ── BRITAIN (England + Scotland + Wales)
  [
    [-5, 50], [-3, 51], [0, 51], [2, 53], [0, 55], [-2, 57], [-5, 58],
    [-3, 59], [-6, 58], [-6, 55], [-5, 54], [-5, 50],
  ],

  // ── IRELAND
  [
    [-10, 52], [-7, 54], [-6, 55], [-7, 52], [-10, 52],
  ],

  // ── CENTRAL ASIA infill (Kazakhstan/Uzbek/Turkmen) — filler between
  //    Caspian and China block so Central Asia isn't a hole.
  [
    [48, 50], [55, 53], [62, 52], [70, 50], [78, 48], [82, 46], [82, 42],
    [75, 42], [68, 42], [60, 40], [55, 42], [50, 45], [48, 50],
  ],
];

// ============================================================================
// Polygon -> pixel grid -> Braille text rows
// ============================================================================

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
// Each Braille glyph encodes a 2x4 dot matrix.  DOT_BITS[row][col] is the
// bit set for the dot at that sub-pixel position.
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

// Module-scope cache: the world map never changes, so we rasterise once.
let _brailleMap: string[] | null = null;
function getBrailleMap(): string[] {
  if (!_brailleMap) _brailleMap = pixelGridToBraille(rasterize());
  return _brailleMap;
}

// ============================================================================
// ISO-2 -> approximate (lon, lat) centroid for marker placement.
// Preserved verbatim from the previous implementation (240+ codes).
// ============================================================================

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

// ============================================================================
// Marker tier colours
//   low  (<33% of peak)  -> cyan,   static
//   mid  (33-66%)        -> orange, static
//   high (>66%)          -> red,    pulsing
// ============================================================================

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

// ============================================================================
// SVG layout constants — cells deliberately small so the map sits gracefully
// inside a dashboard card without overpowering the surrounding content.
// CELL_H = 2 * CELL_W keeps the 2:1 cartographic aspect ratio for the world.
// ============================================================================

const CELL_W = 6;
const CELL_H = 12;
const VIEWBOX_W = COLS * CELL_W; // 720
const VIEWBOX_H = ROWS * CELL_H; // 360

// ============================================================================
// Component
// ============================================================================

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

  // Top-5 markers (highest count first) — used both for the SVG label overlay
  // and the bottom-right legend list.
  const topFive = useMemo(() => points.slice().reverse().slice(0, 5), [points]);

  // Build label geometry: anchor on the right of the dot by default; if the
  // dot sits in the right ~18% of the canvas, flip the label to the left so
  // it doesn't overflow.  Deterministic — no randomness, SSR-safe.
  const labels = useMemo(
    () =>
      topFive.map((p) => {
        const flipX = p.cx > VIEWBOX_W * 0.82;
        const flipY = p.cy < 18;
        const offsetX = 7;
        const offsetY = flipY ? 12 : -6;
        const lx = flipX ? p.cx - offsetX : p.cx + offsetX;
        const ly = p.cy + offsetY;
        return {
          cc: p.cc,
          cx: p.cx,
          cy: p.cy,
          lx,
          ly,
          textAnchor: flipX ? ('end' as const) : ('start' as const),
        };
      }),
    [topFive],
  );

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
        {/* Braille continent layer — context, ambient */}
        <g
          fontFamily="Azeret Mono, ui-monospace, Menlo, Consolas, monospace"
          fontSize={CELL_H}
          fill="rgba(34,211,238,0.30)"
          dominantBaseline="hanging"
        >
          {/* textLength + lengthAdjust forces each row to span exactly VIEWBOX_W,
              keeping per-glyph alignment with the dot grid regardless of the
              font's natural advance width. */}
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

        {/* Soft halos behind dots */}
        <g>
          {points.map(({ cc, cx, cy, ratio }) => {
            const { glow } = tierColour(ratio);
            const radius = 2.2 + ratio * 3.4;
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

        {/* Attack dots */}
        <g>
          {points.map(({ cc, cx, cy, ratio, count }) => {
            const { fill, pulse } = tierColour(ratio);
            const radius = 2.2 + ratio * 3.4;
            return (
              <circle
                key={cc}
                cx={cx}
                cy={cy}
                r={radius}
                fill={fill}
                stroke="rgba(0,0,0,0.55)"
                strokeWidth={0.8}
                style={pulse ? { animation: 'aegis-threat-pulse 1.8s ease-in-out infinite' } : undefined}
              >
                <title>{`${cc}: ${count} ${count === 1 ? 'incident' : 'incidents'}`}</title>
              </circle>
            );
          })}
        </g>

        {/* Top-5 labels with thin leader lines */}
        <g>
          {labels.map(({ cc, cx, cy, lx, ly, textAnchor }) => (
            <g key={`label-${cc}`}>
              <line
                x1={cx}
                y1={cy}
                x2={lx}
                y2={ly + 3}
                stroke="rgba(245,245,245,0.35)"
                strokeWidth={0.5}
              />
              <text
                x={lx}
                y={ly}
                textAnchor={textAnchor}
                dominantBaseline="hanging"
                fontFamily="Azeret Mono, ui-monospace, Menlo, Consolas, monospace"
                fontSize={9}
                fontWeight={600}
                className="fill-foreground/70"
                stroke="#16181D"
                strokeWidth={2.5}
                paintOrder="stroke"
                style={{ paintOrder: 'stroke' }}
              >
                {cc}
              </text>
            </g>
          ))}
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
            {topFive.map(({ cc, count, ratio }) => {
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
