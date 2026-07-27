#!/usr/bin/env node
/**
 * build-vector-map.mjs — Build-time vector map generator.
 *
 * Generates src/lib/geo/vector-map.generated.ts: static pre-projected SVG vector
 * path geometry for the world's landmasses and individual country borders.
 *
 * Runs automatically at build time or manually via `node scripts/build-vector-map.mjs`.
 */

import { writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const outputPath = join(__dirname, '../src/lib/geo/vector-map.generated.ts');

let d3Geo, topojsonClient, landTopology50m;
try {
  d3Geo = await import('d3-geo');
  topojsonClient = await import('topojson-client');
  const mod = await import('world-atlas/countries-50m.json', { with: { type: 'json' } });
  landTopology50m = mod.default;
} catch (err) {
  if (existsSync(outputPath)) {
    console.log(`Using existing pre-generated vector-map.generated.ts (world-atlas not in node_modules).`);
    process.exit(0);
  } else {
    console.error(`Error: world-atlas devDependency is required to generate vector-map.generated.ts.`, err);
    process.exit(1);
  }
}

const { geoPath, geoEquirectangular } = d3Geo;
const { feature } = topojsonClient;

const MAP_W = 1000;
const MAP_H = 500;

// Equirectangular projection matching the existing projectLonLat linear mapping exactly
const projection = geoEquirectangular().fitSize([MAP_W, MAP_H], { type: 'Sphere' });
const pathGenerator = geoPath().projection(projection);

// Numeric ISO-3166-1 to Alpha-2 Code Mapping
const NUMERIC_TO_ALPHA2 = {
  '004': 'AF', '008': 'AL', '012': 'DZ', '016': 'AS', '020': 'AD', '024': 'AO', '028': 'AI', '010': 'AQ',
  '031': 'AZ', '032': 'AR', '036': 'AU', '040': 'AT', '044': 'BS', '048': 'BH', '050': 'BD', '051': 'AM',
  '052': 'BB', '056': 'BE', '060': 'BM', '064': 'BT', '068': 'BO', '070': 'BA', '072': 'BW', '074': 'BV',
  '076': 'BR', '084': 'BZ', '086': 'IO', '090': 'SB', '092': 'VG', '096': 'BN', '100': 'BG', '104': 'MM',
  '108': 'BI', '112': 'BY', '116': 'KH', '120': 'CM', '124': 'CA', '132': 'CV', '136': 'KY', '140': 'CF',
  '144': 'LK', '148': 'TD', '152': 'CL', '156': 'CN', '158': 'TW', '162': 'CX', '166': 'CC', '170': 'CO',
  '174': 'KM', '175': 'YT', '178': 'CG', '180': 'CD', '184': 'CK', '188': 'CR', '191': 'HR', '192': 'CU',
  '196': 'CY', '203': 'CZ', '204': 'BJ', '208': 'DK', '212': 'DM', '214': 'DO', '218': 'EC', '222': 'SV',
  '226': 'GQ', '231': 'ET', '232': 'ER', '233': 'EE', '234': 'FO', '238': 'FK', '239': 'GS', '242': 'FJ',
  '246': 'FI', '248': 'AX', '250': 'FR', '254': 'GF', '258': 'PF', '260': 'TF', '262': 'DJ', '266': 'GA',
  '268': 'GE', '270': 'GM', '275': 'PS', '276': 'DE', '288': 'GH', '292': 'GI', '296': 'KI', '300': 'GR',
  '304': 'GL', '308': 'GD', '312': 'GP', '316': 'GU', '320': 'GT', '324': 'GN', '328': 'GY', '332': 'HT',
  '334': 'HM', '336': 'VA', '340': 'HN', '344': 'HK', '348': 'HU', '352': 'IS', '356': 'IN', '360': 'ID',
  '364': 'IR', '368': 'IQ', '372': 'IE', '376': 'IL', '380': 'IT', '384': 'CI', '388': 'JM', '392': 'JP',
  '398': 'KZ', '400': 'JO', '404': 'KE', '408': 'KP', '410': 'KR', '414': 'KW', '417': 'KG', '418': 'LA',
  '422': 'LB', '426': 'LS', '428': 'LV', '430': 'LR', '434': 'LY', '438': 'LI', '440': 'LT', '442': 'LU',
  '446': 'MO', '450': 'MG', '454': 'MW', '458': 'MY', '462': 'MV', '466': 'ML', '470': 'MT', '474': 'MQ',
  '478': 'MR', '480': 'MU', '484': 'MX', '492': 'MC', '496': 'MN', '498': 'MD', '499': 'ME', '500': 'MS',
  '504': 'MA', '508': 'MZ', '512': 'OM', '516': 'NA', '520': 'NR', '524': 'NP', '528': 'NL', '531': 'CW',
  '533': 'AW', '534': 'SX', '535': 'BQ', '540': 'NC', '554': 'NZ', '558': 'NI', '562': 'NE', '566': 'NG',
  '570': 'NU', '574': 'NF', '578': 'NO', '580': 'MP', '581': 'UM', '583': 'FM', '584': 'MH', '585': 'PW',
  '586': 'PK', '591': 'PA', '598': 'PG', '600': 'PY', '604': 'PE', '608': 'PH', '612': 'PN', '616': 'PL',
  '620': 'PT', '624': 'GW', '626': 'TL', '630': 'PR', '634': 'QA', '638': 'RE', '642': 'RO', '643': 'RU',
  '646': 'RW', '652': 'BL', '654': 'SH', '659': 'KN', '662': 'LC', '663': 'MF', '666': 'PM', '670': 'VC',
  '674': 'SM', '678': 'ST', '682': 'SA', '686': 'SN', '688': 'RS', '690': 'SC', '694': 'SL', '702': 'SG',
  '703': 'SK', '704': 'VN', '705': 'SI', '706': 'SO', '710': 'ZA', '716': 'ZW', '724': 'ES', '728': 'SS',
  '729': 'SD', '740': 'SR', '744': 'SJ', '748': 'SZ', '752': 'SE', '756': 'CH', '760': 'SY', '762': 'TJ',
  '764': 'TH', '768': 'TG', '772': 'TK', '776': 'TO', '780': 'TT', '788': 'TN', '792': 'TR', '795': 'TM',
  '796': 'TC', '798': 'TV', '800': 'UG', '804': 'UA', '807': 'MK', '818': 'EG', '826': 'GB', '834': 'TZ',
  '840': 'US', '850': 'VI', '854': 'BF', '858': 'UY', '860': 'UZ', '862': 'VE', '876': 'WF', '882': 'WS',
  '887': 'YE', '894': 'ZM', '732': 'EH'
};

function cleanSvgPath(d) {
  if (!d) return '';
  return d.replace(/\d+\.\d+/g, (m) => parseFloat(m).toFixed(1));
}

// 1. Full Landmass SVG Path
const landGeo = feature(landTopology50m, landTopology50m.objects.land);
const rawLandPath = pathGenerator(landGeo);
const LAND_VECTOR_PATH = cleanSvgPath(rawLandPath);

// 2. Individual Country SVG Paths
const countriesGeo = feature(landTopology50m, landTopology50m.objects.countries);
const COUNTRY_VECTOR_PATHS = {};

for (const feat of countriesGeo.features) {
  const numericId = String(feat.id).padStart(3, '0');
  const code = NUMERIC_TO_ALPHA2[numericId];
  if (!code) continue;
  const p = pathGenerator(feat);
  if (p) {
    COUNTRY_VECTOR_PATHS[code] = cleanSvgPath(p);
  }
}

// Output file generation
const fileContent = `/**
 * vector-map.generated.ts — BUILD-TIME GENERATED VECTOR MAP GEOMETRY.
 *
 * Generated by scripts/build-vector-map.mjs using world-atlas 50m boundaries.
 * Pre-projected to equirectangular [1000 x 500] coordinate space for 60 FPS
 * razor-sharp vector zooming (1x - 8x).
 */

export const LAND_VECTOR_PATH = ${JSON.stringify(LAND_VECTOR_PATH)};

export const COUNTRY_VECTOR_PATHS: Record<string, string> = ${JSON.stringify(COUNTRY_VECTOR_PATHS, null, 2)};
`;

writeFileSync(outputPath, fileContent, 'utf-8');

console.log(`Successfully generated vector-map.generated.ts!`);
console.log(`- Land vector path size: ${(LAND_VECTOR_PATH.length / 1024).toFixed(1)} KB`);
console.log(`- Attributed countries mapped: ${Object.keys(COUNTRY_VECTOR_PATHS).length}`);
