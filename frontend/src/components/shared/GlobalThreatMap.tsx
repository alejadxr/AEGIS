'use client';

import { useState, useEffect } from 'react';

export interface ThreatMapEntry {
  country: string;
  country_code: string;
  count: number;
}

// v1.6.2: full ISO-3166-1 alpha-2 coverage (~249 codes) so the threat map
// renders every attacker country instead of silently dropping ~225 via the
// `if (!coords) return null;` guard. Centroids approximated to country center.
const COUNTRY_COORDS: Record<string, { lat: number; lng: number; label: string }> = {
  AD: { lat: 42.5, lng: 1.6, label: 'Andorra' },
  AE: { lat: 23.4, lng: 54.4, label: 'United Arab Emirates' },
  AF: { lat: 33.9, lng: 67.7, label: 'Afghanistan' },
  AG: { lat: 17.1, lng: -61.8, label: 'Antigua and Barbuda' },
  AI: { lat: 18.2, lng: -63.1, label: 'Anguilla' },
  AL: { lat: 41.2, lng: 20.2, label: 'Albania' },
  AM: { lat: 40.1, lng: 45.0, label: 'Armenia' },
  AO: { lat: -11.2, lng: 17.9, label: 'Angola' },
  AQ: { lat: -75.0, lng: 0.0, label: 'Antarctica' },
  AR: { lat: -38.4, lng: -63.6, label: 'Argentina' },
  AS: { lat: -14.3, lng: -170.1, label: 'American Samoa' },
  AT: { lat: 47.5, lng: 14.6, label: 'Austria' },
  AU: { lat: -25.3, lng: 133.8, label: 'Australia' },
  AW: { lat: 12.5, lng: -69.97, label: 'Aruba' },
  AX: { lat: 60.0, lng: 20.0, label: 'Åland Islands' },
  AZ: { lat: 40.1, lng: 47.6, label: 'Azerbaijan' },
  BA: { lat: 43.9, lng: 17.7, label: 'Bosnia and Herzegovina' },
  BB: { lat: 13.2, lng: -59.5, label: 'Barbados' },
  BD: { lat: 23.7, lng: 90.4, label: 'Bangladesh' },
  BE: { lat: 50.5, lng: 4.5, label: 'Belgium' },
  BF: { lat: 12.2, lng: -1.6, label: 'Burkina Faso' },
  BG: { lat: 42.7, lng: 25.5, label: 'Bulgaria' },
  BH: { lat: 26.0, lng: 50.6, label: 'Bahrain' },
  BI: { lat: -3.4, lng: 29.9, label: 'Burundi' },
  BJ: { lat: 9.3, lng: 2.3, label: 'Benin' },
  BL: { lat: 17.9, lng: -62.83, label: 'Saint Barthélemy' },
  BM: { lat: 32.32, lng: -64.75, label: 'Bermuda' },
  BN: { lat: 4.5, lng: 114.7, label: 'Brunei' },
  BO: { lat: -16.3, lng: -63.6, label: 'Bolivia' },
  BQ: { lat: 12.18, lng: -68.27, label: 'Caribbean Netherlands' },
  BR: { lat: -14.2, lng: -51.9, label: 'Brazil' },
  BS: { lat: 25.0, lng: -77.4, label: 'Bahamas' },
  BT: { lat: 27.5, lng: 90.4, label: 'Bhutan' },
  BV: { lat: -54.4, lng: 3.4, label: 'Bouvet Island' },
  BW: { lat: -22.3, lng: 24.7, label: 'Botswana' },
  BY: { lat: 53.7, lng: 27.95, label: 'Belarus' },
  BZ: { lat: 17.2, lng: -88.5, label: 'Belize' },
  CA: { lat: 56.1, lng: -106.3, label: 'Canada' },
  CC: { lat: -12.2, lng: 96.9, label: 'Cocos Islands' },
  CD: { lat: -4.0, lng: 21.8, label: 'DR Congo' },
  CF: { lat: 6.6, lng: 20.9, label: 'Central African Republic' },
  CG: { lat: -0.2, lng: 15.8, label: 'Republic of the Congo' },
  CH: { lat: 46.8, lng: 8.2, label: 'Switzerland' },
  CI: { lat: 7.5, lng: -5.5, label: 'Ivory Coast' },
  CK: { lat: -21.2, lng: -159.8, label: 'Cook Islands' },
  CL: { lat: -35.7, lng: -71.5, label: 'Chile' },
  CM: { lat: 7.4, lng: 12.4, label: 'Cameroon' },
  CN: { lat: 35.9, lng: 104.2, label: 'China' },
  CO: { lat: 4.6, lng: -74.3, label: 'Colombia' },
  CR: { lat: 9.7, lng: -83.8, label: 'Costa Rica' },
  CU: { lat: 21.5, lng: -77.8, label: 'Cuba' },
  CV: { lat: 16.0, lng: -24.0, label: 'Cape Verde' },
  CW: { lat: 12.2, lng: -69.0, label: 'Curaçao' },
  CX: { lat: -10.4, lng: 105.7, label: 'Christmas Island' },
  CY: { lat: 35.1, lng: 33.4, label: 'Cyprus' },
  CZ: { lat: 49.8, lng: 15.5, label: 'Czech Republic' },
  DE: { lat: 51.2, lng: 10.5, label: 'Germany' },
  DJ: { lat: 11.8, lng: 42.6, label: 'Djibouti' },
  DK: { lat: 56.3, lng: 9.5, label: 'Denmark' },
  DM: { lat: 15.4, lng: -61.4, label: 'Dominica' },
  DO: { lat: 18.7, lng: -70.2, label: 'Dominican Republic' },
  DZ: { lat: 28.0, lng: 1.7, label: 'Algeria' },
  EC: { lat: -1.8, lng: -78.2, label: 'Ecuador' },
  EE: { lat: 58.6, lng: 25.0, label: 'Estonia' },
  EG: { lat: 26.8, lng: 30.8, label: 'Egypt' },
  EH: { lat: 24.2, lng: -12.9, label: 'Western Sahara' },
  ER: { lat: 15.2, lng: 39.8, label: 'Eritrea' },
  ES: { lat: 40.5, lng: -3.7, label: 'Spain' },
  ET: { lat: 9.1, lng: 40.5, label: 'Ethiopia' },
  FI: { lat: 61.9, lng: 25.7, label: 'Finland' },
  FJ: { lat: -16.6, lng: 178.1, label: 'Fiji' },
  FK: { lat: -51.8, lng: -59.5, label: 'Falkland Islands' },
  FM: { lat: 7.4, lng: 150.5, label: 'Micronesia' },
  FO: { lat: 62.0, lng: -7.0, label: 'Faroe Islands' },
  FR: { lat: 46.2, lng: 2.2, label: 'France' },
  GA: { lat: -0.8, lng: 11.6, label: 'Gabon' },
  GB: { lat: 55.4, lng: -3.4, label: 'United Kingdom' },
  GD: { lat: 12.1, lng: -61.7, label: 'Grenada' },
  GE: { lat: 42.3, lng: 43.4, label: 'Georgia' },
  GF: { lat: 3.9, lng: -53.1, label: 'French Guiana' },
  GG: { lat: 49.5, lng: -2.6, label: 'Guernsey' },
  GH: { lat: 7.9, lng: -1.0, label: 'Ghana' },
  GI: { lat: 36.14, lng: -5.35, label: 'Gibraltar' },
  GL: { lat: 71.7, lng: -42.6, label: 'Greenland' },
  GM: { lat: 13.4, lng: -15.3, label: 'Gambia' },
  GN: { lat: 9.9, lng: -9.7, label: 'Guinea' },
  GP: { lat: 16.3, lng: -61.6, label: 'Guadeloupe' },
  GQ: { lat: 1.7, lng: 10.3, label: 'Equatorial Guinea' },
  GR: { lat: 39.0, lng: 21.8, label: 'Greece' },
  GS: { lat: -54.4, lng: -37.0, label: 'South Georgia' },
  GT: { lat: 15.8, lng: -90.2, label: 'Guatemala' },
  GU: { lat: 13.44, lng: 144.79, label: 'Guam' },
  GW: { lat: 11.8, lng: -15.2, label: 'Guinea-Bissau' },
  GY: { lat: 4.9, lng: -58.9, label: 'Guyana' },
  HK: { lat: 22.4, lng: 114.1, label: 'Hong Kong' },
  HM: { lat: -53.1, lng: 73.5, label: 'Heard Island' },
  HN: { lat: 15.2, lng: -86.2, label: 'Honduras' },
  HR: { lat: 45.1, lng: 15.2, label: 'Croatia' },
  HT: { lat: 18.9, lng: -72.3, label: 'Haiti' },
  HU: { lat: 47.2, lng: 19.5, label: 'Hungary' },
  ID: { lat: -0.8, lng: 113.9, label: 'Indonesia' },
  IE: { lat: 53.4, lng: -8.2, label: 'Ireland' },
  IL: { lat: 31.0, lng: 34.8, label: 'Israel' },
  IM: { lat: 54.2, lng: -4.5, label: 'Isle of Man' },
  IN: { lat: 20.59, lng: 78.96, label: 'India' },
  IO: { lat: -6.3, lng: 71.5, label: 'British Indian Ocean Territory' },
  IQ: { lat: 33.2, lng: 43.7, label: 'Iraq' },
  IR: { lat: 32.4, lng: 53.7, label: 'Iran' },
  IS: { lat: 64.9, lng: -19.0, label: 'Iceland' },
  IT: { lat: 41.9, lng: 12.6, label: 'Italy' },
  JE: { lat: 49.2, lng: -2.1, label: 'Jersey' },
  JM: { lat: 18.1, lng: -77.3, label: 'Jamaica' },
  JO: { lat: 30.6, lng: 36.2, label: 'Jordan' },
  JP: { lat: 36.2, lng: 138.3, label: 'Japan' },
  KE: { lat: 0.0, lng: 37.9, label: 'Kenya' },
  KG: { lat: 41.2, lng: 74.8, label: 'Kyrgyzstan' },
  KH: { lat: 12.6, lng: 104.9, label: 'Cambodia' },
  KI: { lat: 1.4, lng: -168.7, label: 'Kiribati' },
  KM: { lat: -11.9, lng: 43.9, label: 'Comoros' },
  KN: { lat: 17.3, lng: -62.8, label: 'Saint Kitts and Nevis' },
  KP: { lat: 40.3, lng: 127.5, label: 'North Korea' },
  KR: { lat: 35.9, lng: 127.8, label: 'South Korea' },
  KW: { lat: 29.3, lng: 47.5, label: 'Kuwait' },
  KY: { lat: 19.5, lng: -80.6, label: 'Cayman Islands' },
  KZ: { lat: 48.0, lng: 66.9, label: 'Kazakhstan' },
  LA: { lat: 19.9, lng: 102.5, label: 'Laos' },
  LB: { lat: 33.9, lng: 35.9, label: 'Lebanon' },
  LC: { lat: 13.9, lng: -61.0, label: 'Saint Lucia' },
  LI: { lat: 47.2, lng: 9.5, label: 'Liechtenstein' },
  LK: { lat: 7.9, lng: 80.8, label: 'Sri Lanka' },
  LR: { lat: 6.4, lng: -9.4, label: 'Liberia' },
  LS: { lat: -29.6, lng: 28.2, label: 'Lesotho' },
  LT: { lat: 55.2, lng: 23.9, label: 'Lithuania' },
  LU: { lat: 49.8, lng: 6.1, label: 'Luxembourg' },
  LV: { lat: 56.9, lng: 24.6, label: 'Latvia' },
  LY: { lat: 26.3, lng: 17.2, label: 'Libya' },
  MA: { lat: 31.8, lng: -7.1, label: 'Morocco' },
  MC: { lat: 43.7, lng: 7.4, label: 'Monaco' },
  MD: { lat: 47.4, lng: 28.4, label: 'Moldova' },
  ME: { lat: 42.7, lng: 19.4, label: 'Montenegro' },
  MF: { lat: 18.08, lng: -63.05, label: 'Saint Martin' },
  MG: { lat: -18.8, lng: 46.9, label: 'Madagascar' },
  MH: { lat: 7.1, lng: 171.2, label: 'Marshall Islands' },
  MK: { lat: 41.6, lng: 21.7, label: 'North Macedonia' },
  ML: { lat: 17.6, lng: -3.9, label: 'Mali' },
  MM: { lat: 21.9, lng: 95.9, label: 'Myanmar' },
  MN: { lat: 46.9, lng: 103.8, label: 'Mongolia' },
  MO: { lat: 22.2, lng: 113.5, label: 'Macao' },
  MP: { lat: 17.3, lng: 145.4, label: 'Northern Mariana Islands' },
  MQ: { lat: 14.6, lng: -61.0, label: 'Martinique' },
  MR: { lat: 21.0, lng: -10.9, label: 'Mauritania' },
  MS: { lat: 16.7, lng: -62.2, label: 'Montserrat' },
  MT: { lat: 35.9, lng: 14.4, label: 'Malta' },
  MU: { lat: -20.3, lng: 57.5, label: 'Mauritius' },
  MV: { lat: 3.2, lng: 73.2, label: 'Maldives' },
  MW: { lat: -13.3, lng: 34.3, label: 'Malawi' },
  MX: { lat: 23.6, lng: -102.6, label: 'Mexico' },
  MY: { lat: 4.2, lng: 101.9, label: 'Malaysia' },
  MZ: { lat: -18.7, lng: 35.5, label: 'Mozambique' },
  NA: { lat: -22.9, lng: 18.5, label: 'Namibia' },
  NC: { lat: -20.9, lng: 165.6, label: 'New Caledonia' },
  NE: { lat: 17.6, lng: 8.1, label: 'Niger' },
  NF: { lat: -29.0, lng: 167.9, label: 'Norfolk Island' },
  NG: { lat: 9.1, lng: 8.7, label: 'Nigeria' },
  NI: { lat: 12.9, lng: -85.2, label: 'Nicaragua' },
  NL: { lat: 52.1, lng: 5.3, label: 'Netherlands' },
  NO: { lat: 60.5, lng: 8.5, label: 'Norway' },
  NP: { lat: 28.4, lng: 84.1, label: 'Nepal' },
  NR: { lat: -0.5, lng: 166.9, label: 'Nauru' },
  NU: { lat: -19.1, lng: -169.9, label: 'Niue' },
  NZ: { lat: -40.9, lng: 174.9, label: 'New Zealand' },
  OM: { lat: 21.5, lng: 55.9, label: 'Oman' },
  PA: { lat: 8.5, lng: -80.8, label: 'Panama' },
  PE: { lat: -9.2, lng: -75.0, label: 'Peru' },
  PF: { lat: -17.7, lng: -149.4, label: 'French Polynesia' },
  PG: { lat: -6.3, lng: 143.9, label: 'Papua New Guinea' },
  PH: { lat: 12.9, lng: 121.8, label: 'Philippines' },
  PK: { lat: 30.4, lng: 69.3, label: 'Pakistan' },
  PL: { lat: 51.9, lng: 19.1, label: 'Poland' },
  PM: { lat: 46.9, lng: -56.3, label: 'Saint Pierre and Miquelon' },
  PN: { lat: -24.7, lng: -128.3, label: 'Pitcairn' },
  PR: { lat: 18.2, lng: -66.6, label: 'Puerto Rico' },
  PS: { lat: 31.9, lng: 35.2, label: 'Palestine' },
  PT: { lat: 39.4, lng: -8.2, label: 'Portugal' },
  PW: { lat: 7.5, lng: 134.6, label: 'Palau' },
  PY: { lat: -23.4, lng: -58.4, label: 'Paraguay' },
  QA: { lat: 25.4, lng: 51.2, label: 'Qatar' },
  RE: { lat: -21.1, lng: 55.5, label: 'Réunion' },
  RO: { lat: 45.9, lng: 25.0, label: 'Romania' },
  RS: { lat: 44.0, lng: 21.0, label: 'Serbia' },
  RU: { lat: 61.5, lng: 105.3, label: 'Russia' },
  RW: { lat: -1.9, lng: 29.9, label: 'Rwanda' },
  SA: { lat: 23.9, lng: 45.1, label: 'Saudi Arabia' },
  SB: { lat: -9.6, lng: 160.2, label: 'Solomon Islands' },
  SC: { lat: -4.7, lng: 55.5, label: 'Seychelles' },
  SD: { lat: 12.9, lng: 30.2, label: 'Sudan' },
  SE: { lat: 60.1, lng: 18.6, label: 'Sweden' },
  SG: { lat: 1.4, lng: 103.8, label: 'Singapore' },
  SH: { lat: -24.1, lng: -10.0, label: 'Saint Helena' },
  SI: { lat: 46.2, lng: 14.9, label: 'Slovenia' },
  SJ: { lat: 78.0, lng: 16.0, label: 'Svalbard and Jan Mayen' },
  SK: { lat: 48.7, lng: 19.7, label: 'Slovakia' },
  SL: { lat: 8.5, lng: -11.8, label: 'Sierra Leone' },
  SM: { lat: 43.9, lng: 12.5, label: 'San Marino' },
  SN: { lat: 14.5, lng: -14.5, label: 'Senegal' },
  SO: { lat: 5.2, lng: 46.2, label: 'Somalia' },
  SR: { lat: 3.9, lng: -56.0, label: 'Suriname' },
  SS: { lat: 6.9, lng: 31.3, label: 'South Sudan' },
  ST: { lat: 0.2, lng: 6.6, label: 'São Tomé and Príncipe' },
  SV: { lat: 13.8, lng: -88.9, label: 'El Salvador' },
  SX: { lat: 18.0, lng: -63.1, label: 'Sint Maarten' },
  SY: { lat: 34.8, lng: 38.0, label: 'Syria' },
  SZ: { lat: -26.5, lng: 31.5, label: 'Eswatini' },
  TC: { lat: 21.7, lng: -71.8, label: 'Turks and Caicos' },
  TD: { lat: 15.5, lng: 18.7, label: 'Chad' },
  TF: { lat: -49.3, lng: 69.4, label: 'French Southern Territories' },
  TG: { lat: 8.6, lng: 0.8, label: 'Togo' },
  TH: { lat: 15.9, lng: 100.9, label: 'Thailand' },
  TJ: { lat: 38.9, lng: 71.3, label: 'Tajikistan' },
  TK: { lat: -9.2, lng: -171.8, label: 'Tokelau' },
  TL: { lat: -8.9, lng: 125.7, label: 'Timor-Leste' },
  TM: { lat: 38.9, lng: 59.6, label: 'Turkmenistan' },
  TN: { lat: 33.9, lng: 9.5, label: 'Tunisia' },
  TO: { lat: -21.1, lng: -175.2, label: 'Tonga' },
  TR: { lat: 38.9, lng: 35.2, label: 'Turkey' },
  TT: { lat: 10.7, lng: -61.2, label: 'Trinidad and Tobago' },
  TV: { lat: -8.0, lng: 177.6, label: 'Tuvalu' },
  TW: { lat: 23.7, lng: 121.0, label: 'Taiwan' },
  TZ: { lat: -6.4, lng: 34.9, label: 'Tanzania' },
  UA: { lat: 48.4, lng: 31.2, label: 'Ukraine' },
  UG: { lat: 1.4, lng: 32.3, label: 'Uganda' },
  UM: { lat: 5.0, lng: -160.0, label: 'US Minor Outlying Islands' },
  US: { lat: 37.1, lng: -95.7, label: 'United States' },
  UY: { lat: -32.5, lng: -55.8, label: 'Uruguay' },
  UZ: { lat: 41.4, lng: 64.6, label: 'Uzbekistan' },
  VA: { lat: 41.9, lng: 12.45, label: 'Vatican' },
  VC: { lat: 13.0, lng: -61.3, label: 'Saint Vincent' },
  VE: { lat: 6.4, lng: -66.6, label: 'Venezuela' },
  VG: { lat: 18.4, lng: -64.6, label: 'British Virgin Islands' },
  VI: { lat: 18.3, lng: -64.9, label: 'US Virgin Islands' },
  VN: { lat: 14.1, lng: 108.3, label: 'Vietnam' },
  VU: { lat: -15.4, lng: 166.9, label: 'Vanuatu' },
  WF: { lat: -13.8, lng: -176.2, label: 'Wallis and Futuna' },
  WS: { lat: -13.8, lng: -172.1, label: 'Samoa' },
  YE: { lat: 15.6, lng: 48.5, label: 'Yemen' },
  YT: { lat: -12.8, lng: 45.2, label: 'Mayotte' },
  ZA: { lat: -30.6, lng: 22.9, label: 'South Africa' },
  ZM: { lat: -13.1, lng: 27.8, label: 'Zambia' },
  ZW: { lat: -19.0, lng: 29.2, label: 'Zimbabwe' },
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
          {'// NO THREAT DATA'}
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
