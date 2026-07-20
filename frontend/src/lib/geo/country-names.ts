/**
 * ISO-3166-1 alpha-2 code -> human-readable country name.
 *
 * The backend's /dashboard/threat-map endpoint (app/api/dashboard.py) only
 * knows ~80 country names by hand-written lookup; for anything outside that
 * list it echoes the code back as `country` (e.g. `{ country: "DO",
 * country_code: "DO" }`), which is the bug this file fixes. `country_code`
 * itself is trustworthy (it comes straight from the offline GeoIP dataset,
 * app/services/offline_geoip.py) so we resolve the display name client-side
 * from the code alone and never trust `country`.
 *
 * Primary resolver: `Intl.DisplayNames` (baseline-available since 2021,
 * zero bytes shipped). Verified against the full ~249-entry ISO-3166-1
 * table below (see STATIC_COUNTRY_NAMES) with zero unresolved codes — it
 * only differs in house style (e.g. "Turkey" vs "Türkiye", "and" vs "&"),
 * never in coverage. STATIC_COUNTRY_NAMES exists purely as a fallback for
 * runtimes where `Intl.DisplayNames` is unavailable (very old browsers, or
 * a non-full-ICU Node build during SSR) so a code never renders as its own
 * name even in that degraded path.
 *
 * `ZZ` is GeoIP's own "unresolved location" sentinel (see
 * offline_geoip.py's country table, sourced from a GeoLite2-style CSV) — it
 * is not an assigned ISO-3166 country and must never be shown as one.
 */

export interface ResolvedCountry {
  /** Human-readable name, or the honest "unknown" label — never a bare code. */
  name: string;
  /** False for ZZ / empty / anything that isn't a resolvable ISO-3166 country. */
  known: boolean;
}

export const UNKNOWN_COUNTRY_LABEL = 'Unmapped origin';

/** Sentinels seen in the wild that are not real ISO-3166-1 countries. */
const UNKNOWN_CODES = new Set(['ZZ', 'XX', '??', 'UNKNOWN', 'N/A']);

// Recovered verbatim from the pre-redesign GlobalThreatMap.tsx (git history,
// commit 4528944, "v1.6.2: full ISO-3166-1 alpha-2 coverage") — that
// component's only job left after this refactor is centroids
// (src/lib/geo-centroids.ts); this keeps its name coverage alive as a
// fallback instead of being lost.
const STATIC_COUNTRY_NAMES: Record<string, string> = {
  AD: 'Andorra', AE: 'United Arab Emirates', AF: 'Afghanistan', AG: 'Antigua and Barbuda',
  AI: 'Anguilla', AL: 'Albania', AM: 'Armenia', AO: 'Angola',
  AQ: 'Antarctica', AR: 'Argentina', AS: 'American Samoa', AT: 'Austria',
  AU: 'Australia', AW: 'Aruba', AX: 'Åland Islands', AZ: 'Azerbaijan',
  BA: 'Bosnia and Herzegovina', BB: 'Barbados', BD: 'Bangladesh', BE: 'Belgium',
  BF: 'Burkina Faso', BG: 'Bulgaria', BH: 'Bahrain', BI: 'Burundi',
  BJ: 'Benin', BL: 'Saint Barthélemy', BM: 'Bermuda', BN: 'Brunei',
  BO: 'Bolivia', BQ: 'Caribbean Netherlands', BR: 'Brazil', BS: 'Bahamas',
  BT: 'Bhutan', BV: 'Bouvet Island', BW: 'Botswana', BY: 'Belarus',
  BZ: 'Belize', CA: 'Canada', CC: 'Cocos Islands', CD: 'DR Congo',
  CF: 'Central African Republic', CG: 'Republic of the Congo', CH: 'Switzerland', CI: 'Ivory Coast',
  CK: 'Cook Islands', CL: 'Chile', CM: 'Cameroon', CN: 'China',
  CO: 'Colombia', CR: 'Costa Rica', CU: 'Cuba', CV: 'Cape Verde',
  CW: 'Curaçao', CX: 'Christmas Island', CY: 'Cyprus', CZ: 'Czech Republic',
  DE: 'Germany', DJ: 'Djibouti', DK: 'Denmark', DM: 'Dominica',
  DO: 'Dominican Republic', DZ: 'Algeria', EC: 'Ecuador', EE: 'Estonia',
  EG: 'Egypt', EH: 'Western Sahara', ER: 'Eritrea', ES: 'Spain',
  ET: 'Ethiopia', FI: 'Finland', FJ: 'Fiji', FK: 'Falkland Islands',
  FM: 'Micronesia', FO: 'Faroe Islands', FR: 'France', GA: 'Gabon',
  GB: 'United Kingdom', GD: 'Grenada', GE: 'Georgia', GF: 'French Guiana',
  GG: 'Guernsey', GH: 'Ghana', GI: 'Gibraltar', GL: 'Greenland',
  GM: 'Gambia', GN: 'Guinea', GP: 'Guadeloupe', GQ: 'Equatorial Guinea',
  GR: 'Greece', GS: 'South Georgia', GT: 'Guatemala', GU: 'Guam',
  GW: 'Guinea-Bissau', GY: 'Guyana', HK: 'Hong Kong', HM: 'Heard Island',
  HN: 'Honduras', HR: 'Croatia', HT: 'Haiti', HU: 'Hungary',
  ID: 'Indonesia', IE: 'Ireland', IL: 'Israel', IM: 'Isle of Man',
  IN: 'India', IO: 'British Indian Ocean Territory', IQ: 'Iraq', IR: 'Iran',
  IS: 'Iceland', IT: 'Italy', JE: 'Jersey', JM: 'Jamaica',
  JO: 'Jordan', JP: 'Japan', KE: 'Kenya', KG: 'Kyrgyzstan',
  KH: 'Cambodia', KI: 'Kiribati', KM: 'Comoros', KN: 'Saint Kitts and Nevis',
  KP: 'North Korea', KR: 'South Korea', KW: 'Kuwait', KY: 'Cayman Islands',
  KZ: 'Kazakhstan', LA: 'Laos', LB: 'Lebanon', LC: 'Saint Lucia',
  LI: 'Liechtenstein', LK: 'Sri Lanka', LR: 'Liberia', LS: 'Lesotho',
  LT: 'Lithuania', LU: 'Luxembourg', LV: 'Latvia', LY: 'Libya',
  MA: 'Morocco', MC: 'Monaco', MD: 'Moldova', ME: 'Montenegro',
  MF: 'Saint Martin', MG: 'Madagascar', MH: 'Marshall Islands', MK: 'North Macedonia',
  ML: 'Mali', MM: 'Myanmar', MN: 'Mongolia', MO: 'Macao',
  MP: 'Northern Mariana Islands', MQ: 'Martinique', MR: 'Mauritania', MS: 'Montserrat',
  MT: 'Malta', MU: 'Mauritius', MV: 'Maldives', MW: 'Malawi',
  MX: 'Mexico', MY: 'Malaysia', MZ: 'Mozambique', NA: 'Namibia',
  NC: 'New Caledonia', NE: 'Niger', NF: 'Norfolk Island', NG: 'Nigeria',
  NI: 'Nicaragua', NL: 'Netherlands', NO: 'Norway', NP: 'Nepal',
  NR: 'Nauru', NU: 'Niue', NZ: 'New Zealand', OM: 'Oman',
  PA: 'Panama', PE: 'Peru', PF: 'French Polynesia', PG: 'Papua New Guinea',
  PH: 'Philippines', PK: 'Pakistan', PL: 'Poland', PM: 'Saint Pierre and Miquelon',
  PN: 'Pitcairn', PR: 'Puerto Rico', PS: 'Palestine', PT: 'Portugal',
  PW: 'Palau', PY: 'Paraguay', QA: 'Qatar', RE: 'Réunion',
  RO: 'Romania', RS: 'Serbia', RU: 'Russia', RW: 'Rwanda',
  SA: 'Saudi Arabia', SB: 'Solomon Islands', SC: 'Seychelles', SD: 'Sudan',
  SE: 'Sweden', SG: 'Singapore', SH: 'Saint Helena', SI: 'Slovenia',
  SJ: 'Svalbard and Jan Mayen', SK: 'Slovakia', SL: 'Sierra Leone', SM: 'San Marino',
  SN: 'Senegal', SO: 'Somalia', SR: 'Suriname', SS: 'South Sudan',
  ST: 'São Tomé and Príncipe', SV: 'El Salvador', SX: 'Sint Maarten', SY: 'Syria',
  SZ: 'Eswatini', TC: 'Turks and Caicos', TD: 'Chad', TF: 'French Southern Territories',
  TG: 'Togo', TH: 'Thailand', TJ: 'Tajikistan', TK: 'Tokelau',
  TL: 'Timor-Leste', TM: 'Turkmenistan', TN: 'Tunisia', TO: 'Tonga',
  TR: 'Turkey', TT: 'Trinidad and Tobago', TV: 'Tuvalu', TW: 'Taiwan',
  TZ: 'Tanzania', UA: 'Ukraine', UG: 'Uganda', UM: 'US Minor Outlying Islands',
  US: 'United States', UY: 'Uruguay', UZ: 'Uzbekistan', VA: 'Vatican',
  VC: 'Saint Vincent', VE: 'Venezuela', VG: 'British Virgin Islands', VI: 'US Virgin Islands',
  VN: 'Vietnam', VU: 'Vanuatu', WF: 'Wallis and Futuna', WS: 'Samoa',
  YE: 'Yemen', YT: 'Mayotte', ZA: 'South Africa', ZM: 'Zambia',
  ZW: 'Zimbabwe',
};

/** Lazily-constructed singleton — `Intl.DisplayNames` instantiation is not
 * free, and this is called once per marker/row render. `undefined` means
 * "not yet attempted", `null` means "unsupported in this runtime". */
let cachedDisplayNames: Intl.DisplayNames | null | undefined;

function getDisplayNames(): Intl.DisplayNames | null {
  if (cachedDisplayNames !== undefined) return cachedDisplayNames;
  try {
    cachedDisplayNames =
      typeof Intl !== 'undefined' && typeof Intl.DisplayNames === 'function'
        ? new Intl.DisplayNames(['en'], { type: 'region' })
        : null;
  } catch {
    cachedDisplayNames = null;
  }
  return cachedDisplayNames;
}

/**
 * Resolve an ISO-3166-1 alpha-2 code to a display-ready country name.
 *
 * Never returns the bare code as a fake "name" — codes that cannot be
 * resolved to a real country (GeoIP's `ZZ` bucket, empty strings, junk
 * input) come back with `known: false` and an honest label instead.
 */
export function resolveCountryName(code: string | null | undefined): ResolvedCountry {
  const cc = (code ?? '').trim().toUpperCase();

  if (cc.length !== 2 || UNKNOWN_CODES.has(cc)) {
    return { name: UNKNOWN_COUNTRY_LABEL, known: false };
  }

  const displayNames = getDisplayNames();
  if (displayNames) {
    try {
      const resolved = displayNames.of(cc);
      // Unresolvable codes are echoed back unchanged by Intl.DisplayNames
      // rather than throwing — treat "same as input" as a miss.
      if (resolved && resolved.toUpperCase() !== cc) {
        return { name: resolved, known: true };
      }
    } catch {
      // Falls through to the static table below.
    }
  }

  const fallback = STATIC_COUNTRY_NAMES[cc];
  return fallback ? { name: fallback, known: true } : { name: UNKNOWN_COUNTRY_LABEL, known: false };
}
