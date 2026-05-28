/**
 * MITRE ATT&CK tactic constants for the Campaigns page.
 *
 * The 12 enterprise tactics in their canonical kill-chain order. Each carries
 * a stable token-based color so cells in the matrix and chips in the cards
 * read the same hue across the page.
 *
 * Colors cycle through --chart-1..5 with opacity bands. Zero raw hex.
 */
export interface MitreTactic {
  id: string;            // canonical lowercase id
  aliases: string[];     // accepted variants in incident.mitre_tactic
  label: string;         // display label
  short: string;         // matrix header short form
  /** Hue token used at full opacity for max-heat cells. */
  hue: string;
}

export const MITRE_TACTICS: MitreTactic[] = [
  { id: 'reconnaissance',         aliases: ['Reconnaissance', 'reconnaissance', 'TA0043'],         label: 'Reconnaissance',         short: 'Recon',   hue: 'var(--chart-1)' },
  { id: 'resource-development',   aliases: ['Resource Development', 'resource-development', 'TA0042'], label: 'Resource Development', short: 'ResDev',  hue: 'var(--chart-2)' },
  { id: 'initial-access',         aliases: ['Initial Access', 'initial-access', 'TA0001'],         label: 'Initial Access',         short: 'Initial', hue: 'var(--chart-3)' },
  { id: 'execution',              aliases: ['Execution', 'execution', 'TA0002'],                   label: 'Execution',              short: 'Exec',    hue: 'var(--chart-4)' },
  { id: 'persistence',            aliases: ['Persistence', 'persistence', 'TA0003'],               label: 'Persistence',            short: 'Persist', hue: 'var(--chart-5)' },
  { id: 'privilege-escalation',   aliases: ['Privilege Escalation', 'privilege-escalation', 'TA0004'], label: 'Privilege Escalation', short: 'PrivEsc', hue: 'var(--chart-1)' },
  { id: 'defense-evasion',        aliases: ['Defense Evasion', 'defense-evasion', 'TA0005'],       label: 'Defense Evasion',        short: 'Evasion', hue: 'var(--chart-2)' },
  { id: 'credential-access',      aliases: ['Credential Access', 'credential-access', 'TA0006'],   label: 'Credential Access',      short: 'CredAcc', hue: 'var(--chart-3)' },
  { id: 'discovery',              aliases: ['Discovery', 'discovery', 'TA0007'],                   label: 'Discovery',              short: 'Disc',    hue: 'var(--chart-4)' },
  { id: 'lateral-movement',       aliases: ['Lateral Movement', 'lateral-movement', 'TA0008'],     label: 'Lateral Movement',       short: 'Lateral', hue: 'var(--chart-5)' },
  { id: 'collection',             aliases: ['Collection', 'collection', 'TA0009'],                 label: 'Collection',             short: 'Coll',    hue: 'var(--chart-1)' },
  { id: 'command-and-control',    aliases: ['Command and Control', 'command-and-control', 'C2', 'TA0011'], label: 'Command & Control', short: 'C2',     hue: 'var(--chart-2)' },
  { id: 'exfiltration',           aliases: ['Exfiltration', 'exfiltration', 'TA0010'],             label: 'Exfiltration',           short: 'Exfil',   hue: 'var(--chart-3)' },
  { id: 'impact',                 aliases: ['Impact', 'impact', 'TA0040'],                         label: 'Impact',                 short: 'Impact',  hue: 'var(--chart-4)' },
];

const ALIAS_INDEX = new Map<string, MitreTactic>();
for (const t of MITRE_TACTICS) {
  ALIAS_INDEX.set(t.id, t);
  for (const a of t.aliases) ALIAS_INDEX.set(a.toLowerCase(), t);
}

export function resolveTactic(raw: string | null | undefined): MitreTactic | null {
  if (!raw) return null;
  return ALIAS_INDEX.get(String(raw).toLowerCase().trim()) ?? null;
}

export function tacticHeatColor(intensity: number): string {
  // intensity ∈ [0,1] — opacity band over --brand-accent for the heatmap cell fill.
  const clamped = Math.max(0, Math.min(1, intensity));
  const opacity = clamped === 0 ? 0 : 0.12 + clamped * 0.5; // 12% min visible, 62% max
  return `color-mix(in oklab, var(--brand-accent) ${Math.round(opacity * 100)}%, transparent)`;
}

export function severityTone(sev: string | null | undefined): 'danger' | 'warning' | 'accent' | 'muted' {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'danger';
  if (s === 'high') return 'danger';
  if (s === 'medium') return 'warning';
  if (s === 'low') return 'accent';
  return 'muted';
}

export function countryFlagEmoji(country: string | null | undefined): string {
  if (!country || country.length !== 2) return '';
  const cc = country.toUpperCase();
  const A = 0x1f1e6;
  return String.fromCodePoint(A + cc.charCodeAt(0) - 65, A + cc.charCodeAt(1) - 65);
}
