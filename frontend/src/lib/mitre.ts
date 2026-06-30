/**
 * MITRE ATT&CK technique lookup for AEGIS.
 *
 * Provides a typed map of technique codes to human-readable plain-language
 * descriptions. Used everywhere AEGIS renders a T1xxx code in the UI so that
 * non-security users can understand what each technique means.
 *
 * Plain-language field uses simple English that works for both English and
 * Spanish-speaking users without requiring an i18n framework.
 */

export interface MitreInfo {
  id: string;
  name: string;        // official ATT&CK name
  tactic: string;      // canonical tactic label (from mitreTactics.ts)
  plain: string;       // plain-language description, understandable by non-security users
  url: string;         // link to attack.mitre.org
}

/**
 * Tactic → chart token mapping for visual consistency with mitreTactics.ts
 * Uses the same var(--chart-N) assignments defined there.
 */
export const TACTIC_COLOR: Record<string, string> = {
  'Reconnaissance':       'var(--chart-1)',
  'Resource Development': 'var(--chart-2)',
  'Initial Access':       'var(--chart-3)',
  'Execution':            'var(--chart-4)',
  'Persistence':          'var(--chart-5)',
  'Privilege Escalation': 'var(--chart-1)',
  'Defense Evasion':      'var(--chart-2)',
  'Credential Access':    'var(--chart-3)',
  'Discovery':            'var(--chart-4)',
  'Lateral Movement':     'var(--chart-5)',
  'Collection':           'var(--chart-1)',
  'Command and Control':  'var(--chart-2)',
  'Exfiltration':         'var(--chart-3)',
  'Impact':               'var(--chart-4)',
};

export const MITRE_LOOKUP: Record<string, MitreInfo> = {
  'T1190': {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    plain: 'Exploiting a public website, API, or web app',
    url: 'https://attack.mitre.org/techniques/T1190',
  },
  'T1059': {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    plain: 'Running malicious commands or scripts',
    url: 'https://attack.mitre.org/techniques/T1059',
  },
  'T1059.007': {
    id: 'T1059.007',
    name: 'Command and Scripting Interpreter: JavaScript',
    tactic: 'Execution',
    plain: 'Running malicious JavaScript code',
    url: 'https://attack.mitre.org/techniques/T1059/007',
  },
  'T1068': {
    id: 'T1068',
    name: 'Exploitation for Privilege Escalation',
    tactic: 'Privilege Escalation',
    plain: 'Trying to gain admin / root access by exploiting a vulnerability',
    url: 'https://attack.mitre.org/techniques/T1068',
  },
  'T1046': {
    id: 'T1046',
    name: 'Network Service Discovery',
    tactic: 'Discovery',
    plain: 'Scanning for open ports and exposed services',
    url: 'https://attack.mitre.org/techniques/T1046',
  },
  'T1595': {
    id: 'T1595',
    name: 'Active Scanning',
    tactic: 'Reconnaissance',
    plain: 'Probing your network or systems before attacking',
    url: 'https://attack.mitre.org/techniques/T1595',
  },
  'T1595.001': {
    id: 'T1595.001',
    name: 'Active Scanning: IP Block',
    tactic: 'Reconnaissance',
    plain: 'Probing your IP ranges to find live hosts',
    url: 'https://attack.mitre.org/techniques/T1595/001',
  },
  'T1595.002': {
    id: 'T1595.002',
    name: 'Active Scanning: Vulnerability Scanning',
    tactic: 'Reconnaissance',
    plain: 'Scanning for known vulnerabilities in your services',
    url: 'https://attack.mitre.org/techniques/T1595/002',
  },
  'T1595.003': {
    id: 'T1595.003',
    name: 'Active Scanning: Wordlist Scanning',
    tactic: 'Reconnaissance',
    plain: 'Brute-forcing URLs or hidden paths on your site',
    url: 'https://attack.mitre.org/techniques/T1595/003',
  },
  'T1110': {
    id: 'T1110',
    name: 'Brute Force',
    tactic: 'Credential Access',
    plain: 'Trying many passwords to break into an account',
    url: 'https://attack.mitre.org/techniques/T1110',
  },
  'T1110.004': {
    id: 'T1110.004',
    name: 'Brute Force: Credential Stuffing',
    tactic: 'Credential Access',
    plain: 'Using leaked username/password lists to try to log in',
    url: 'https://attack.mitre.org/techniques/T1110/004',
  },
  'T1486': {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    tactic: 'Impact',
    plain: 'Encrypting your files (ransomware attack)',
    url: 'https://attack.mitre.org/techniques/T1486',
  },
  'T1490': {
    id: 'T1490',
    name: 'Inhibit System Recovery',
    tactic: 'Impact',
    plain: 'Deleting backups and snapshots to prevent recovery',
    url: 'https://attack.mitre.org/techniques/T1490',
  },
  'T1105': {
    id: 'T1105',
    name: 'Ingress Tool Transfer',
    tactic: 'Command and Control',
    plain: 'Downloading malicious tools or payloads into your system',
    url: 'https://attack.mitre.org/techniques/T1105',
  },
  'T1218': {
    id: 'T1218',
    name: 'System Binary Proxy Execution',
    tactic: 'Defense Evasion',
    plain: 'Using legitimate system tools (e.g. Windows builtins) to hide attacks',
    url: 'https://attack.mitre.org/techniques/T1218',
  },
  'T1021': {
    id: 'T1021',
    name: 'Remote Services',
    tactic: 'Lateral Movement',
    plain: 'Logging in remotely via SSH, RDP, SMB, or WinRM',
    url: 'https://attack.mitre.org/techniques/T1021',
  },
  'T1071': {
    id: 'T1071',
    name: 'Application Layer Protocol',
    tactic: 'Command and Control',
    plain: 'Using HTTP or DNS to secretly communicate with an attacker server',
    url: 'https://attack.mitre.org/techniques/T1071',
  },
  'T1056': {
    id: 'T1056',
    name: 'Input Capture',
    tactic: 'Collection',
    plain: 'Keylogging or intercepting user input to steal credentials',
    url: 'https://attack.mitre.org/techniques/T1056',
  },
  'T1027': {
    id: 'T1027',
    name: 'Obfuscated Files or Information',
    tactic: 'Defense Evasion',
    plain: 'Hiding malicious code so antivirus and analysts cannot detect it',
    url: 'https://attack.mitre.org/techniques/T1027',
  },
  'T1003': {
    id: 'T1003',
    name: 'OS Credential Dumping',
    tactic: 'Credential Access',
    plain: 'Stealing saved passwords and credentials stored in the OS',
    url: 'https://attack.mitre.org/techniques/T1003',
  },
};

/**
 * Returns a display label like "T1190 (Exploiting a public website, API, or web app)".
 * Falls back to the parent technique if the sub-technique is not in the lookup.
 * Falls back to the bare code if neither is found.
 * Returns '—' for null/undefined/empty input.
 */
export function mitreLabel(id: string | null | undefined): string {
  if (!id) return '—';
  const direct = MITRE_LOOKUP[id];
  if (direct) return `${id} (${direct.plain})`;
  // Try parent technique (e.g. T1059 for T1059.007)
  const parent = id.includes('.') ? id.split('.')[0] : null;
  if (parent) {
    const p = MITRE_LOOKUP[parent];
    if (p) return `${id} (${p.plain})`;
  }
  return id; // bare code fallback — never crash
}

/**
 * Returns full MitreInfo for a technique code, with parent fallback.
 * Returns null if neither the code nor its parent is in the lookup.
 */
export function mitreInfo(id: string | null | undefined): MitreInfo | null {
  if (!id) return null;
  const direct = MITRE_LOOKUP[id];
  if (direct) return direct;
  const parent = id.includes('.') ? id.split('.')[0] : null;
  if (parent) return MITRE_LOOKUP[parent] ?? null;
  return null;
}

/**
 * Returns the chart CSS token for the given technique's tactic.
 * Defaults to var(--chart-1) for unknown tactics.
 */
export function mitreTacticColor(id: string | null | undefined): string {
  const info = mitreInfo(id);
  if (!info) return 'var(--chart-1)';
  return TACTIC_COLOR[info.tactic] ?? 'var(--chart-1)';
}
