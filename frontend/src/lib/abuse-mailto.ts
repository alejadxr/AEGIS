/**
 * Shared helper to build a `mailto:` link to the network's abuse contact,
 * pre-filled with the IP, ASN, and AEGIS's detection evidence.
 *
 * Used by both `/dashboard/ip-intel` (manual lookup) and
 * `/dashboard/response` (expanded incident panel — "Report abuse" CTA).
 *
 * The shape is intentionally loose (`AbuseMailtoIntel`) so callers can pass
 * either the full `IPIntel` from /dashboard/ip-intel/page.tsx OR an enriched
 * incident's `ai_analysis.ip_intel` subset.
 */

export type AbuseMailtoIntel = {
  ip: string;
  asn?: string | null;
  asn_reputation_owner?: string | null;
  org?: string | null;
  country?: string | null;
  hostname?: string | null;
  classification?: string | null;
  confidence?: {
    tor?: number | string;
    vpn?: number | string;
    proxy?: number | string;
    datacenter?: number | string;
    attacker?: number | string;
  } | null;
  consensus_risk?: number | null;
  tor_list_match?: boolean | null;
  spamhaus_match?: boolean | null;
  abuseipdb_score?: number | null;
  external_feeds?: Array<{ feed?: string | null; threat_type?: string | null }> | null;
  history?: {
    incidents?: {
      count?: number;
      first_seen?: string;
      last_seen?: string;
    } | null;
  } | null;
  ipapi_is_abuse_contact?: string | null;
};

/**
 * Returns the abuse contact email, or null if none known. Use this to gate
 * the "Report abuse" CTA — never render it with a `mailto:` pointing nowhere.
 */
export function abuseContactOf(intel: AbuseMailtoIntel | null | undefined): string | null {
  if (!intel) return null;
  const c = (intel.ipapi_is_abuse_contact || '').trim();
  return c.length > 0 ? c : null;
}

export function buildAbuseMailto(intel: AbuseMailtoIntel): string {
  const to = intel.ipapi_is_abuse_contact || '';
  const ip = intel.ip;
  const subject = `Abuse report: malicious activity from ${ip}`;
  const lines: string[] = [
    `Hello,`,
    ``,
    `We are reporting abusive activity originating from an IP under your network management.`,
    ``,
    `IP:           ${ip}`,
  ];
  if (intel.asn)
    lines.push(
      `ASN:          ${intel.asn}` +
        (intel.asn_reputation_owner ? ` (${intel.asn_reputation_owner})` : ''),
    );
  if (intel.org) lines.push(`Organization: ${intel.org}`);
  if (intel.country) lines.push(`Country:      ${intel.country}`);
  if (intel.hostname) lines.push(`Reverse DNS:  ${intel.hostname}`);
  lines.push(``);
  lines.push(`AEGIS detection evidence:`);
  if (intel.classification) lines.push(`  classification: ${intel.classification}`);
  if (intel.confidence) {
    const c = intel.confidence;
    lines.push(
      `  confidence:     tor=${c.tor} vpn=${c.vpn} proxy=${c.proxy} dc=${c.datacenter} attacker=${c.attacker}`,
    );
  }
  if (typeof intel.consensus_risk === 'number')
    lines.push(`  consensus_risk: ${intel.consensus_risk}/100`);
  if (intel.tor_list_match) lines.push(`  tor_list_match: yes (verified Tor exit)`);
  if (intel.spamhaus_match) lines.push(`  spamhaus:       on DROP list`);
  if (intel.abuseipdb_score !== undefined && intel.abuseipdb_score !== null)
    lines.push(`  abuseipdb:      ${intel.abuseipdb_score}/100`);
  if (intel.external_feeds && intel.external_feeds.length > 0) {
    lines.push(`  external_feeds:`);
    intel.external_feeds.slice(0, 5).forEach((f) =>
      lines.push(`    - ${f.feed || 'feed'} (${f.threat_type || 'n/a'})`),
    );
  }
  const inc = intel.history?.incidents;
  if (inc && inc.count) {
    lines.push(
      `  aegis_history:  ${inc.count} incidents` +
        (inc.first_seen ? ` (first ${inc.first_seen}` : '') +
        (inc.last_seen ? `, last ${inc.last_seen})` : inc.first_seen ? ')' : ''),
    );
  }
  lines.push(``);
  lines.push(`Please investigate and take appropriate action. Thank you.`);
  lines.push(``);
  lines.push(`— Reported by an AEGIS-defended network`);
  const body = lines.join('\n');
  return `mailto:${encodeURIComponent(to)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}
