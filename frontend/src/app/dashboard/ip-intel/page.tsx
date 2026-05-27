'use client';

import { useEffect, useRef, useState } from 'react';
import { Search01Icon } from 'hugeicons-react';
import { cn } from '@/lib/utils';
import { api, ApiError } from '@/lib/api';

type Confidence = {
  tor: number; vpn: number; proxy: number; datacenter: number; attacker: number;
};

type Behavioral = {
  hits: number;
  distinct_apps?: number;
  distinct_paths?: number;
  distinct_uas?: number;
  apps?: string[];
  paths?: string[];
  uas?: string[];
  first_seen?: number;
  last_seen?: number;
  request_interval_mean_sec?: number;
  request_interval_stddev_sec?: number;
  session_fingerprint?: string;
};

type HistoryIncidents = {
  count: number;
  first?: string | null;
  last?: string | null;
  severities?: Record<string, number>;
  statuses?: Record<string, number>;
  mitre_top?: string[];
};
type HistoryHoneypot = {
  total: number;
  protocols?: Record<string, number>;
  last?: string | null;
  first?: string | null;
  commands?: string[];
  creds?: string[];
};
type HistoryProfile = {
  sophistication?: string | null;
  tools_used?: string[];
  techniques?: string[];
  ai_assessment?: string | null;
  total_interactions?: number;
  first_seen?: string | null;
  last_seen?: string | null;
} | null;
type HistoryAction = {
  type: string;
  target?: string | null;
  status?: string | null;
  reasoning?: string | null;
  created_at?: string | null;
  executed_at?: string | null;
};
type ExternalFeed = {
  feed: string;
  threat_type?: string | null;
  confidence?: number | null;
  last_seen?: string | null;
  tags?: string[];
};
type AISummary = {
  text: string;
  _provenance?: {
    kind?: string;
    source?: string;
    tokens_used?: number;
    cost_usd?: number;
    latency_ms?: number;
  };
} | null;

type IPIntel = {
  ip: string;
  asn?: string;
  org?: string;
  country?: string;
  city?: string;
  region?: string;
  hostname?: string;
  is_tor?: boolean | null;
  is_vpn?: boolean | null;
  is_proxy?: boolean | null;
  is_datacenter?: boolean | null;
  is_mobile?: boolean | null;
  is_malicious?: boolean | null;
  is_scanner?: boolean | null;
  is_known_service?: boolean | null;
  risk_score?: number | null;
  providers?: string[];
  cached?: boolean;
  internal?: boolean;
  deep?: boolean;
  classification?: string;
  confidence?: Confidence;
  greynoise_classification?: string;
  greynoise_noise?: boolean;
  greynoise_riot?: boolean;
  greynoise_name?: string;
  greynoise_link?: string;
  shodan_seen?: boolean;
  shodan_ports?: number[];
  shodan_hostnames?: string[];
  shodan_tags?: string[];
  shodan_vulns?: string[];
  abuseipdb_score?: number;
  abuseipdb_reports?: number;
  abuseipdb_last_reported?: string;
  asn_reputation_tag?: string;
  asn_reputation_name?: string;
  asn_reputation_owner?: string;
  tor_list_match?: boolean;
  spamhaus_match?: boolean;
  behavioral?: Behavioral;
  correlated_sessions?: string[];
  history?: {
    incidents?: HistoryIncidents;
    honeypot?: HistoryHoneypot;
    profile?: HistoryProfile;
    actions?: HistoryAction[];
  };
  external_feeds?: ExternalFeed[];
  related?: { same_subnet?: string[]; same_asn?: string[] };
  ai_summary?: AISummary;
  // Additive (v1.7+ providers — slice 1)
  is_abuser?: boolean | null;
  is_crawler?: boolean | null;
  ipapi_is_abuse_score?: number | null;       // 0..1
  ipapi_is_abuse_contact?: string | null;
  ipapi_is_company?: string | null;
  ipapi_is_company_type?: string | null;
  proxycheck_type?: string | null;            // VPN | TOR | CGI | Business | Compromised Server | ...
  proxycheck_risk?: number | null;            // 0..100
  proxycheck_provider?: string | null;
  proxycheck_org?: string | null;
  otx_pulse_count?: number | null;
  otx_pulses?: Array<{ name?: string; adversary?: string | null; tags?: string[]; references_count?: number; id?: string }>;
  otx_adversaries?: string[];
  otx_malware_families?: string[];
  otx_reputation?: number | null;
  vt_malicious_count?: number | null;
  vt_suspicious_count?: number | null;
  vt_harmless_count?: number | null;
  vt_undetected_count?: number | null;
  vt_reputation?: number | null;
  vt_total_votes?: { harmless?: number; malicious?: number };
  vt_link?: string;
  vt_network?: string;
  ipinfo_lite_continent?: string;
  ipinfo_lite_as_domain?: string;
  // Honeypot canary leak captures (slice 3+)
  honeypot_canaries?: Array<{
    id: string;
    captured_at: string;
    real_ip_webrtc?: string | null;
    fingerprint_hash?: string | null;
    headless_detected?: boolean | null;
    browser_meta?: Record<string, unknown>;
  }>;
};

const RECENT_KEY = 'aegis.ipIntel.recent';
const RECENT_MAX = 8;

function loadRecent(): string[] {
  try {
    const raw = typeof window === 'undefined' ? null : window.localStorage.getItem(RECENT_KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr.filter((x) => typeof x === 'string').slice(0, RECENT_MAX) : [];
  } catch {
    return [];
  }
}

function saveRecent(ips: string[]) {
  try {
    window.localStorage.setItem(RECENT_KEY, JSON.stringify(ips.slice(0, RECENT_MAX)));
  } catch {
    /* ignore */
  }
}

function validIp(ip: string): boolean {
  const v4 = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$/;
  const v6 = /^[0-9a-fA-F:]+$/;
  return v4.test(ip) || (v6.test(ip) && ip.includes(':') && ip.length >= 3);
}

const TONE_CLASS: Record<string, string> = {
  red: 'bg-[color-mix(in_oklab,var(--danger)_12%,transparent)] text-[var(--danger)] border-[color-mix(in_oklab,var(--danger)_30%,transparent)]',
  amber: 'bg-[color-mix(in_oklab,var(--warning)_12%,transparent)] text-[var(--warning)] border-[color-mix(in_oklab,var(--warning)_30%,transparent)]',
  cyan: 'bg-[color-mix(in_oklab,var(--primary)_12%,transparent)] text-primary border-[color-mix(in_oklab,var(--primary)_30%,transparent)]',
  muted: 'bg-muted/40 text-muted-foreground border-border',
};

const CLASSIFICATION_LABEL: Record<string, { label: string; tone: keyof typeof TONE_CLASS }> = {
  tor_exit: { label: 'Tor exit', tone: 'red' },
  known_attacker: { label: 'Known attacker', tone: 'red' },
  vpn_user: { label: 'VPN user', tone: 'amber' },
  known_crawler: { label: 'Known crawler', tone: 'cyan' },
  datacenter_bot: { label: 'Datacenter / bot', tone: 'cyan' },
  known_service: { label: 'Known service', tone: 'cyan' },
  unknown: { label: 'Unknown', tone: 'muted' },
};

function ConfidencePill({ label, value }: { label: string; value: number }) {
  const tone: keyof typeof TONE_CLASS =
    value >= 0.7 ? 'red' : value >= 0.4 ? 'amber' : value >= 0.1 ? 'cyan' : 'muted';
  return (
    <span
      className={cn(
        'text-[9px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded border font-mono',
        TONE_CLASS[tone],
      )}
    >
      {label} {value.toFixed(2)}
    </span>
  );
}

// RFC5737 documentation ranges that should NEVER appear in real traffic.
const RFC5737_RANGES: Array<[number, number, number, number]> = [
  [192, 0, 2, 24],     // TEST-NET-1
  [198, 51, 100, 24],  // TEST-NET-2
  [203, 0, 113, 24],   // TEST-NET-3
];

function classifyInternal(ip: string): { label: string; hint: string } {
  // IPv4 only — IPv6 uses string match on common prefixes.
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const [a, b, c] = [Number(m[1]), Number(m[2]), Number(m[3])];
    for (const [ra, rb, rc] of RFC5737_RANGES) {
      if (a === ra && b === rb && c === rc) {
        return {
          label: 'RFC 5737 documentation range',
          hint: 'TEST-NET — reserved for examples. Should never appear in real traffic. If you see it in incidents, it is a synthetic test artifact.',
        };
      }
    }
    if (a === 127) return { label: 'Loopback', hint: 'Localhost — traffic from this machine itself.' };
    if (a === 10) return { label: 'RFC 1918 private', hint: '10.0.0.0/8 — private network.' };
    if (a === 172 && b >= 16 && b <= 31) return { label: 'RFC 1918 private', hint: '172.16.0.0/12 — private network.' };
    if (a === 192 && b === 168) return { label: 'RFC 1918 private', hint: '192.168.0.0/16 — private network.' };
    if (a === 100 && b >= 64 && b <= 127) return { label: 'Tailscale CGNAT', hint: '100.64.0.0/10 — Carrier-Grade NAT, used by Tailscale.' };
    if (a === 169 && b === 254) return { label: 'Link-local', hint: 'Self-assigned address.' };
  }
  if (ip.toLowerCase().startsWith('fe80:')) return { label: 'IPv6 link-local', hint: 'Self-assigned address.' };
  if (ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd')) return { label: 'IPv6 ULA', hint: 'Unique local address — private IPv6.' };
  if (ip === '::1') return { label: 'Loopback', hint: 'Localhost.' };
  return { label: 'Reserved / non-routable', hint: 'Public intel not applicable.' };
}

function renderIntelCard(
  intel: IPIntel,
  onRelatedClick: (ip: string) => void = () => {},
) {
  if (intel.internal) {
    const c = classifyInternal(intel.ip);
    return (
      <div className="bg-card border border-border rounded-2xl p-6">
        <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1">Address</p>
        <p className="text-[18px] text-foreground font-mono mb-3">{intel.ip}</p>
        <div className="flex items-center gap-2 mb-2">
          <span className={cn(
            'text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded border',
            TONE_CLASS.muted,
          )}>
            {c.label}
          </span>
          <span className="text-[9px] font-mono text-muted-foreground/40">[algorithm:safe_net_filter]</span>
        </div>
        <p className="text-[12px] text-muted-foreground">{c.hint}</p>
      </div>
    );
  }
  const hostnameLooksTor = !!intel.hostname && /(tor|exit)/i.test(intel.hostname);
  const isTor = intel.is_tor === true || hostnameLooksTor || intel.tor_list_match === true;
  const tags: Array<{ label: string; tone: keyof typeof TONE_CLASS }> = [];
  if (isTor) tags.push({ label: 'TOR EXIT', tone: 'red' });
  if (intel.is_vpn) tags.push({ label: 'VPN', tone: 'amber' });
  if (intel.is_proxy) tags.push({ label: 'PROXY', tone: 'amber' });
  if (intel.is_datacenter) tags.push({ label: 'DATACENTER', tone: 'cyan' });
  if (intel.is_malicious) tags.push({ label: 'MALICIOUS', tone: 'red' });
  if (intel.is_scanner) tags.push({ label: 'SCANNER', tone: 'amber' });
  if (intel.is_known_service) tags.push({ label: 'BENIGN SERVICE', tone: 'cyan' });
  if (intel.spamhaus_match) tags.push({ label: 'SPAMHAUS DROP', tone: 'red' });
  if (intel.cached) tags.push({ label: 'CACHED', tone: 'muted' });
  const locParts = [intel.city, intel.region, intel.country].filter(Boolean);

  const cls = intel.classification ? CLASSIFICATION_LABEL[intel.classification] : null;
  const classificationText = cls
    ? intel.asn_reputation_name && (intel.classification === 'known_crawler' || intel.classification === 'known_service')
      ? `${cls.label} · ${intel.asn_reputation_name}`
      : cls.label
    : null;

  return (
    <div className="bg-card border border-border rounded-2xl p-6 space-y-4 animate-fade-in">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1">Address</p>
          <p className="text-[18px] text-foreground font-mono">{intel.ip}</p>
          {classificationText && cls && (
            <div className="mt-2 flex items-center gap-2">
              <span
                className={cn(
                  'text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded border',
                  TONE_CLASS[cls.tone],
                )}
              >
                {classificationText}
              </span>
              <span className="text-[9px] font-mono text-muted-foreground/40">[algorithm:classification]</span>
            </div>
          )}
        </div>
        {intel.providers && intel.providers.length > 0 && (
          <p className="text-[10px] font-mono text-muted-foreground/50 self-end">
            {intel.providers.join(' · ')}
          </p>
        )}
      </div>

      {tags.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          {tags.map((t) => (
            <span
              key={t.label}
              className={cn(
                'text-[9px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded border',
                TONE_CLASS[t.tone],
              )}
            >
              {t.label}
            </span>
          ))}
          {typeof intel.risk_score === 'number' && (
            <span className="text-[10px] font-mono text-muted-foreground/70 ml-1">
              risk score: {intel.risk_score}
            </span>
          )}
        </div>
      )}

      {intel.confidence && (
        <div>
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1.5 flex items-center gap-2">
            Confidence
            <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">
              [algorithm:vote_aggregation]
            </span>
          </p>
          <div className="flex flex-wrap gap-1.5">
            <ConfidencePill label="TOR" value={intel.confidence.tor} />
            <ConfidencePill label="VPN" value={intel.confidence.vpn} />
            <ConfidencePill label="PROXY" value={intel.confidence.proxy} />
            <ConfidencePill label="DC" value={intel.confidence.datacenter} />
            <ConfidencePill label="ATTACKER" value={intel.confidence.attacker} />
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {intel.asn && (
          <div className="bg-background border border-border rounded-xl p-3">
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1">ASN</p>
            <p className="text-[13px] text-foreground font-mono">{intel.asn}</p>
            {intel.asn_reputation_tag && (
              <p className="text-[10px] text-muted-foreground/60 mt-0.5">
                {intel.asn_reputation_tag} · {intel.asn_reputation_owner} <span className="text-muted-foreground/40">[algorithm:asn_reputation]</span>
              </p>
            )}
          </div>
        )}
        {intel.org && (
          <div className="bg-background border border-border rounded-xl p-3">
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1">Organization</p>
            <p className="text-[13px] text-foreground truncate" title={intel.org}>
              {intel.org}
            </p>
          </div>
        )}
        {locParts.length > 0 && (
          <div className="bg-background border border-border rounded-xl p-3">
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1">Location</p>
            <p className="text-[13px] text-foreground">{locParts.join(', ')}</p>
          </div>
        )}
        {intel.hostname && (
          <div className="bg-background border border-border rounded-xl p-3 sm:col-span-2">
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1">Reverse DNS</p>
            <p className="text-[13px] text-foreground font-mono truncate" title={intel.hostname}>
              {intel.hostname}
            </p>
          </div>
        )}
      </div>

      {(intel.greynoise_classification || intel.greynoise_name) && (
        <div className="bg-background border border-border rounded-xl p-3">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1 flex items-center gap-2">
            GreyNoise
            <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">[algorithm:greynoise]</span>
          </p>
          <p className="text-[12px] text-foreground">
            {intel.greynoise_classification ?? '—'}
            {intel.greynoise_name ? ` · ${intel.greynoise_name}` : ''}
            {intel.greynoise_noise ? ' · scanner' : ''}
            {intel.greynoise_riot ? ' · common service' : ''}
          </p>
          {intel.greynoise_link && (
            <a href={intel.greynoise_link} target="_blank" rel="noreferrer" className="text-[10px] text-primary hover:underline font-mono">
              viz.greynoise.io
            </a>
          )}
        </div>
      )}

      {(() => {
        // ─── Combined Abuse score (ipapi.is 0..1 ⊕ VT malicious_count) ───
        // Big single number 0..100, color-coded green/amber/red.
        const ipApi = typeof intel.ipapi_is_abuse_score === 'number' ? intel.ipapi_is_abuse_score : null;
        const vtMal = typeof intel.vt_malicious_count === 'number' ? intel.vt_malicious_count : null;
        if (ipApi === null && vtMal === null) return null;
        // ipapi 0..1 -> 0..70; vt 0..10+ -> up to 70; combined capped at 100
        const ipApiScaled = ipApi !== null ? Math.round(ipApi * 70) : 0;
        const vtScaled = vtMal !== null ? Math.min(70, vtMal * 12) : 0;
        const combined = Math.min(100, Math.max(ipApiScaled, vtScaled) + Math.min(30, (ipApiScaled + vtScaled) / 4));
        const score = Math.round(combined);
        const tone: keyof typeof TONE_CLASS = score > 80 ? 'red' : score >= 50 ? 'amber' : 'cyan';
        return (
          <div className="bg-background border border-border rounded-xl p-3">
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1.5 flex items-center gap-2">
              Abuse score
              <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">
                [algorithm:ipapi_is+virustotal]
              </span>
            </p>
            <div className="flex items-end gap-3">
              <span className={cn(
                'text-[32px] leading-none font-mono font-semibold px-3 py-1 rounded border',
                TONE_CLASS[tone],
              )}>
                {score}
              </span>
              <span className="text-[11px] text-muted-foreground mb-1">
                / 100
                {ipApi !== null && (
                  <> · ipapi.is {(ipApi * 100).toFixed(0)}%</>
                )}
                {vtMal !== null && (
                  <> · VT {vtMal} engines</>
                )}
                {intel.is_abuser && <> · <span className="text-[var(--danger)]">is_abuser</span></>}
              </span>
            </div>
            {intel.ipapi_is_abuse_contact && (
              <p className="text-[11px] text-muted-foreground/70 mt-1 font-mono">
                abuse contact: {intel.ipapi_is_abuse_contact}
              </p>
            )}
          </div>
        );
      })()}

      {intel.proxycheck_type && (
        <div className="bg-background border border-border rounded-xl p-3">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1.5 flex items-center gap-2">
            Proxy type
            <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">[algorithm:proxycheck.io]</span>
          </p>
          <div className="flex items-center gap-2 flex-wrap">
            {(() => {
              const t = (intel.proxycheck_type || '').toUpperCase();
              const tone: keyof typeof TONE_CLASS =
                t === 'TOR' || t.includes('COMPROMISED') ? 'red'
                : t === 'VPN' || t === 'CGI' ? 'amber'
                : t === 'BUSINESS' || t === 'RESIDENTIAL' ? 'cyan'
                : 'muted';
              return (
                <span className={cn(
                  'text-[11px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded border font-mono',
                  TONE_CLASS[tone],
                )}>
                  {t}
                </span>
              );
            })()}
            {typeof intel.proxycheck_risk === 'number' && (
              <span className="text-[11px] font-mono text-muted-foreground">
                risk: {intel.proxycheck_risk}/100
              </span>
            )}
            {intel.proxycheck_provider && (
              <span className="text-[11px] text-muted-foreground">· {intel.proxycheck_provider}</span>
            )}
          </div>
        </div>
      )}

      {typeof intel.otx_pulse_count === 'number' && intel.otx_pulse_count > 0 && (
        <div className="bg-background border border-border rounded-xl p-3 space-y-1.5">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 flex items-center gap-2">
            OTX pulses
            <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">[agent:otx_community]</span>
          </p>
          <p className="text-[12px] text-foreground font-mono">
            {intel.otx_pulse_count} pulses
            {intel.otx_adversaries && intel.otx_adversaries.length > 0 && (
              <> · adversaries: {intel.otx_adversaries.slice(0, 3).join(', ')}</>
            )}
          </p>
          {intel.otx_malware_families && intel.otx_malware_families.length > 0 && (
            <p className="text-[11px] text-[var(--danger)]">
              malware: {intel.otx_malware_families.slice(0, 5).join(', ')}
            </p>
          )}
          {intel.otx_pulses && intel.otx_pulses.length > 0 && (
            <ul className="space-y-0.5">
              {intel.otx_pulses.slice(0, 3).map((p, i) => (
                <li key={p.id ?? i} className="text-[11px] text-muted-foreground truncate" title={p.name}>
                  · {p.name}
                  {p.adversary ? ` (${p.adversary})` : ''}
                  {typeof p.references_count === 'number' && p.references_count > 0
                    ? ` · ${p.references_count} refs`
                    : ''}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {typeof intel.vt_malicious_count === 'number' && (
        <div className="bg-background border border-border rounded-xl p-3">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1.5 flex items-center gap-2">
            VirusTotal
            <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">[algorithm:virustotal_v3]</span>
          </p>
          {(() => {
            const total = (intel.vt_malicious_count ?? 0) + (intel.vt_suspicious_count ?? 0)
              + (intel.vt_harmless_count ?? 0) + (intel.vt_undetected_count ?? 0);
            const flagged = (intel.vt_malicious_count ?? 0) + (intel.vt_suspicious_count ?? 0);
            const tone: keyof typeof TONE_CLASS =
              (intel.vt_malicious_count ?? 0) >= 3 ? 'red'
              : (intel.vt_malicious_count ?? 0) >= 1 ? 'amber'
              : 'cyan';
            return (
              <p className="text-[12px] font-mono">
                <span className={cn(
                  'px-1.5 py-0.5 rounded border',
                  TONE_CLASS[tone],
                )}>
                  {flagged}/{total || '?'} engines flagged
                </span>
                {typeof intel.vt_reputation === 'number' && (
                  <span className="ml-2 text-muted-foreground">
                    reputation {intel.vt_reputation}
                  </span>
                )}
                {intel.vt_link && (
                  <>
                    {' '}·{' '}
                    <a
                      href={intel.vt_link}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary underline-offset-2 hover:underline"
                    >
                      view on VT
                    </a>
                  </>
                )}
              </p>
            );
          })()}
        </div>
      )}

      {(intel.ipinfo_lite_continent || intel.ipinfo_lite_as_domain) && (
        <div className="bg-background border border-border rounded-xl p-3">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1 flex items-center gap-2">
            IPInfo Lite
            <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">[algorithm:ipinfo_lite]</span>
          </p>
          <p className="text-[11px] text-muted-foreground font-mono">
            {intel.ipinfo_lite_continent && <>continent: {intel.ipinfo_lite_continent}{' · '}</>}
            {intel.ipinfo_lite_as_domain && <>as_domain: {intel.ipinfo_lite_as_domain}</>}
          </p>
        </div>
      )}

      {intel.honeypot_canaries && intel.honeypot_canaries.length > 0 && (
        <div className="bg-background border border-border rounded-xl p-3 space-y-1.5">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 flex items-center gap-2">
            Honeypot canary captures
            <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">[algorithm:webrtc_leak+browser_fp]</span>
          </p>
          <ul className="space-y-1">
            {intel.honeypot_canaries.slice(0, 5).map((c) => (
              <li key={c.id} className="text-[11px] font-mono text-foreground">
                {c.captured_at?.slice(0, 19)}
                {c.real_ip_webrtc && (
                  <> · <span className="text-[var(--danger)]">real IP: {c.real_ip_webrtc}</span></>
                )}
                {c.fingerprint_hash && (
                  <> · fp: <span className="text-muted-foreground">{c.fingerprint_hash.slice(0, 12)}</span></>
                )}
                {c.headless_detected && (
                  <> · <span className="text-[var(--warning)]">headless</span></>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      {intel.shodan_seen && (
        <div className="bg-background border border-border rounded-xl p-3 space-y-1">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 flex items-center gap-2">
            Shodan InternetDB
            <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">[algorithm:shodan]</span>
          </p>
          {intel.shodan_ports && intel.shodan_ports.length > 0 && (
            <p className="text-[12px] text-foreground font-mono">
              ports: {intel.shodan_ports.join(', ')}
            </p>
          )}
          {intel.shodan_tags && intel.shodan_tags.length > 0 && (
            <p className="text-[12px] text-foreground">tags: {intel.shodan_tags.join(', ')}</p>
          )}
          {intel.shodan_vulns && intel.shodan_vulns.length > 0 && (
            <p className="text-[12px] text-[var(--danger)] font-mono">
              vulns: {intel.shodan_vulns.slice(0, 6).join(', ')}{intel.shodan_vulns.length > 6 ? '…' : ''}
            </p>
          )}
        </div>
      )}

      {typeof intel.abuseipdb_score === 'number' && (
        <div className="bg-background border border-border rounded-xl p-3">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1 flex items-center gap-2">
            AbuseIPDB
            <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">[algorithm:abuseipdb]</span>
          </p>
          <p className="text-[12px] text-foreground">
            confidence: {intel.abuseipdb_score} / 100
            {typeof intel.abuseipdb_reports === 'number' ? ` · ${intel.abuseipdb_reports} reports` : ''}
          </p>
        </div>
      )}

      {intel.behavioral && intel.behavioral.hits > 0 && (
        <div className="bg-background border border-border rounded-xl p-3 space-y-1">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 flex items-center gap-2">
            Observed behavior
            <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">[algorithm:behavioral_fingerprint]</span>
          </p>
          <p className="text-[12px] text-foreground font-mono">
            {intel.behavioral.hits} hits · {intel.behavioral.distinct_apps ?? 0} apps · {intel.behavioral.distinct_paths ?? 0} paths
          </p>
          {intel.behavioral.apps && intel.behavioral.apps.length > 0 && (
            <p className="text-[11px] text-muted-foreground">apps: {intel.behavioral.apps.join(', ')}</p>
          )}
          {intel.behavioral.uas && intel.behavioral.uas.length > 0 && (
            <p className="text-[11px] text-muted-foreground truncate" title={intel.behavioral.uas.join(' | ')}>
              UA: {intel.behavioral.uas.slice(0, 3).join(' | ')}
            </p>
          )}
          {intel.behavioral.session_fingerprint && (
            <p className="text-[11px] font-mono text-muted-foreground/70">
              session_fp: {intel.behavioral.session_fingerprint}
            </p>
          )}
        </div>
      )}

      {intel.external_feeds && intel.external_feeds.length > 0 && (
        <div className="bg-background border border-border rounded-xl p-3">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1.5 flex items-center gap-2">
            External feeds
            <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">[algorithm:threat_feeds]</span>
          </p>
          <div className="flex flex-wrap gap-1.5">
            {intel.external_feeds.map((f) => (
              <span
                key={`${f.feed}-${f.threat_type}`}
                className={cn(
                  'text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded border font-mono',
                  TONE_CLASS.red,
                )}
                title={`last_seen=${f.last_seen ?? '?'} · conf=${f.confidence ?? '?'}`}
              >
                {f.feed}{f.threat_type ? ` · ${f.threat_type}` : ''}
              </span>
            ))}
          </div>
        </div>
      )}

      {intel.history && (
        intel.history.incidents?.count ||
        intel.history.honeypot?.total ||
        intel.history.profile ||
        (intel.history.actions && intel.history.actions.length > 0)
      ) && (
        <div className="bg-background border border-border rounded-xl p-3 space-y-3">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 flex items-center gap-2">
            Internal observations
            <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">[algorithm:incidents_table]</span>
          </p>

          {intel.history.incidents && intel.history.incidents.count > 0 && (
            <div className="space-y-1">
              <p className="text-[11px] text-foreground font-mono">
                {intel.history.incidents.count} incidents
                {intel.history.incidents.first ? ` · first ${intel.history.incidents.first.slice(0, 10)}` : ''}
                {intel.history.incidents.last ? ` · last ${intel.history.incidents.last.slice(0, 10)}` : ''}
              </p>
              {intel.history.incidents.severities && (
                <p className="text-[11px] text-muted-foreground">
                  severities: {Object.entries(intel.history.incidents.severities).map(([k, v]) => `${k}=${v}`).join(' · ')}
                </p>
              )}
              {intel.history.incidents.mitre_top && intel.history.incidents.mitre_top.length > 0 && (
                <p className="text-[11px] text-muted-foreground">
                  MITRE: {intel.history.incidents.mitre_top.join(', ')}
                </p>
              )}
            </div>
          )}

          {intel.history.honeypot && intel.history.honeypot.total > 0 && (
            <div className="space-y-1 pt-2 border-t border-border/40">
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 flex items-center gap-2">
                Honeypot interactions
                <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">[algorithm:phantom_processor]</span>
              </p>
              <p className="text-[11px] text-foreground font-mono">
                {intel.history.honeypot.total} sessions
                {intel.history.honeypot.protocols && ` · ${Object.entries(intel.history.honeypot.protocols).map(([k, v]) => `${k}=${v}`).join(' · ')}`}
              </p>
              {intel.history.honeypot.commands && intel.history.honeypot.commands.length > 0 && (
                <p className="text-[11px] text-muted-foreground truncate" title={intel.history.honeypot.commands.join(' | ')}>
                  commands: {intel.history.honeypot.commands.slice(0, 4).join(' | ')}
                </p>
              )}
              {intel.history.honeypot.creds && intel.history.honeypot.creds.length > 0 && (
                <p className="text-[11px] text-muted-foreground truncate" title={intel.history.honeypot.creds.join(', ')}>
                  creds tried: {intel.history.honeypot.creds.slice(0, 5).join(', ')}
                </p>
              )}
            </div>
          )}

          {intel.history.profile && (
            <div className="space-y-1 pt-2 border-t border-border/40">
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 flex items-center gap-2">
                Attacker profile
                <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">[algorithm:phantom_profiler]</span>
              </p>
              {intel.history.profile.sophistication && (
                <p className="text-[11px] text-foreground">sophistication: {intel.history.profile.sophistication}</p>
              )}
              {intel.history.profile.tools_used && intel.history.profile.tools_used.length > 0 && (
                <p className="text-[11px] text-muted-foreground">tools: {intel.history.profile.tools_used.join(', ')}</p>
              )}
              {intel.history.profile.techniques && intel.history.profile.techniques.length > 0 && (
                <p className="text-[11px] text-muted-foreground">techniques: {intel.history.profile.techniques.join(', ')}</p>
              )}
            </div>
          )}

          {intel.history.actions && intel.history.actions.length > 0 && (
            <div className="space-y-1 pt-2 border-t border-border/40">
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 flex items-center gap-2">
                Actions taken
                <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">[algorithm:auto_responder]</span>
              </p>
              <ul className="space-y-0.5">
                {intel.history.actions.slice(0, 6).map((a, i) => (
                  <li key={i} className="text-[11px] font-mono text-foreground">
                    <span className="text-muted-foreground/70">{a.created_at?.slice(0, 16) ?? '?'}</span>
                    {' · '}
                    <span className={a.status === 'executed' ? 'text-[var(--success)]' : 'text-[var(--warning)]'}>
                      {a.type}
                    </span>
                    {a.target ? ` · ${a.target}` : ''}
                    {a.status ? ` · ${a.status}` : ''}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {intel.related && (intel.related.same_subnet?.length || intel.related.same_asn?.length) ? (
        <div className="bg-background border border-border rounded-xl p-3">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1.5 flex items-center gap-2">
            Related infrastructure
            <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">[algorithm:internal_correlation]</span>
          </p>
          {intel.related.same_subnet && intel.related.same_subnet.length > 0 && (
            <div className="mb-2">
              <p className="text-[10px] text-muted-foreground/60 mb-1">Same /24 (incidents)</p>
              <div className="flex flex-wrap gap-1">
                {intel.related.same_subnet.map((rip) => (
                  <button
                    key={rip}
                    type="button"
                    onClick={() => onRelatedClick(rip)}
                    className="text-[11px] font-mono bg-card border border-border hover:border-primary/40 text-foreground rounded px-1.5 py-0.5 transition-colors"
                  >
                    {rip}
                  </button>
                ))}
              </div>
            </div>
          )}
          {intel.related.same_asn && intel.related.same_asn.length > 0 && (
            <div>
              <p className="text-[10px] text-muted-foreground/60 mb-1">Same ASN</p>
              <div className="flex flex-wrap gap-1">
                {intel.related.same_asn.map((rip) => (
                  <button
                    key={rip}
                    type="button"
                    onClick={() => onRelatedClick(rip)}
                    className="text-[11px] font-mono bg-card border border-border hover:border-primary/40 text-foreground rounded px-1.5 py-0.5 transition-colors"
                  >
                    {rip}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : null}

      {intel.deep && (
        <div className="bg-background border border-border rounded-xl p-3">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1.5 flex items-center gap-2">
            Threat brief
            {intel.ai_summary?._provenance?.source && (
              <span className={cn(
                'text-[9px] font-mono normal-case tracking-normal px-1.5 py-0.5 rounded border',
                TONE_CLASS.cyan,
              )}>
                [agent:{intel.ai_summary._provenance.source}]
              </span>
            )}
          </p>
          {intel.ai_summary?.text ? (
            <p className="text-[12px] text-foreground leading-relaxed whitespace-pre-wrap">
              {intel.ai_summary.text}
            </p>
          ) : (
            <p className="text-[11px] text-muted-foreground/60 italic">
              AI summary requires AEGIS_AI_MODE=full.
            </p>
          )}
        </div>
      )}

      {intel.correlated_sessions && intel.correlated_sessions.length > 0 && (
        <div className="bg-background border border-border rounded-xl p-3">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1 flex items-center gap-2">
            Correlated session IPs
            <span className="text-[9px] font-mono text-muted-foreground/40 normal-case tracking-normal">[algorithm:session_correlation]</span>
          </p>
          <p className="text-[11px] font-mono text-foreground break-all">
            {intel.correlated_sessions.join(', ')}
          </p>
          <p className="text-[10px] text-muted-foreground/60 mt-1">
            Same path/UA/timing fingerprint — likely the same operator using multiple exits. Heuristic; collisions possible.
          </p>
        </div>
      )}
    </div>
  );
}

export default function IPIntelPage() {
  const [query, setQuery] = useState('');
  const [deep, setDeep] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [intel, setIntel] = useState<IPIntel | null>(null);
  const [recent, setRecent] = useState<string[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setRecent(loadRecent());
    inputRef.current?.focus();
  }, []);

  async function lookup(target: string, deepFlag: boolean = deep) {
    const ip = target.trim();
    if (!ip) return;
    if (!validIp(ip)) {
      setError('Not a valid IPv4 or IPv6 address.');
      setIntel(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const data = await api.ipIntel.lookup(ip, deepFlag);
      setIntel(data);
      const next = [ip, ...recent.filter((r) => r !== ip)].slice(0, RECENT_MAX);
      setRecent(next);
      saveRecent(next);
    } catch (e) {
      const msg =
        e instanceof ApiError
          ? e.status === 401
            ? 'Unauthorized — set your API key in Settings.'
            : `Lookup failed (HTTP ${e.status}).`
          : e instanceof Error
          ? e.message
          : 'Lookup failed.';
      setError(msg);
      setIntel(null);
    } finally {
      setLoading(false);
    }
  }

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    lookup(query);
  }

  function clearRecent() {
    setRecent([]);
    saveRecent([]);
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-[22px] sm:text-[28px] font-bold text-foreground tracking-tight">
          IP Intelligence
        </h1>
        <p className="text-[13px] text-muted-foreground mt-1.5">
          Lookup any IPv4 or IPv6 address. Aggregates free public providers
          (ipinfo.io, ip.guide, ipquery.io, GreyNoise community, ip-api.com,
          GeoJS) — no AI, no LLM, no third-party telemetry beyond those
          GET requests. Static intel cached 24 h; behavioral fingerprint 15 min.
        </p>
      </div>

      <form onSubmit={onSubmit} className="bg-card border border-border rounded-2xl p-5">
        <label htmlFor="ip-input" className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1.5 block">
          Address
        </label>
        <div className="flex gap-2">
          <input
            ref={inputRef}
            id="ip-input"
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="1.1.1.1 or 2606:4700:4700::1111"
            spellCheck={false}
            autoComplete="off"
            className="flex-1 bg-background border border-border rounded-xl px-3 py-2 text-[13px] text-foreground font-mono placeholder:text-muted-foreground/40 focus:outline-none focus:border-primary/40 focus:ring-1 focus:ring-primary/20 transition-colors"
          />
          <button
            type="submit"
            disabled={loading || !query.trim()}
            className="bg-primary text-background hover:bg-primary/90 disabled:opacity-40 disabled:cursor-not-allowed rounded-xl px-4 text-[13px] font-medium transition-colors flex items-center gap-2"
          >
            <Search01Icon size={16} />
            {loading ? 'Looking up…' : 'Lookup'}
          </button>
        </div>

        <div className="mt-3 flex items-start gap-2">
          <input
            id="deep-toggle"
            type="checkbox"
            checked={deep}
            onChange={(e) => setDeep(e.target.checked)}
            className="mt-0.5 accent-[var(--primary)]"
          />
          <label htmlFor="deep-toggle" className="text-[12px] text-foreground cursor-pointer select-none">
            <span className="font-medium">Deep lookup</span>
            <span className="text-muted-foreground/70 ml-2 text-[11px]">
              + Shodan ports/CPEs, Spamhaus DROP, Tor exit list, ASN reputation,
              behavioral fingerprint from local feed, correlated session IPs.
            </span>
          </label>
        </div>
        <p className="mt-1.5 ml-6 text-[10px] text-muted-foreground/60 leading-relaxed">
          Cannot de-anonymize Tor / VPN users by server-side data — those threat models defeat
          reverse DNS, headers, cookies, WebRTC and fingerprinting. Deep mode adds intel sources +
          behavioral correlation across known proxy networks (same operator, multiple exits).
        </p>

        {error && (
          <p className="mt-3 text-[12px] text-[var(--danger)]">{error}</p>
        )}
        {recent.length > 0 && (
          <div className="mt-4 pt-4 border-t border-border">
            <div className="flex items-center justify-between mb-2">
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50">Recent</p>
              <button
                type="button"
                onClick={clearRecent}
                className="text-[10px] text-muted-foreground/60 hover:text-foreground transition-colors"
              >
                Clear
              </button>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {recent.map((ip) => (
                <button
                  key={ip}
                  type="button"
                  onClick={() => {
                    setQuery(ip);
                    lookup(ip);
                  }}
                  className="text-[11px] font-mono bg-background border border-border hover:border-primary/30 hover:text-foreground text-muted-foreground rounded-md px-2 py-1 transition-colors"
                >
                  {ip}
                </button>
              ))}
            </div>
          </div>
        )}
      </form>

      {intel && renderIntelCard(intel, (ip) => { setQuery(ip); lookup(ip); })}

      {!intel && !error && !loading && (
        <div className="bg-card border border-border rounded-2xl p-6 text-center">
          <Search01Icon size={24} className="mx-auto text-muted-foreground/40 mb-2" />
          <p className="text-[13px] text-muted-foreground">
            Enter an IP address to investigate. Same enrichment AEGIS attaches
            to every incident — manually queryable here.
          </p>
        </div>
      )}
    </div>
  );
}
