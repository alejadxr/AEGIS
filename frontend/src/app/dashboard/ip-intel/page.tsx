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

function renderIntelCard(intel: IPIntel) {
  if (intel.internal) {
    return (
      <div className="bg-card border border-border rounded-2xl p-6">
        <p className="text-[13px] text-foreground font-mono mb-1">{intel.ip}</p>
        <p className="text-[12px] text-muted-foreground">
          Internal / private / Tailscale CGNAT address — no public intel available.
        </p>
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

      {intel && renderIntelCard(intel)}

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
