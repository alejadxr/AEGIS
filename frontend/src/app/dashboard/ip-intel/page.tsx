'use client';

import { useEffect, useRef, useState } from 'react';
import { Search01Icon } from 'hugeicons-react';
import { cn } from '@/lib/utils';
import { api, ApiError } from '@/lib/api';

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
  risk_score?: number | null;
  providers?: string[];
  cached?: boolean;
  internal?: boolean;
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
  // Permissive IPv6 — backend revalidates strictly.
  const v6 = /^[0-9a-fA-F:]+$/;
  return v4.test(ip) || (v6.test(ip) && ip.includes(':') && ip.length >= 3);
}

const TONE_CLASS: Record<string, string> = {
  red: 'bg-[color-mix(in_oklab,var(--danger)_12%,transparent)] text-[var(--danger)] border-[color-mix(in_oklab,var(--danger)_30%,transparent)]',
  amber: 'bg-[color-mix(in_oklab,var(--warning)_12%,transparent)] text-[var(--warning)] border-[color-mix(in_oklab,var(--warning)_30%,transparent)]',
  cyan: 'bg-[color-mix(in_oklab,var(--primary)_12%,transparent)] text-primary border-[color-mix(in_oklab,var(--primary)_30%,transparent)]',
  muted: 'bg-muted/40 text-muted-foreground border-border',
};

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
  const isTor = intel.is_tor === true || hostnameLooksTor;
  const tags: Array<{ label: string; tone: keyof typeof TONE_CLASS }> = [];
  if (isTor) tags.push({ label: 'TOR EXIT', tone: 'red' });
  if (intel.is_vpn) tags.push({ label: 'VPN', tone: 'amber' });
  if (intel.is_proxy) tags.push({ label: 'PROXY', tone: 'amber' });
  if (intel.is_datacenter) tags.push({ label: 'DATACENTER', tone: 'cyan' });
  if (intel.cached) tags.push({ label: 'CACHED', tone: 'muted' });
  const locParts = [intel.city, intel.region, intel.country].filter(Boolean);

  return (
    <div className="bg-card border border-border rounded-2xl p-6 space-y-4 animate-fade-in">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1">Address</p>
          <p className="text-[18px] text-foreground font-mono">{intel.ip}</p>
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

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {intel.asn && (
          <div className="bg-background border border-border rounded-xl p-3">
            <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 mb-1">ASN</p>
            <p className="text-[13px] text-foreground font-mono">{intel.asn}</p>
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
    </div>
  );
}

export default function IPIntelPage() {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [intel, setIntel] = useState<IPIntel | null>(null);
  const [recent, setRecent] = useState<string[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setRecent(loadRecent());
    inputRef.current?.focus();
  }, []);

  async function lookup(target: string) {
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
      const data = await api.ipIntel.lookup(ip);
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
          (ipinfo.io, ip.guide, ipquery.io) — no AI, no LLM, no third-party
          telemetry beyond those three GET requests. Results cached 24 h.
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
