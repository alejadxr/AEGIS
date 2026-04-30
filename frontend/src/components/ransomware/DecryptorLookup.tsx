'use client';

import { useState } from 'react';
import { Search01Icon } from 'hugeicons-react';
import { ExternalLink, CheckCircle2 } from 'lucide-react';
import { cn } from '@/lib/utils';

interface Decryptor {
  id: string;
  name: string;
  ransomware_family: string;
  file_extensions: string[];
  source_url: string;
  verified: boolean;
  confidence: number;
  published_at?: string;
}

interface DecryptorApiResponse {
  decryptors?: Decryptor[];
  items?: Decryptor[];
}

export function DecryptorLookup() {
  const [extension, setExtension] = useState('');
  const [results, setResults] = useState<Decryptor[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const [error, setError] = useState(false);

  async function lookup() {
    const ext = extension.trim().replace(/^\./, '');
    if (!ext) return;
    setLoading(true);
    setSearched(true);
    setError(false);
    setResults(null);
    try {
      const apiKey = typeof window !== 'undefined' ? localStorage.getItem('aegis_api_key') : null;
      const res = await fetch(`/api/v1/ransomware/decryptors?file_extension=${encodeURIComponent(ext)}`, {
        headers: apiKey ? { 'X-API-Key': apiKey } : {},
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json: DecryptorApiResponse = await res.json();
      const items = Array.isArray(json) ? json : (json.decryptors ?? json.items ?? []);
      setResults(items as Decryptor[]);
    } catch {
      setResults([]);
      setError(true);
    } finally {
      setLoading(false);
    }
  }

  function handleKey(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') lookup();
  }

  return (
    <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl overflow-hidden">
      <div className="flex items-center gap-2 px-5 py-4 border-b border-white/[0.06]">
        <Search01Icon size={16} className="text-[#22D3EE]" />
        <span className="text-[13px] font-semibold text-foreground">Decryptor Lookup</span>
      </div>

      <div className="p-5 space-y-4">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <span className="absolute left-3.5 top-1/2 -translate-y-1/2 text-muted-foreground/50 font-mono text-[13px]">.</span>
            <input
              type="text"
              value={extension}
              onChange={(e) => setExtension(e.target.value)}
              onKeyDown={handleKey}
              placeholder="locked, encrypted, pay2decrypt…"
              className="w-full bg-[#09090B] border border-border rounded-xl pl-7 pr-4 py-2.5 text-[13px] font-mono text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:border-[#22D3EE]/30 transition-colors"
            />
          </div>
          <button
            onClick={lookup}
            disabled={loading || !extension.trim()}
            className={cn(
              'px-4 py-2.5 rounded-xl text-[13px] font-semibold transition-colors shrink-0',
              loading || !extension.trim()
                ? 'bg-white/[0.04] text-muted-foreground/40 cursor-not-allowed'
                : 'bg-[#22D3EE] hover:bg-[#22D3EE]/90 text-[#09090B]'
            )}
          >
            {loading ? 'Searching…' : 'Search'}
          </button>
        </div>

        {!searched && (
          <p className="text-[11px] text-muted-foreground/50 leading-relaxed">
            Enter the file extension used by the ransomware (without the dot) to find known decryptors from No More Ransom and other verified sources.
          </p>
        )}

        {searched && results !== null && results.length === 0 && (
          <div className="flex flex-col items-center justify-center py-6 text-center">
            <p className="text-[13px] text-muted-foreground">
              {error
                ? 'Decryptor service unavailable — endpoint not yet wired.'
                : `No known decryptors for ".${extension.replace(/^\./, '')}".`}
            </p>
            {error && (
              <p className="text-[11px] text-muted-foreground/50 mt-1 font-mono">
                /api/v1/ransomware/decryptors
              </p>
            )}
            {!error && (
              <a
                href="https://www.nomoreransom.org/crypto-sheriff.php"
                target="_blank"
                rel="noopener noreferrer"
                className="mt-3 flex items-center gap-1.5 text-[12px] text-[#22D3EE] hover:text-[#22D3EE]/80 transition-colors"
              >
                Try No More Ransom
                <ExternalLink className="w-3 h-3" />
              </a>
            )}
          </div>
        )}

        {results && results.length > 0 && (
          <div className="space-y-2">
            {results.map((d) => (
              <div
                key={d.id}
                className="bg-[#09090B] border border-white/[0.06] rounded-xl p-4 space-y-2"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-[13px] font-semibold text-foreground truncate">{d.name}</p>
                      {d.verified && (
                        <CheckCircle2 className="w-3.5 h-3.5 text-[var(--success)] shrink-0" />
                      )}
                    </div>
                    <p className="text-[11px] text-muted-foreground/70 mt-0.5">{d.ransomware_family}</p>
                  </div>
                  <span
                    className={cn(
                      'text-[10px] font-mono px-2 py-0.5 rounded-md shrink-0',
                      d.confidence >= 0.9
                        ? 'text-[var(--success)] bg-[var(--success)]/10'
                        : d.confidence >= 0.7
                          ? 'text-[var(--warning)] bg-[var(--warning)]/10'
                          : 'text-muted-foreground/60 bg-white/[0.04]'
                    )}
                  >
                    {Math.round(d.confidence * 100)}%
                  </span>
                </div>
                {d.file_extensions?.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {d.file_extensions.map((ext) => (
                      <span
                        key={ext}
                        className="text-[10px] font-mono bg-white/[0.04] border border-border px-1.5 py-0.5 rounded text-muted-foreground/70"
                      >
                        .{ext}
                      </span>
                    ))}
                  </div>
                )}
                {d.source_url && (
                  <a
                    href={d.source_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 text-[11px] text-[#22D3EE] hover:text-[#22D3EE]/80 transition-colors"
                  >
                    Download decryptor
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
