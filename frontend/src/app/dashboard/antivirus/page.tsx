'use client';

import { useCallback, useEffect, useState } from 'react';
import { ShieldAlert, RotateCcw, FileWarning, RefreshCw, Search } from 'lucide-react';
import { api } from '@/lib/api';
import { cn, formatDate } from '@/lib/utils';
import { LoadingState } from '@/components/shared/LoadingState';

interface QuarantineItem {
  id: string;
  agent_id: string;
  path: string;
  sha256: string;
  rule: string | null;
  engine: string;
  file_size: number | null;
  detected_at: string | null;
}

interface SignatureBundle {
  version: string;
  yara_rules: string;
  bad_hashes: string[];
  generated_at: string;
}

export default function AntivirusPage() {
  const [items, setItems] = useState<QuarantineItem[]>([]);
  const [bundle, setBundle] = useState<SignatureBundle | null>(null);
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [lookupHash, setLookupHash] = useState('');
  const [lookupResult, setLookupResult] = useState<Record<string, unknown> | null>(null);

  const load = useCallback(async () => {
    try {
      const [q, sig] = await Promise.all([
        api.get<QuarantineItem[]>('/antivirus/quarantine?limit=100'),
        api.get<SignatureBundle>('/antivirus/signatures'),
      ]);
      setItems(q || []);
      setBundle(sig || null);
    } catch (e) {
      console.error('antivirus load failed', e);
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await load();
      setLoading(false);
    })();
  }, [load]);

  const release = async (id: string) => {
    if (!confirm('Restore this file from quarantine? It may contain malware.')) return;
    try {
      await api.post(`/antivirus/quarantine/${id}/release`, {});
      await load();
    } catch (e) {
      console.error('release failed', e);
    }
  };

  const forceUpdate = async () => {
    setUpdating(true);
    try {
      await api.post('/antivirus/signatures/update', {});
      await load();
    } catch (e) {
      console.error('force update failed', e);
    } finally {
      setUpdating(false);
    }
  };

  const lookup = async () => {
    if (lookupHash.length !== 64) return;
    try {
      const r = await api.get<Record<string, unknown>>(`/antivirus/hash/${lookupHash}/lookup`);
      setLookupResult(r);
    } catch (e) {
      console.error('lookup failed', e);
      setLookupResult({ error: String(e) });
    }
  };

  if (loading) return <LoadingState message="Loading antivirus data..." />;

  return (
    <div className="p-6 space-y-6">
      <header className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-orange-500/10 border border-orange-500/30">
            <ShieldAlert className="w-6 h-6 text-orange-400" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold text-zinc-100">Antivirus Engine</h1>
            <p className="text-sm text-zinc-500">
              YARA + ClamAV + hash reputation signatures
            </p>
          </div>
        </div>
        <button
          onClick={forceUpdate}
          disabled={updating}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 text-sm hover:bg-cyan-500/30 disabled:opacity-50"
        >
          <RefreshCw className={cn('w-4 h-4', updating && 'animate-spin')} />
          Update signatures
        </button>
      </header>

      {/* Signature status */}
      {bundle && (
        <section className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-5">
          <h2 className="text-lg font-semibold text-zinc-100 mb-3">Signature status</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Metric label="Version" value={bundle.version.slice(0, 12)} mono />
            <Metric label="YARA rules" value={`${bundle.yara_rules.length.toLocaleString()} bytes`} />
            <Metric label="Bad hashes" value={bundle.bad_hashes.length.toLocaleString()} />
            <Metric
              label="Generated"
              value={bundle.generated_at ? formatDate(bundle.generated_at) : '—'}
            />
          </div>
        </section>
      )}

      {/* Hash reputation lookup */}
      <section className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-5">
        <h2 className="text-lg font-semibold text-zinc-100 mb-3 flex items-center gap-2">
          <Search className="w-5 h-5 text-cyan-400" />
          Hash reputation lookup
        </h2>
        <div className="flex flex-wrap items-center gap-3">
          <input
            type="text"
            value={lookupHash}
            onChange={(e) => setLookupHash(e.target.value.toLowerCase().trim())}
            placeholder="paste sha256 (64 hex chars)"
            className="bg-zinc-900 border border-white/[0.06] rounded-lg px-3 py-2 text-sm text-zinc-100 font-mono w-[32rem] max-w-full"
          />
          <button
            onClick={lookup}
            disabled={lookupHash.length !== 64}
            className="px-4 py-2 rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 text-sm disabled:opacity-40"
          >
            Lookup
          </button>
        </div>
        {lookupResult && (
          <pre className="mt-3 bg-zinc-950 border border-white/[0.06] rounded-lg p-3 text-xs text-zinc-300 overflow-auto">
            {JSON.stringify(lookupResult, null, 2)}
          </pre>
        )}
      </section>

      {/* Quarantine list */}
      <section className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <FileWarning className="w-5 h-5 text-red-400" />
          <h2 className="text-lg font-semibold text-zinc-100">Quarantine</h2>
          <span className="text-xs text-zinc-500 ml-2">{items.length} items</span>
        </div>
        {items.length === 0 ? (
          <p className="text-sm text-zinc-500 py-4">No quarantined files.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead className="text-zinc-500 border-b border-white/[0.06]">
                <tr>
                  <th className="text-left py-2 pr-4">Detected</th>
                  <th className="text-left py-2 pr-4">Path</th>
                  <th className="text-left py-2 pr-4">Rule</th>
                  <th className="text-left py-2 pr-4">Engine</th>
                  <th className="text-left py-2 pr-4">SHA256</th>
                  <th className="text-right py-2">Actions</th>
                </tr>
              </thead>
              <tbody className="text-zinc-300">
                {items.map((it) => (
                  <tr key={it.id} className="border-b border-white/[0.03]">
                    <td className="py-2 pr-4 whitespace-nowrap">
                      {it.detected_at ? formatDate(it.detected_at) : '—'}
                    </td>
                    <td className="py-2 pr-4 max-w-lg truncate" title={it.path}>
                      {it.path}
                    </td>
                    <td className="py-2 pr-4 text-orange-400">{it.rule ?? '—'}</td>
                    <td className="py-2 pr-4 text-cyan-400">{it.engine}</td>
                    <td className="py-2 pr-4 text-zinc-500">
                      {it.sha256.slice(0, 12)}...
                    </td>
                    <td className="py-2 text-right">
                      <button
                        onClick={() => release(it.id)}
                        className="inline-flex items-center gap-1 px-2 py-1 rounded bg-zinc-800 border border-white/[0.06] text-zinc-300 hover:bg-zinc-700"
                      >
                        <RotateCcw className="w-3 h-3" />
                        Release
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function Metric({ label, value, mono }: { label: string; value: string | number; mono?: boolean }) {
  return (
    <div className="bg-zinc-900/40 border border-white/[0.04] rounded-xl p-3">
      <div className="text-[10px] uppercase tracking-wider text-zinc-500">{label}</div>
      <div
        className={cn(
          'text-lg text-zinc-100 mt-1',
          mono && 'font-mono text-sm',
        )}
      >
        {value}
      </div>
    </div>
  );
}
