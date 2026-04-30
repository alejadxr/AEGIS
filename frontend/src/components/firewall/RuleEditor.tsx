'use client';

import { useEffect, useState } from 'react';
import { Code2, ListChecks } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface RuleFormValues {
  name: string;
  enabled: boolean;
  priority: number;
  yaml_def: string;
}

interface RuleEditorProps {
  initial?: Partial<RuleFormValues>;
  onSubmit: (values: RuleFormValues) => Promise<void> | void;
  onCancel: () => void;
  submitting?: boolean;
}

type Mode = 'form' | 'yaml';

const DEFAULT_YAML = `name: My rule
enabled: true
priority: 100
match:
  - port: 22
  - protocol: tcp
  - rate_limit: { count: 5, window_seconds: 60 }
action: block_ip
duration_seconds: 3600
`;

const ACTIONS = ['block_ip', 'allow', 'alert', 'quarantine_host'] as const;

export function RuleEditor({ initial, onSubmit, onCancel, submitting }: RuleEditorProps) {
  const [mode, setMode] = useState<Mode>('form');
  const [name, setName] = useState(initial?.name ?? '');
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [priority, setPriority] = useState<number>(initial?.priority ?? 100);
  const [yamlDef, setYamlDef] = useState(initial?.yaml_def ?? DEFAULT_YAML);

  // Form-builder fields (a subset of the DSL — full control via YAML tab)
  const [sourceIp, setSourceIp] = useState('');
  const [port, setPort] = useState<string>('');
  const [protocol, setProtocol] = useState<string>('any');
  const [userAgent, setUserAgent] = useState('');
  const [rateCount, setRateCount] = useState<string>('');
  const [rateWindow, setRateWindow] = useState<string>('60');
  const [action, setAction] = useState<typeof ACTIONS[number]>('block_ip');
  const [durationSeconds, setDurationSeconds] = useState<string>('3600');

  // When switching from form → yaml, serialize the form to YAML
  useEffect(() => {
    if (mode !== 'yaml') return;
    const matchClauses: string[] = [];
    if (sourceIp.trim()) matchClauses.push(`  - source_ip: "${sourceIp.trim()}"`);
    if (port.trim()) matchClauses.push(`  - port: ${port.trim()}`);
    if (protocol !== 'any') matchClauses.push(`  - protocol: ${protocol}`);
    if (userAgent.trim()) matchClauses.push(`  - user_agent: "${userAgent.trim()}"`);
    if (rateCount.trim()) {
      matchClauses.push(
        `  - rate_limit: { count: ${rateCount.trim()}, window_seconds: ${rateWindow.trim() || 60} }`
      );
    }
    if (matchClauses.length === 0) matchClauses.push('  - protocol: any');

    const lines = [
      `name: ${name || 'Untitled rule'}`,
      `enabled: ${enabled}`,
      `priority: ${priority}`,
      'match:',
      ...matchClauses,
      `action: ${action}`,
    ];
    if (action === 'block_ip' && durationSeconds.trim()) {
      lines.push(`duration_seconds: ${durationSeconds.trim()}`);
    }
    setYamlDef(lines.join('\n') + '\n');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await onSubmit({
      name: name.trim() || 'Untitled rule',
      enabled,
      priority,
      yaml_def: yamlDef,
    });
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {/* Top row: name / priority / enabled */}
      <div className="grid grid-cols-1 sm:grid-cols-6 gap-3">
        <div className="sm:col-span-3">
          <label className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider block mb-1.5">
            Name
          </label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Block SSH brute force"
            className="w-full bg-[#09090B] border border-white/[0.06] rounded-xl px-4 py-2.5 text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-[var(--brand)]/30"
          />
        </div>
        <div className="sm:col-span-2">
          <label className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider block mb-1.5">
            Priority
          </label>
          <input
            type="number"
            value={priority}
            onChange={(e) => setPriority(parseInt(e.target.value || '0', 10))}
            className="w-full bg-[#09090B] border border-white/[0.06] rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-[var(--brand)]/30 font-mono"
          />
        </div>
        <div className="sm:col-span-1">
          <label className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider block mb-1.5">
            Enabled
          </label>
          <button
            type="button"
            onClick={() => setEnabled((v) => !v)}
            className={cn(
              'w-full h-[42px] rounded-xl text-[13px] font-medium transition-colors',
              enabled
                ? 'bg-[var(--success)]/10 text-[var(--success)] border border-[var(--success)]/30'
                : 'bg-white/[0.03] text-zinc-500 border border-white/[0.06]'
            )}
          >
            {enabled ? 'ON' : 'OFF'}
          </button>
        </div>
      </div>

      {/* Mode toggle */}
      <div className="flex items-center gap-2 border-b border-white/[0.06]">
        <button
          type="button"
          onClick={() => setMode('form')}
          className={cn(
            'flex items-center gap-2 px-3 py-2 text-[13px] font-medium border-b-2 -mb-px transition-colors',
            mode === 'form'
              ? 'text-white border-[var(--brand)]'
              : 'text-zinc-500 border-transparent hover:text-zinc-300'
          )}
        >
          <ListChecks className="w-4 h-4" />
          Form
        </button>
        <button
          type="button"
          onClick={() => setMode('yaml')}
          className={cn(
            'flex items-center gap-2 px-3 py-2 text-[13px] font-medium border-b-2 -mb-px transition-colors',
            mode === 'yaml'
              ? 'text-white border-[var(--brand)]'
              : 'text-zinc-500 border-transparent hover:text-zinc-300'
          )}
        >
          <Code2 className="w-4 h-4" />
          YAML
        </button>
      </div>

      {mode === 'form' ? (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider block mb-1.5">
                Source IP / CIDR
              </label>
              <input
                type="text"
                value={sourceIp}
                onChange={(e) => setSourceIp(e.target.value)}
                placeholder="10.0.0.0/8 (optional)"
                className="w-full bg-[#09090B] border border-white/[0.06] rounded-xl px-4 py-2.5 text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-[var(--brand)]/30 font-mono"
              />
            </div>
            <div>
              <label className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider block mb-1.5">
                Port
              </label>
              <input
                type="text"
                value={port}
                onChange={(e) => setPort(e.target.value)}
                placeholder="22"
                className="w-full bg-[#09090B] border border-white/[0.06] rounded-xl px-4 py-2.5 text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-[var(--brand)]/30 font-mono"
              />
            </div>
            <div>
              <label className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider block mb-1.5">
                Protocol
              </label>
              <select
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
                className="w-full bg-[#09090B] border border-white/[0.06] rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-[var(--brand)]/30"
              >
                <option value="any">Any</option>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="http">HTTP</option>
              </select>
            </div>
            <div>
              <label className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider block mb-1.5">
                User-Agent contains
              </label>
              <input
                type="text"
                value={userAgent}
                onChange={(e) => setUserAgent(e.target.value)}
                placeholder="nmap, sqlmap, ..."
                className="w-full bg-[#09090B] border border-white/[0.06] rounded-xl px-4 py-2.5 text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-[var(--brand)]/30"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider block mb-1.5">
                Rate limit: count
              </label>
              <input
                type="text"
                value={rateCount}
                onChange={(e) => setRateCount(e.target.value)}
                placeholder="5"
                className="w-full bg-[#09090B] border border-white/[0.06] rounded-xl px-4 py-2.5 text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-[var(--brand)]/30 font-mono"
              />
            </div>
            <div>
              <label className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider block mb-1.5">
                Rate limit: window (s)
              </label>
              <input
                type="text"
                value={rateWindow}
                onChange={(e) => setRateWindow(e.target.value)}
                placeholder="60"
                className="w-full bg-[#09090B] border border-white/[0.06] rounded-xl px-4 py-2.5 text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-[var(--brand)]/30 font-mono"
              />
            </div>
            <div>
              <label className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider block mb-1.5">
                Block duration (s)
              </label>
              <input
                type="text"
                value={durationSeconds}
                onChange={(e) => setDurationSeconds(e.target.value)}
                placeholder="3600"
                className="w-full bg-[#09090B] border border-white/[0.06] rounded-xl px-4 py-2.5 text-sm text-white placeholder:text-zinc-600 focus:outline-none focus:border-[var(--brand)]/30 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider block mb-1.5">
              Action
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {ACTIONS.map((a) => (
                <button
                  key={a}
                  type="button"
                  onClick={() => setAction(a)}
                  className={cn(
                    'px-3 py-2.5 rounded-xl text-[12px] font-medium transition-colors font-mono',
                    action === a
                      ? 'bg-[var(--brand)]/10 text-[var(--brand)] border border-[var(--brand)]/30'
                      : 'bg-white/[0.03] text-zinc-500 border border-white/[0.06] hover:text-zinc-300'
                  )}
                >
                  {a}
                </button>
              ))}
            </div>
          </div>

          <p className="text-[11px] text-zinc-600">
            Tip: switch to YAML to use advanced conditions like <span className="font-mono text-zinc-400">user_agent_regex</span>, <span className="font-mono text-zinc-400">source_ip_in</span>, <span className="font-mono text-zinc-400">country</span>, or <span className="font-mono text-zinc-400">event_type</span>.
          </p>
        </div>
      ) : (
        <div>
          <label className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider block mb-1.5">
            Rule YAML
          </label>
          <textarea
            value={yamlDef}
            onChange={(e) => setYamlDef(e.target.value)}
            rows={14}
            spellCheck={false}
            className="w-full bg-[#09090B] border border-white/[0.06] rounded-xl px-4 py-3 text-[13px] text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-[var(--brand)]/30 font-mono leading-relaxed"
          />
        </div>
      )}

      <div className="flex justify-end gap-3 pt-2">
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2 text-[13px] text-zinc-500 hover:text-white transition-colors rounded-xl"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={submitting}
          className="bg-[var(--brand)] hover:bg-[var(--brand)] text-[#09090B] font-semibold px-4 py-2 rounded-xl transition-colors text-[13px] disabled:opacity-50"
        >
          {submitting ? 'Saving...' : 'Save rule'}
        </button>
      </div>
    </form>
  );
}
