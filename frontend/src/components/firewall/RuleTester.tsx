'use client';

import { useState } from 'react';
import { Beaker, CheckCircle2, XCircle } from 'lucide-react';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';

interface TestResult {
  ok: boolean;
  matched: boolean;
  structural_match: boolean | null;
  rate_limit: { count: number; window_seconds: number } | null;
  action: string | null;
  rule_name: string | null;
  error: string | null;
}

interface RuleTesterProps {
  /** When provided, tests an existing saved rule. Otherwise uses raw YAML. */
  ruleId?: string;
  /** Optional YAML override — overrides the stored YAML for what-if testing. */
  yamlDef?: string;
}

const DEFAULT_EVENT = {
  source_ip: '192.168.1.100',
  port: 22,
  protocol: 'tcp',
  path: '/',
  method: 'GET',
  user_agent: 'nmap/7.94',
  event_type: 'http_request',
};

export function RuleTester({ ruleId, yamlDef }: RuleTesterProps) {
  const [eventJson, setEventJson] = useState(JSON.stringify(DEFAULT_EVENT, null, 2));
  const [result, setResult] = useState<TestResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  const runTest = async () => {
    setError(null);
    setResult(null);
    setRunning(true);
    try {
      const event = JSON.parse(eventJson);
      let res: TestResult;
      if (ruleId) {
        res = await api.firewall.test(ruleId, event, yamlDef);
      } else {
        if (!yamlDef) {
          throw new Error('No rule YAML provided');
        }
        res = await api.firewall.testYaml(yamlDef, event);
      }
      setResult(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="text-[11px] font-medium text-zinc-500 uppercase tracking-wider block mb-1.5">
          Synthetic event (JSON)
        </label>
        <textarea
          value={eventJson}
          onChange={(e) => setEventJson(e.target.value)}
          rows={9}
          spellCheck={false}
          className="w-full bg-[#09090B] border border-white/[0.06] rounded-xl px-4 py-3 text-[12px] text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-[#22D3EE]/30 font-mono leading-relaxed"
        />
      </div>

      <button
        type="button"
        onClick={runTest}
        disabled={running}
        className="flex items-center gap-2 bg-white/[0.05] hover:bg-white/[0.08] text-zinc-200 border border-white/[0.06] font-medium px-4 py-2.5 rounded-xl transition-colors text-[13px] disabled:opacity-50"
      >
        <Beaker className="w-4 h-4" />
        {running ? 'Testing...' : 'Run test'}
      </button>

      {error && (
        <div className="flex items-start gap-2 bg-[#EF4444]/[0.06] border border-[#EF4444]/30 rounded-xl px-4 py-3 text-[13px] text-[#EF4444]">
          <XCircle className="w-4 h-4 mt-0.5 shrink-0" />
          <span className="font-mono">{error}</span>
        </div>
      )}

      {result && (
        <div
          className={cn(
            'rounded-xl border px-4 py-3 text-[13px]',
            result.matched
              ? 'bg-[#22C55E]/[0.06] border-[#22C55E]/30 text-[#22C55E]'
              : 'bg-white/[0.03] border-white/[0.06] text-zinc-400'
          )}
        >
          <div className="flex items-center gap-2 mb-2">
            {result.matched ? (
              <CheckCircle2 className="w-4 h-4" />
            ) : (
              <XCircle className="w-4 h-4 text-zinc-500" />
            )}
            <span className="font-semibold">
              {result.matched ? 'Rule matched' : 'Rule did NOT match'}
            </span>
            {result.rule_name && (
              <span className="text-zinc-500">— {result.rule_name}</span>
            )}
          </div>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-[11px]">
            {result.action && (
              <>
                <dt className="text-zinc-500">action</dt>
                <dd className="text-white">{result.action}</dd>
              </>
            )}
            {result.structural_match !== null && (
              <>
                <dt className="text-zinc-500">structural_match</dt>
                <dd className="text-white">{String(result.structural_match)}</dd>
              </>
            )}
            {result.rate_limit && (
              <>
                <dt className="text-zinc-500">rate_limit</dt>
                <dd className="text-white">
                  {result.rate_limit.count} / {result.rate_limit.window_seconds}s
                </dd>
              </>
            )}
            {result.error && (
              <>
                <dt className="text-zinc-500">error</dt>
                <dd className="text-[#EF4444]">{result.error}</dd>
              </>
            )}
          </dl>
        </div>
      )}
    </div>
  );
}
