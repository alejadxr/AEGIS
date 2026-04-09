'use client';

import { useCallback, useEffect, useState } from 'react';
import { GitBranch, Shield, Zap, Clock } from 'lucide-react';
import { api } from '@/lib/api';
import { cn, formatDate } from '@/lib/utils';
import { LoadingState } from '@/components/shared/LoadingState';
import { ProcessTree, ProcessTreeNode } from '@/components/edr/ProcessTree';

interface ChainMatch {
  id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  source: string;
  mitre_technique: string | null;
  mitre_tactic: string | null;
  ai_analysis: { rule_id?: string; chain?: string[] } | null;
  detected_at: string | null;
}

interface RecentEvent {
  id: string;
  category: string;
  severity: string;
  title: string;
  details: {
    kind?: string;
    pid?: number;
    ppid?: number;
    process_name?: string;
    command_line?: string;
    target?: string;
  };
  timestamp: string;
}

const sevColor: Record<string, string> = {
  critical: 'text-red-400 border-red-500/40 bg-red-500/10',
  high: 'text-orange-400 border-orange-500/40 bg-orange-500/10',
  medium: 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10',
  low: 'text-sky-400 border-sky-500/40 bg-sky-500/10',
  info: 'text-zinc-400 border-zinc-500/40 bg-zinc-500/10',
};

export default function EdrDashboardPage() {
  const [chains, setChains] = useState<ChainMatch[]>([]);
  const [events, setEvents] = useState<RecentEvent[]>([]);
  const [tree, setTree] = useState<{
    anchor: ProcessTreeNode;
    ancestors: ProcessTreeNode[];
    descendants: ProcessTreeNode;
    total_nodes: number;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [agentId, setAgentId] = useState<string>('');
  const [pidQuery, setPidQuery] = useState<string>('');
  const [agents, setAgents] = useState<Array<{ id: string; hostname: string; status: string }>>([]);

  const loadChains = useCallback(async () => {
    try {
      const data = await api.get<ChainMatch[]>('/edr/chains?limit=25');
      setChains(data || []);
    } catch (e) {
      console.error('chains load failed', e);
      setChains([]);
    }
  }, []);

  const loadRecent = useCallback(
    async (aid: string) => {
      if (!aid) return;
      try {
        const data = await api.get<RecentEvent[]>(
          `/edr/events/recent?agent_id=${encodeURIComponent(aid)}&minutes=15&limit=150`,
        );
        setEvents(data || []);
      } catch (e) {
        console.error('recent events load failed', e);
        setEvents([]);
      }
    },
    [],
  );

  // Auto-load agents list and select the first one
  useEffect(() => {
    (async () => {
      setLoading(true);
      await loadChains();

      // Fetch enrolled agents and auto-select the first one
      try {
        const nodesData = await api.nodes.list();
        const raw = (nodesData as { agents?: Array<Record<string, unknown>> })?.agents
          || (Array.isArray(nodesData) ? nodesData : []);
        const nodeList = raw.map((n: Record<string, unknown>) => ({
          id: String(n.agent_id || n.id || ''),
          hostname: String(n.hostname || ''),
          status: String(n.status || 'unknown'),
        }));
        setAgents(nodeList);
        if (nodeList.length > 0 && !agentId) {
          setAgentId(nodeList[0].id);
        }
      } catch (e) {
        console.error('agents list load failed', e);
      }

      setLoading(false);
    })();
  }, [loadChains]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-load recent events when agent changes (poll every 5s)
  useEffect(() => {
    if (agentId) {
      loadRecent(agentId);
      const t = setInterval(() => loadRecent(agentId), 5000);
      return () => clearInterval(t);
    }
  }, [agentId, loadRecent]);

  const loadTree = async () => {
    if (!agentId || !pidQuery) return;
    try {
      const data = await api.get<typeof tree>(
        `/edr/process-tree?agent_id=${encodeURIComponent(agentId)}&pid=${encodeURIComponent(pidQuery)}`,
      );
      setTree(data || null);
    } catch (e) {
      console.error('process tree load failed', e);
      setTree(null);
    }
  };

  if (loading) return <LoadingState message="Loading EDR telemetry..." />;

  return (
    <div className="p-6 space-y-6">
      <header className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30">
            <Shield className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold text-zinc-100">EDR / XDR Core</h1>
            <p className="text-sm text-zinc-500">
              Process telemetry, attack chain detection, and live event stream
            </p>
          </div>
        </div>
      </header>

      {/* Attack chain incidents */}
      <section className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <Zap className="w-5 h-5 text-orange-400" />
          <h2 className="text-lg font-semibold text-zinc-100">Attack chain matches</h2>
          <span className="text-xs text-zinc-500 ml-2">
            {chains.length} recent
          </span>
        </div>
        {chains.length === 0 ? (
          <p className="text-sm text-zinc-500 py-4">
            No chain-rule matches yet. Telemetry will populate this list as
            agents report process starts.
          </p>
        ) : (
          <div className="space-y-2">
            {chains.map((c) => (
              <article
                key={c.id}
                className={cn(
                  'border rounded-xl p-4 flex items-start justify-between gap-4',
                  sevColor[c.severity] ?? sevColor.info,
                )}
              >
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="uppercase text-[10px] font-mono tracking-wider">
                      {c.severity}
                    </span>
                    {c.mitre_technique && (
                      <span className="text-[10px] font-mono bg-white/[0.06] px-2 py-0.5 rounded">
                        {c.mitre_technique}
                      </span>
                    )}
                  </div>
                  <h3 className="text-sm font-semibold text-zinc-100 mt-1 truncate">
                    {c.title}
                  </h3>
                  {c.ai_analysis?.chain && (
                    <p className="text-xs font-mono text-zinc-400 mt-1 truncate">
                      {c.ai_analysis.chain.join(' -> ')}
                    </p>
                  )}
                </div>
                <time className="text-xs text-zinc-500 shrink-0 flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {c.detected_at ? formatDate(c.detected_at) : '—'}
                </time>
              </article>
            ))}
          </div>
        )}
      </section>

      {/* Process tree viewer */}
      <section className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <GitBranch className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg font-semibold text-zinc-100">Process tree</h2>
        </div>
        <div className="flex flex-wrap items-end gap-3 mb-4">
          <div>
            <label className="block text-xs text-zinc-500 mb-1">Agent</label>
            <select
              value={agentId}
              onChange={(e) => setAgentId(e.target.value)}
              className="bg-zinc-900 border border-white/[0.06] rounded-lg px-3 py-1.5 text-sm text-zinc-100 w-80 font-mono"
            >
              {agents.length === 0 && <option value="">No agents enrolled</option>}
              {agents.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.hostname || a.id.slice(0, 12)} — {a.status}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs text-zinc-500 mb-1">PID</label>
            <input
              type="text"
              value={pidQuery}
              onChange={(e) => setPidQuery(e.target.value)}
              placeholder="1234"
              className="bg-zinc-900 border border-white/[0.06] rounded-lg px-3 py-1.5 text-sm text-zinc-100 w-28 font-mono"
            />
          </div>
          <button
            onClick={loadTree}
            className="px-4 py-1.5 rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 text-sm hover:bg-cyan-500/30"
          >
            Load tree
          </button>
        </div>

        {tree ? (
          <ProcessTree
            anchor={tree.anchor}
            ancestors={tree.ancestors}
            descendants={tree.descendants}
          />
        ) : (
          <p className="text-sm text-zinc-500 py-4">
            Enter an agent ID and PID above to reconstruct the process tree.
          </p>
        )}
      </section>

      {/* Live event stream */}
      <section className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <Zap className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg font-semibold text-zinc-100">Recent events</h2>
          {agentId && (
            <span className="text-xs text-zinc-500 ml-2">
              agent {agentId.slice(0, 8)}... · last 15 min
            </span>
          )}
        </div>
        {!agentId ? (
          <p className="text-sm text-zinc-500 py-4">
            No agents enrolled yet. Install the AEGIS Node Agent on an endpoint to see telemetry here.
          </p>
        ) : events.length === 0 ? (
          <p className="text-sm text-zinc-500 py-4">No events in the last 15 minutes.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead className="text-zinc-500 border-b border-white/[0.06]">
                <tr>
                  <th className="text-left py-2 pr-4">Time</th>
                  <th className="text-left py-2 pr-4">Kind</th>
                  <th className="text-left py-2 pr-4">PID</th>
                  <th className="text-left py-2">Title</th>
                </tr>
              </thead>
              <tbody className="text-zinc-300">
                {events.slice(0, 100).map((e) => (
                  <tr key={e.id} className="border-b border-white/[0.03]">
                    <td className="py-1 pr-4">
                      {new Date(e.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-1 pr-4 text-cyan-400">{e.details?.kind}</td>
                    <td className="py-1 pr-4">{e.details?.pid ?? '-'}</td>
                    <td className="py-1 truncate">{e.title}</td>
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
