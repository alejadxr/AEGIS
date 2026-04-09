'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { AlertTriangle, CheckCircle, GitBranch, Shield, Zap, Clock, Monitor } from 'lucide-react';
import { api } from '@/lib/api';
import { subscribeTopic } from '@/lib/ws';
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
  ai_analysis: { rule_id?: string; chain?: string[]; pid?: number } | null;
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

const EVENT_CATEGORIES = ['All', 'Process', 'Network', 'File', 'Suspicious'] as const;
type EventCategory = (typeof EVENT_CATEGORIES)[number];

const MAX_EVENTS = 200;

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
  const [filterCategory, setFilterCategory] = useState<EventCategory>('All');
  const [killConfirm, setKillConfirm] = useState<{ pid: number; name: string } | null>(null);
  const [killingPids, setKillingPids] = useState<Set<number>>(new Set());
  const [killedPids, setKilledPids] = useState<Set<number>>(new Set());
  const [containedChains, setContainedChains] = useState<Set<string>>(new Set());
  const [containingChains, setContainingChains] = useState<Set<string>>(new Set());
  const eventsRef = useRef<RecentEvent[]>([]);

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
        const list = data || [];
        eventsRef.current = list;
        setEvents(list);
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

      // Fetch enrolled agents — try /agents (EDR agents) then /nodes as fallback
      try {
        let nodeList: Array<{ id: string; hostname: string; status: string }> = [];
        try {
          const agentsData = await api.get<Array<Record<string, unknown>>>('/agents');
          const raw = Array.isArray(agentsData) ? agentsData : [];
          nodeList = raw.map((n) => ({
            id: String(n.id || ''),
            hostname: String(n.hostname || ''),
            status: String(n.status || 'unknown'),
          }));
        } catch {
          // Fallback to nodes API
          const nodesData = await api.nodes.list();
          const raw = (nodesData as { agents?: Array<Record<string, unknown>> })?.agents
            || (Array.isArray(nodesData) ? nodesData : []);
          nodeList = raw.map((n: Record<string, unknown>) => ({
            id: String(n.agent_id || n.id || ''),
            hostname: String(n.hostname || ''),
            status: String(n.status || 'unknown'),
          }));
        }
        setAgents(nodeList);
        if (nodeList.length > 0 && !agentId) {
          // Prefer the host monitor agent
          const hostAgent = nodeList.find((a) => a.id === 'aegis-host-monitor');
          setAgentId(hostAgent ? hostAgent.id : nodeList[0].id);
        }
      } catch (e) {
        console.error('agents list load failed', e);
      }

      setLoading(false);
    })();
  }, [loadChains]); // eslint-disable-line react-hooks/exhaustive-deps

  // Load initial events via REST, then stream via WebSocket
  useEffect(() => {
    if (!agentId) return;

    // Load initial batch
    loadRecent(agentId);

    // Subscribe to real-time events via WebSocket
    const unsub = subscribeTopic('edr.events', (data) => {
      const ev = data as RecentEvent;
      if (!ev || !ev.id) return;
      eventsRef.current = [ev, ...eventsRef.current].slice(0, MAX_EVENTS);
      setEvents([...eventsRef.current]);
    });

    return () => unsub();
  }, [agentId, loadRecent]);

  const handleKillProcess = async (pid: number) => {
    setKillConfirm(null);
    setKillingPids((prev) => new Set(prev).add(pid));
    try {
      await api.post('/edr/kill-process', { pid, agent_id: agentId });
      setKilledPids((prev) => new Set(prev).add(pid));
    } catch (e) {
      console.error('kill process failed', e);
    } finally {
      setKillingPids((prev) => {
        const next = new Set(prev);
        next.delete(pid);
        return next;
      });
    }
  };

  const handleContainChain = async (chain: ChainMatch) => {
    const pid = chain.ai_analysis?.pid;
    if (!pid) return;
    setContainingChains((prev) => new Set(prev).add(chain.id));
    try {
      await api.post('/edr/kill-process', { pid, agent_id: agentId, contain: true });
      setContainedChains((prev) => new Set(prev).add(chain.id));
    } catch (e) {
      console.error('contain chain failed', e);
    } finally {
      setContainingChains((prev) => {
        const next = new Set(prev);
        next.delete(chain.id);
        return next;
      });
    }
  };

  const filteredEvents = events.filter((e) => {
    if (filterCategory === 'All') return true;
    if (filterCategory === 'Suspicious') {
      return e.severity === 'medium' || e.severity === 'high' || e.severity === 'critical';
    }
    return e.category?.toLowerCase() === filterCategory.toLowerCase()
      || e.details?.kind?.toLowerCase().includes(filterCategory.toLowerCase());
  });

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
        {agents.some((a) => a.id === 'aegis-host-monitor') && (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs font-medium text-emerald-400">Host protected</span>
          </div>
        )}
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
                <div className="flex items-center gap-3 shrink-0">
                  {c.ai_analysis?.pid && (
                    containedChains.has(c.id) ? (
                      <span className="flex items-center gap-1.5 text-xs font-medium text-emerald-400">
                        <CheckCircle className="w-3.5 h-3.5" />
                        Contained
                      </span>
                    ) : (
                      <button
                        onClick={() => handleContainChain(c)}
                        disabled={containingChains.has(c.id)}
                        className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-red-500/15 border border-red-500/30 text-red-400 text-xs font-medium hover:bg-red-500/25 disabled:opacity-50"
                      >
                        <AlertTriangle className="w-3.5 h-3.5" />
                        {containingChains.has(c.id) ? 'Containing...' : 'Kill & Contain'}
                      </button>
                    )
                  )}
                  <time className="text-xs text-zinc-500 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {c.detected_at ? formatDate(c.detected_at) : '—'}
                  </time>
                </div>
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
                  {a.id === 'aegis-host-monitor' ? `${a.hostname} (Host Monitor)` : (a.hostname || a.id.slice(0, 12))} — {a.status}
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
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-cyan-400" />
            <h2 className="text-lg font-semibold text-zinc-100">Recent events</h2>
            {agentId && (
              <span className="text-xs text-zinc-500 ml-2">
                agent {agentId.slice(0, 8)}... · live
              </span>
            )}
          </div>
          {/* Category filter tabs */}
          <div className="flex items-center gap-1 bg-zinc-900/60 rounded-lg p-0.5 border border-white/[0.04]">
            {EVENT_CATEGORIES.map((cat) => (
              <button
                key={cat}
                onClick={() => setFilterCategory(cat)}
                className={cn(
                  'px-3 py-1 text-xs font-medium rounded-md transition-colors',
                  filterCategory === cat
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                    : 'text-zinc-500 hover:text-zinc-300',
                )}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>
        {!agentId ? (
          <p className="text-sm text-zinc-500 py-4">
            Waiting for host monitor to initialize. Process telemetry will appear shortly.
          </p>
        ) : filteredEvents.length === 0 ? (
          <div className="flex items-center gap-2 py-4">
            <Monitor className="w-4 h-4 text-cyan-400 animate-pulse" />
            <p className="text-sm text-zinc-400">
              {agentId === 'aegis-host-monitor'
                ? 'Host monitoring active — collecting process telemetry...'
                : 'No events in the last 15 minutes.'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead className="text-zinc-500 border-b border-white/[0.06]">
                <tr>
                  <th className="text-left py-2 pr-4">Time</th>
                  <th className="text-left py-2 pr-4">Kind</th>
                  <th className="text-left py-2 pr-4">PID</th>
                  <th className="text-left py-2 pr-4">Title</th>
                  <th className="text-left py-2 w-24">Action</th>
                </tr>
              </thead>
              <tbody className="text-zinc-300">
                {filteredEvents.slice(0, 100).map((e) => {
                  const isProcess = e.details?.kind === 'process_start';
                  const pid = e.details?.pid;
                  const isKilled = pid !== undefined && killedPids.has(pid);
                  const isKilling = pid !== undefined && killingPids.has(pid);
                  return (
                    <tr key={e.id} className="border-b border-white/[0.03]">
                      <td className="py-1 pr-4">
                        {new Date(e.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-1 pr-4 text-cyan-400">{e.details?.kind}</td>
                      <td className="py-1 pr-4">{pid ?? '-'}</td>
                      <td className="py-1 pr-4 truncate max-w-[300px]">{e.title}</td>
                      <td className="py-1">
                        {isProcess && pid !== undefined && (
                          isKilled ? (
                            <span className="text-emerald-400 text-[10px] flex items-center gap-1">
                              <CheckCircle className="w-3 h-3" /> Killed
                            </span>
                          ) : (
                            <button
                              onClick={() => setKillConfirm({ pid, name: e.details?.process_name || e.title })}
                              disabled={isKilling}
                              className="flex items-center gap-1 px-2 py-0.5 rounded bg-red-500/15 border border-red-500/30 text-red-400 text-[10px] font-medium hover:bg-red-500/25 disabled:opacity-50"
                            >
                              <AlertTriangle className="w-3 h-3" />
                              {isKilling ? '...' : 'Kill'}
                            </button>
                          )
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Kill confirmation modal */}
      {killConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#18181B] border border-white/[0.08] rounded-2xl p-6 max-w-sm w-full mx-4 shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 rounded-lg bg-red-500/15 border border-red-500/30">
                <AlertTriangle className="w-5 h-5 text-red-400" />
              </div>
              <h3 className="text-base font-semibold text-zinc-100">Kill Process</h3>
            </div>
            <p className="text-sm text-zinc-400 mb-1">
              Terminate PID <span className="font-mono text-zinc-200">{killConfirm.pid}</span>?
            </p>
            <p className="text-xs text-zinc-500 mb-6 font-mono truncate">
              {killConfirm.name}
            </p>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setKillConfirm(null)}
                className="px-4 py-1.5 rounded-lg border border-white/[0.08] text-zinc-400 text-sm hover:text-zinc-200 hover:border-white/[0.12]"
              >
                Cancel
              </button>
              <button
                onClick={() => handleKillProcess(killConfirm.pid)}
                className="px-4 py-1.5 rounded-lg bg-red-500/20 border border-red-500/40 text-red-400 text-sm font-medium hover:bg-red-500/30"
              >
                Kill Process
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
