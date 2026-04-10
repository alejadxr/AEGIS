'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { AlertTriangle, CheckCircle, GitBranch, Zap, Clock, Monitor } from 'lucide-react';
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

const sevDot: Record<string, string> = {
  critical: 'bg-[#EF4444]',
  high: 'bg-[#F97316]',
  medium: 'bg-[#F59E0B]',
  low: 'bg-[#3B82F6]',
  info: 'bg-[#737373]',
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

  useEffect(() => {
    (async () => {
      setLoading(true);
      await loadChains();

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
          const hostAgent = nodeList.find((a) => a.id === 'aegis-host-monitor');
          setAgentId(hostAgent ? hostAgent.id : nodeList[0].id);
        }
      } catch (e) {
        console.error('agents list load failed', e);
      }

      setLoading(false);
    })();
  }, [loadChains]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!agentId) return;

    loadRecent(agentId);

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
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-[22px] sm:text-[28px] font-bold text-[#E5E5E5] tracking-tight">EDR / XDR Core</h1>
          <p className="text-sm text-[#737373] mt-1 hidden sm:block">Process telemetry, attack chain detection, and live event stream</p>
        </div>
        {agents.some((a) => a.id === 'aegis-host-monitor') && (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#22C55E]/10 border border-[#22C55E]/20">
            <span className="w-1.5 h-1.5 rounded-full bg-[#22C55E] animate-pulse" />
            <span className="text-[11px] font-medium text-[#22C55E]">Host protected</span>
          </div>
        )}
      </div>

      {/* Attack chain incidents */}
      <div className="bg-[#0A0A0A] border border-white/[0.04] rounded-xl overflow-hidden">
        <div className="px-4 sm:px-6 py-4 border-b border-white/[0.04] flex items-center gap-2">
          <Zap className="w-4 h-4 text-[#F97316]" />
          <span className="text-[13px] font-medium text-[#E5E5E5] uppercase tracking-wider">Attack Chain Matches</span>
          <span className="text-[11px] text-[#737373] ml-2">{chains.length} recent</span>
        </div>
        <div className="p-4 sm:p-6">
          {chains.length === 0 ? (
            <p className="text-[13px] text-[#737373] py-4">
              No chain-rule matches yet. Telemetry will populate this list as agents report process starts.
            </p>
          ) : (
            <div className="space-y-2">
              {chains.map((c) => (
                <div
                  key={c.id}
                  className="border border-white/[0.04] rounded-xl p-4 flex items-start justify-between gap-4 hover:border-white/[0.08] transition-colors"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={cn('w-2 h-2 rounded-full shrink-0', sevDot[c.severity] ?? sevDot.info)} />
                      <span className="uppercase text-[10px] font-mono tracking-wider text-[#737373]">
                        {c.severity}
                      </span>
                      {c.mitre_technique && (
                        <span className="text-[10px] font-mono bg-white/[0.04] text-[#A855F7] px-2 py-0.5 rounded">
                          {c.mitre_technique}
                        </span>
                      )}
                    </div>
                    <h3 className="text-[13px] font-medium text-[#E5E5E5] mt-1 truncate">
                      {c.title}
                    </h3>
                    {c.ai_analysis?.chain && (
                      <p className="text-[11px] font-mono text-[#737373] mt-1 truncate">
                        {c.ai_analysis.chain.join(' \u2192 ')}
                      </p>
                    )}
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    {c.ai_analysis?.pid && (
                      containedChains.has(c.id) ? (
                        <span className="flex items-center gap-1.5 text-[11px] font-medium text-[#22C55E]">
                          <CheckCircle className="w-3.5 h-3.5" />
                          Contained
                        </span>
                      ) : (
                        <button
                          onClick={() => handleContainChain(c)}
                          disabled={containingChains.has(c.id)}
                          className="flex items-center gap-1.5 px-3 py-1 rounded-lg text-[#EF4444] text-[11px] font-medium border border-white/[0.04] hover:bg-[#EF4444]/10 disabled:opacity-50 transition-colors"
                        >
                          <AlertTriangle className="w-3.5 h-3.5" />
                          {containingChains.has(c.id) ? 'Containing...' : 'Kill & Contain'}
                        </button>
                      )
                    )}
                    <time className="text-[11px] text-[#525252] flex items-center gap-1 font-mono">
                      <Clock className="w-3 h-3" />
                      {c.detected_at ? formatDate(c.detected_at) : '\u2014'}
                    </time>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Process tree viewer */}
      <div className="bg-[#0A0A0A] border border-white/[0.04] rounded-xl overflow-hidden">
        <div className="px-4 sm:px-6 py-4 border-b border-white/[0.04] flex items-center gap-2">
          <GitBranch className="w-4 h-4 text-[#22D3EE]" />
          <span className="text-[13px] font-medium text-[#E5E5E5] uppercase tracking-wider">Process Tree</span>
        </div>
        <div className="p-4 sm:p-6">
          <div className="flex flex-wrap items-end gap-3 mb-4">
            <div>
              <label className="block text-[10px] text-[#737373] uppercase tracking-wider font-medium mb-1">Agent</label>
              <select
                value={agentId}
                onChange={(e) => setAgentId(e.target.value)}
                className="bg-[#09090B] border border-white/[0.04] rounded-lg px-3 py-1.5 text-sm text-[#E5E5E5] w-80 font-mono focus:outline-none focus:border-[#22D3EE]/30"
              >
                {agents.length === 0 && <option value="">No agents enrolled</option>}
                {agents.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.id === 'aegis-host-monitor' ? `${a.hostname} (Host Monitor)` : (a.hostname || a.id.slice(0, 12))} \u2014 {a.status}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-[10px] text-[#737373] uppercase tracking-wider font-medium mb-1">PID</label>
              <input
                type="text"
                value={pidQuery}
                onChange={(e) => setPidQuery(e.target.value)}
                placeholder="1234"
                className="bg-[#09090B] border border-white/[0.04] rounded-lg px-3 py-1.5 text-sm text-[#E5E5E5] w-28 font-mono focus:outline-none focus:border-[#22D3EE]/30"
              />
            </div>
            <button
              onClick={loadTree}
              className="px-4 py-1.5 rounded-lg text-[#22D3EE] text-[13px] border border-white/[0.04] hover:bg-white/[0.04] transition-colors"
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
            <p className="text-[13px] text-[#737373] py-4">
              Enter an agent ID and PID above to reconstruct the process tree.
            </p>
          )}
        </div>
      </div>

      {/* Live event stream */}
      <div className="bg-[#0A0A0A] border border-white/[0.04] rounded-xl overflow-hidden">
        <div className="px-4 sm:px-6 py-4 border-b border-white/[0.04] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-[#22D3EE]" />
            <span className="text-[13px] font-medium text-[#E5E5E5] uppercase tracking-wider">Recent Events</span>
            {agentId && (
              <span className="text-[11px] text-[#737373] ml-2 font-mono">
                agent {agentId.slice(0, 8)}... \u00B7 live
              </span>
            )}
          </div>
          <div className="flex items-center gap-1 bg-[#09090B] rounded-lg p-0.5 border border-white/[0.04]">
            {EVENT_CATEGORIES.map((cat) => (
              <button
                key={cat}
                onClick={() => setFilterCategory(cat)}
                className={cn(
                  'px-3 py-1 text-[11px] font-medium rounded-md transition-colors',
                  filterCategory === cat
                    ? 'bg-[#22D3EE]/10 text-[#22D3EE]'
                    : 'text-[#737373] hover:text-[#E5E5E5]',
                )}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>
        <div className="p-4 sm:p-6">
          {!agentId ? (
            <p className="text-[13px] text-[#737373] py-4">
              Waiting for host monitor to initialize. Process telemetry will appear shortly.
            </p>
          ) : filteredEvents.length === 0 ? (
            <div className="flex items-center gap-2 py-4">
              <Monitor className="w-4 h-4 text-[#22D3EE] animate-pulse" />
              <p className="text-[13px] text-[#737373]">
                {agentId === 'aegis-host-monitor'
                  ? 'Host monitoring active \u2014 collecting process telemetry...'
                  : 'No events in the last 15 minutes.'}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-[11px] font-mono">
                <thead className="text-[#737373] border-b border-white/[0.04]">
                  <tr>
                    <th className="text-left py-2 pr-4 font-medium">Time</th>
                    <th className="text-left py-2 pr-4 font-medium">Kind</th>
                    <th className="text-left py-2 pr-4 font-medium">PID</th>
                    <th className="text-left py-2 pr-4 font-medium">Title</th>
                    <th className="text-left py-2 w-24 font-medium">Action</th>
                  </tr>
                </thead>
                <tbody className="text-[#E5E5E5]">
                  {filteredEvents.slice(0, 100).map((e) => {
                    const isProcess = e.details?.kind === 'process_start';
                    const pid = e.details?.pid;
                    const isKilled = pid !== undefined && killedPids.has(pid);
                    const isKilling = pid !== undefined && killingPids.has(pid);
                    return (
                      <tr key={e.id} className="border-b border-white/[0.02]">
                        <td className="py-1.5 pr-4 text-[#737373]">
                          {new Date(e.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-1.5 pr-4 text-[#22D3EE]">{e.details?.kind}</td>
                        <td className="py-1.5 pr-4">{pid ?? '-'}</td>
                        <td className="py-1.5 pr-4 truncate max-w-[300px]">{e.title}</td>
                        <td className="py-1.5">
                          {isProcess && pid !== undefined && (
                            isKilled ? (
                              <span className="text-[#22C55E] text-[10px] flex items-center gap-1">
                                <CheckCircle className="w-3 h-3" /> Killed
                              </span>
                            ) : (
                              <button
                                onClick={() => setKillConfirm({ pid, name: e.details?.process_name || e.title })}
                                disabled={isKilling}
                                className="flex items-center gap-1 px-2 py-0.5 rounded text-[#EF4444] text-[10px] font-medium border border-white/[0.04] hover:bg-[#EF4444]/10 disabled:opacity-50 transition-colors"
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
        </div>
      </div>

      {/* Kill confirmation modal */}
      {killConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0A0A0A] border border-white/[0.04] rounded-xl p-6 max-w-sm w-full mx-4">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 rounded-lg bg-[#EF4444]/10 border border-[#EF4444]/20">
                <AlertTriangle className="w-5 h-5 text-[#EF4444]" />
              </div>
              <h3 className="text-[14px] font-medium text-[#E5E5E5]">Kill Process</h3>
            </div>
            <p className="text-[13px] text-[#737373] mb-1">
              Terminate PID <span className="font-mono text-[#E5E5E5]">{killConfirm.pid}</span>?
            </p>
            <p className="text-[11px] text-[#525252] mb-6 font-mono truncate">
              {killConfirm.name}
            </p>
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => setKillConfirm(null)}
                className="px-4 py-1.5 rounded-lg border border-white/[0.04] text-[#737373] text-[13px] hover:text-[#E5E5E5] hover:border-white/[0.08] transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => handleKillProcess(killConfirm.pid)}
                className="px-4 py-1.5 rounded-lg text-[#EF4444] text-[13px] font-medium border border-white/[0.04] hover:bg-[#EF4444]/10 transition-colors"
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
