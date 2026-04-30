'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { AlertTriangle, CheckCircle, GitBranch, Zap, Clock, Monitor } from 'lucide-react';
import { api } from '@/lib/api';
import { subscribeTopic } from '@/lib/ws';
import { cn, formatDate } from '@/lib/utils';
import { LoadingState } from '@/components/shared/LoadingState';
import { ProcessTree, ProcessTreeNode } from '@/components/edr/ProcessTree';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Input } from '@/components/ui/input';

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
  critical: 'bg-[var(--danger)]',
  high: 'bg-[var(--brand-accent)]',
  medium: 'bg-[var(--warning)]',
  low: 'bg-[var(--info)]',
  info: 'bg-muted-foreground',
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
          <h1 className="text-[22px] sm:text-[28px] font-bold text-foreground tracking-tight">EDR / XDR Core</h1>
          <p className="text-sm text-muted-foreground mt-1 hidden sm:block">Process telemetry, attack chain detection, and live event stream</p>
        </div>
        {agents.some((a) => a.id === 'aegis-host-monitor') && (
          <Badge variant="outline" className="bg-[var(--success)]/10 border-[var(--success)]/20 text-[var(--success)] gap-1.5 px-3 py-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--success)] animate-pulse" />
            Host protected
          </Badge>
        )}
      </div>

      {/* Attack chain incidents */}
      <Card className="rounded-xl">
        <CardHeader className="border-b border-border px-4 sm:px-6 py-4">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-[var(--brand-accent)]" />
            <CardTitle className="text-[13px] font-medium uppercase tracking-wider">Attack Chain Matches</CardTitle>
            <span className="text-[11px] text-muted-foreground ml-2">{chains.length} recent</span>
          </div>
        </CardHeader>
        <CardContent className="p-4 sm:p-6">
          {chains.length === 0 ? (
            <p className="text-[13px] text-muted-foreground py-4">
              No chain-rule matches yet. Telemetry will populate this list as agents report process starts.
            </p>
          ) : (
            <div className="space-y-2">
              {chains.map((c) => (
                <div
                  key={c.id}
                  className="border border-border rounded-xl p-4 flex items-start justify-between gap-4 hover:border-foreground/10 transition-colors"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={cn('w-2 h-2 rounded-full shrink-0', sevDot[c.severity] ?? sevDot.info)} />
                      <span className="uppercase text-[10px] font-mono tracking-wider text-muted-foreground">
                        {c.severity}
                      </span>
                      {c.mitre_technique && (
                        <Badge variant="secondary" className="text-[10px] font-mono text-[var(--chart-5)] px-2 py-0.5">
                          {c.mitre_technique}
                        </Badge>
                      )}
                    </div>
                    <h3 className="text-[13px] font-medium text-foreground mt-1 truncate">
                      {c.title}
                    </h3>
                    {c.ai_analysis?.chain && (
                      <p className="text-[11px] font-mono text-muted-foreground mt-1 truncate">
                        {c.ai_analysis.chain.join(' \u2192 ')}
                      </p>
                    )}
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    {c.ai_analysis?.pid && (
                      containedChains.has(c.id) ? (
                        <span className="flex items-center gap-1.5 text-[11px] font-medium text-[var(--success)]">
                          <CheckCircle className="w-3.5 h-3.5" />
                          Contained
                        </span>
                      ) : (
                        <Button
                          variant="destructive"
                          size="sm"
                          onClick={() => handleContainChain(c)}
                          disabled={containingChains.has(c.id)}
                          className="gap-1.5 text-[11px]"
                        >
                          <AlertTriangle className="w-3.5 h-3.5" />
                          {containingChains.has(c.id) ? 'Containing...' : 'Kill & Contain'}
                        </Button>
                      )
                    )}
                    <time className="text-[11px] text-muted-foreground/60 flex items-center gap-1 font-mono">
                      <Clock className="w-3 h-3" />
                      {c.detected_at ? formatDate(c.detected_at) : '\u2014'}
                    </time>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Process tree viewer */}
      <Card className="rounded-xl">
        <CardHeader className="border-b border-border px-4 sm:px-6 py-4">
          <div className="flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-[var(--brand)]" />
            <CardTitle className="text-[13px] font-medium uppercase tracking-wider">Process Tree</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="p-4 sm:p-6">
          <div className="flex flex-wrap items-end gap-3 mb-4">
            <div>
              <label className="block text-[10px] text-muted-foreground uppercase tracking-wider font-medium mb-1">Agent</label>
              <select
                value={agentId}
                onChange={(e) => setAgentId(e.target.value)}
                className="bg-background border border-border rounded-lg px-3 py-1.5 text-sm text-foreground w-80 font-mono focus:outline-none focus:border-[var(--brand)]/30"
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
              <label className="block text-[10px] text-muted-foreground uppercase tracking-wider font-medium mb-1">PID</label>
              <Input
                type="text"
                value={pidQuery}
                onChange={(e) => setPidQuery(e.target.value)}
                placeholder="1234"
                className="w-28 font-mono"
              />
            </div>
            <Button variant="outline" onClick={loadTree} className="text-[var(--brand)]">
              Load tree
            </Button>
          </div>

          {tree ? (
            <ProcessTree
              anchor={tree.anchor}
              ancestors={tree.ancestors}
              descendants={tree.descendants}
            />
          ) : (
            <p className="text-[13px] text-muted-foreground py-4">
              Enter an agent ID and PID above to reconstruct the process tree.
            </p>
          )}
        </CardContent>
      </Card>

      {/* Live event stream */}
      <Card className="rounded-xl">
        <CardHeader className="border-b border-border px-4 sm:px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4 text-[var(--brand)]" />
              <CardTitle className="text-[13px] font-medium uppercase tracking-wider">Recent Events</CardTitle>
              {agentId && (
                <span className="text-[11px] text-muted-foreground ml-2 font-mono">
                  agent {agentId.slice(0, 8)}... · live
                </span>
              )}
            </div>
            <div className="flex items-center gap-1 bg-background rounded-lg p-0.5 border border-border">
              {EVENT_CATEGORIES.map((cat) => (
                <button
                  key={cat}
                  onClick={() => setFilterCategory(cat)}
                  className={cn(
                    'px-3 py-1 text-[11px] font-medium rounded-md transition-colors',
                    filterCategory === cat
                      ? 'bg-[var(--brand)]/10 text-[var(--brand)]'
                      : 'text-muted-foreground hover:text-foreground',
                  )}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-4 sm:p-6">
          {!agentId ? (
            <p className="text-[13px] text-muted-foreground py-4">
              Waiting for host monitor to initialize. Process telemetry will appear shortly.
            </p>
          ) : filteredEvents.length === 0 ? (
            <div className="flex items-center gap-2 py-4">
              <Monitor className="w-4 h-4 text-[var(--brand)] animate-pulse" />
              <p className="text-[13px] text-muted-foreground">
                {agentId === 'aegis-host-monitor'
                  ? 'Host monitoring active \u2014 collecting process telemetry...'
                  : 'No events in the last 15 minutes.'}
              </p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-[11px] font-mono">Time</TableHead>
                  <TableHead className="text-[11px] font-mono">Kind</TableHead>
                  <TableHead className="text-[11px] font-mono">PID</TableHead>
                  <TableHead className="text-[11px] font-mono">Title</TableHead>
                  <TableHead className="text-[11px] font-mono w-24">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredEvents.slice(0, 100).map((e) => {
                  const isProcess = e.details?.kind === 'process_start';
                  const pid = e.details?.pid;
                  const isKilled = pid !== undefined && killedPids.has(pid);
                  const isKilling = pid !== undefined && killingPids.has(pid);
                  return (
                    <TableRow key={e.id}>
                      <TableCell className="text-[11px] font-mono text-muted-foreground">
                        {new Date(e.timestamp).toLocaleTimeString()}
                      </TableCell>
                      <TableCell className="text-[11px] font-mono text-[var(--brand)]">{e.details?.kind}</TableCell>
                      <TableCell className="text-[11px] font-mono">{pid ?? '-'}</TableCell>
                      <TableCell className="text-[11px] font-mono truncate max-w-[300px]">{e.title}</TableCell>
                      <TableCell className="text-[11px]">
                        {isProcess && pid !== undefined && (
                          isKilled ? (
                            <span className="text-[var(--success)] text-[10px] flex items-center gap-1">
                              <CheckCircle className="w-3 h-3" /> Killed
                            </span>
                          ) : (
                            <Button
                              variant="destructive"
                              size="xs"
                              onClick={() => setKillConfirm({ pid, name: e.details?.process_name || e.title })}
                              disabled={isKilling}
                              className="gap-1 text-[10px]"
                            >
                              <AlertTriangle className="w-3 h-3" />
                              {isKilling ? '...' : 'Kill'}
                            </Button>
                          )
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Kill confirmation modal */}
      {killConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <Card className="max-w-sm w-full mx-4 rounded-xl">
            <CardContent className="p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 rounded-lg bg-[var(--danger)]/10 border border-[var(--danger)]/20">
                  <AlertTriangle className="w-5 h-5 text-[var(--danger)]" />
                </div>
                <h3 className="text-[14px] font-medium text-foreground">Kill Process</h3>
              </div>
              <p className="text-[13px] text-muted-foreground mb-1">
                Terminate PID <span className="font-mono text-foreground">{killConfirm.pid}</span>?
              </p>
              <p className="text-[11px] text-muted-foreground/60 mb-6 font-mono truncate">
                {killConfirm.name}
              </p>
              <div className="flex gap-3 justify-end">
                <Button variant="outline" onClick={() => setKillConfirm(null)}>
                  Cancel
                </Button>
                <Button variant="destructive" onClick={() => handleKillProcess(killConfirm.pid)}>
                  Kill Process
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
