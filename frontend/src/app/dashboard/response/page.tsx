'use client';

import { useState, useEffect } from 'react';
import { SecurityCheckIcon, Clock01Icon, FlashIcon } from 'hugeicons-react';
import { CheckCircle, ChevronDown, ChevronUp, Shield } from 'lucide-react';
import { Card, CardHeader, CardContent, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { StatusIndicator } from '@/components/shared/StatusIndicator';
import { LoadingState } from '@/components/shared/LoadingState';
import { api } from '@/lib/api';
import { cn, formatRelativeTime, formatDate } from '@/lib/utils';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';

interface IncidentItem {
  id: string;
  title: string;
  description: string;
  severity: string;
  status: string;
  source: string;
  mitre_technique: string | null;
  mitre_tactic: string | null;
  source_ip: string | null;
  detected_at: string;
}

interface ActionItem {
  id: string;
  incident_id: string;
  action_type: string;
  target: string;
  status: string;
  requires_approval: boolean;
  ai_reasoning: string | null;
  created_at: string;
}

const tooltipStyle = {
  backgroundColor: 'hsl(var(--card))',
  border: '1px solid hsl(var(--border))',
  borderRadius: '8px',
  color: 'hsl(var(--foreground))',
  fontSize: '12px',
  fontFamily: 'Azeret Mono, monospace',
  padding: '8px 12px',
};

const severityDotColor: Record<string, string> = {
  critical: 'bg-[#EF4444]',
  high: 'bg-[#F97316]',
  medium: 'bg-[#F59E0B]',
  low: 'bg-[#3B82F6]',
};

const TACTICS = ['Initial Access', 'Execution', 'Discovery', 'Defense Evasion', 'Lateral Movement'];

function heatmapCellColor(value: number): string {
  if (value === 0) return 'bg-muted/20';
  if (value === 1) return 'bg-[#22D3EE]/20';
  if (value === 2) return 'bg-[#22D3EE]/40';
  if (value === 3) return 'bg-[#22D3EE]/60';
  return 'bg-[#22D3EE]/80';
}

function getLast7DayLabels(): string[] {
  const labels: string[] = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    labels.push(d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
  }
  return labels;
}

function buildTacticsHeatmap(incidents: IncidentItem[]): { days: string[]; data: number[][] } {
  const days = getLast7DayLabels();
  const now = Date.now();
  const data: number[][] = TACTICS.map(() => new Array(7).fill(0));

  incidents.forEach((inc) => {
    if (!inc.mitre_tactic) return;
    const tacticIdx = TACTICS.findIndex(
      (t) => t.toLowerCase() === inc.mitre_tactic!.toLowerCase()
    );
    if (tacticIdx === -1) return;
    const diffDays = Math.floor((now - new Date(inc.detected_at).getTime()) / 86400000);
    const dayIdx = 6 - diffDays;
    if (dayIdx >= 0 && dayIdx < 7) {
      data[tacticIdx][dayIdx] += 1;
    }
  });

  return { days, data };
}

function buildStatusDistribution(incidents: IncidentItem[]): Array<Record<string, string | number>> {
  const days = getLast7DayLabels();
  const now = Date.now();

  const buckets: Record<string, { day: string; escalated: number; resolved: number; in_progress: number; open: number }> = {};
  days.forEach((d) => {
    buckets[d] = { day: d.split(' ')[1], escalated: 0, resolved: 0, in_progress: 0, open: 0 };
  });

  incidents.forEach((inc) => {
    const diffDays = Math.floor((now - new Date(inc.detected_at).getTime()) / 86400000);
    const dayIdx = 6 - diffDays;
    if (dayIdx < 0 || dayIdx >= 7) return;
    const dayKey = days[dayIdx];
    const bucket = buckets[dayKey];
    if (!bucket) return;
    if (inc.status === 'resolved' || inc.status === 'remediated') bucket.resolved += 1;
    else if (inc.status === 'investigating' || inc.status === 'contained') bucket.in_progress += 1;
    else if (inc.status === 'escalated') bucket.escalated += 1;
    else bucket.open += 1;
  });

  return Object.values(buckets);
}

export default function ResponsePage() {
  const [incidents, setIncidents] = useState<IncidentItem[]>([]);
  const [actions, setActions] = useState<ActionItem[]>([]);
  const [guardrails, setGuardrails] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState(true);
  const [expandedIncident, setExpandedIncident] = useState<string | null>(null);
  const [tab, setTab] = useState<string>('incidents');

  useEffect(() => {
    async function load() {
      try {
        const [inc, act, gr] = await Promise.allSettled([
          api.response.incidents(),
          api.response.actions(),
          api.response.guardrails(),
        ]);
        setIncidents(inc.status === 'fulfilled' ? inc.value : []);
        setActions(act.status === 'fulfilled' ? act.value : []);
        if (gr.status === 'fulfilled') {
          const raw = gr.value as Record<string, unknown>;
          const guardrailData = (raw.guardrails || raw) as Record<string, string | boolean>;
          const parsed: Record<string, boolean> = {};
          for (const [k, v] of Object.entries(guardrailData)) {
            if (typeof v === 'boolean') parsed[k] = v;
            else if (typeof v === 'string') parsed[k] = v === 'auto_approve';
          }
          setGuardrails(parsed);
        }
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const handleApprove = async (actionId: string) => {
    try {
      await api.response.approveAction(actionId);
    } catch {
      // best effort
    }
    setActions(actions.map((a) => a.id === actionId ? { ...a, status: 'approved' } : a));
  };

  const toggleGuardrail = async (key: string) => {
    const updated = { ...guardrails, [key]: !guardrails[key] };
    setGuardrails(updated);
    try {
      await api.response.updateGuardrails(updated);
    } catch {
      // best effort
    }
  };

  const pendingActions = actions.filter((a) => a.status === 'pending' && a.requires_approval);

  if (loading) return <LoadingState message="Loading incident response data..." />;

  const { days: heatmapDays, data: heatmapData } = buildTacticsHeatmap(incidents);
  const statusDistData = buildStatusDistribution(incidents);
  const hasIncidents = incidents.length > 0;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-[22px] sm:text-[28px] font-bold text-foreground tracking-tight">Incident Response</h1>
          <p className="text-sm text-muted-foreground mt-1 hidden sm:block">Autonomous threat analysis and response actions</p>
        </div>
        {pendingActions.length > 0 && (
          <Badge variant="outline" className="bg-[#F59E0B]/10 border-[#F59E0B]/20 text-[#F59E0B] shrink-0 px-3 sm:px-4 py-2 h-auto">
            <Clock01Icon size={16} />
            <span className="text-[12px] sm:text-[13px] font-medium">{pendingActions.length} pending</span>
          </Badge>
        )}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Threat Tactics Activity Heatmap */}
        <Card className="overflow-hidden rounded-xl py-0">
          <CardHeader className="border-b border-border px-4 sm:px-6 py-4">
            <CardTitle className="text-[13px] font-medium uppercase tracking-wider">Threat Tactics Activity</CardTitle>
            <CardDescription className="text-[11px] mt-0.5 hidden sm:block">MITRE ATT&CK tactic frequency over the past 7 days</CardDescription>
          </CardHeader>
          <CardContent className="p-4 sm:p-6 overflow-x-auto">
            {!hasIncidents ? (
              <div className="h-40 flex items-center justify-center">
                <p className="text-muted-foreground/50 text-[13px]">No data yet</p>
              </div>
            ) : (
              <>
                <div className="flex mb-2">
                  <div className="w-32 shrink-0" />
                  {heatmapDays.map((day) => (
                    <div key={day} className="flex-1 text-center text-[10px] text-muted-foreground/50 font-mono">{day.split(' ')[1]}</div>
                  ))}
                </div>
                {TACTICS.map((tactic, rowIdx) => (
                  <div key={tactic} className="flex items-center mb-1">
                    <div className="w-32 shrink-0 text-[11px] text-muted-foreground font-medium truncate pr-3">{tactic}</div>
                    {heatmapData[rowIdx].map((value, colIdx) => (
                      <div key={colIdx} className="flex-1 px-0.5">
                        <div
                          className={cn('h-7 rounded-md transition-colors', heatmapCellColor(value))}
                          title={`${tactic}: ${value} events on ${heatmapDays[colIdx]}`}
                        />
                      </div>
                    ))}
                  </div>
                ))}
                <div className="flex items-center gap-2 mt-4 justify-end">
                  <span className="text-[10px] text-muted-foreground/50">Less</span>
                  {[0, 1, 2, 3, 4].map((v) => (
                    <div key={v} className={cn('w-4 h-4 rounded', heatmapCellColor(v))} />
                  ))}
                  <span className="text-[10px] text-muted-foreground/50">More</span>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        {/* Response Status Distribution */}
        <Card className="overflow-hidden rounded-xl py-0">
          <CardHeader className="border-b border-border px-4 sm:px-6 py-4">
            <CardTitle className="text-[13px] font-medium uppercase tracking-wider">Response Status</CardTitle>
            <CardDescription className="text-[11px] mt-0.5 hidden sm:block">Incident outcomes by day of the week</CardDescription>
          </CardHeader>
          <CardContent className="p-4 sm:p-6 h-[200px] sm:h-[240px]">
            {!hasIncidents ? (
              <div className="h-full flex items-center justify-center">
                <p className="text-muted-foreground/50 text-[13px]">No data yet</p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={statusDistData} barCategoryGap={6}>
                  <XAxis
                    dataKey="day"
                    tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11, fontFamily: 'Azeret Mono' }}
                    axisLine={{ stroke: 'hsl(var(--border))' }}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11, fontFamily: 'Azeret Mono' }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'hsl(var(--muted) / 0.2)' }} />
                  <Legend
                    iconType="circle"
                    iconSize={6}
                    content={(props) => {
                      const { payload } = props as { payload?: Array<{ color: string; value: string }> };
                      if (!payload) return null;
                      return (
                        <div className="flex flex-wrap items-center justify-center gap-4 pt-2">
                          {payload.map((entry) => (
                            <div key={entry.value} className="flex items-center gap-1.5">
                              <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: entry.color }} />
                              <span style={{ fontSize: '11px', fontFamily: 'Azeret Mono', color: 'hsl(var(--muted-foreground))' }}>{entry.value}</span>
                            </div>
                          ))}
                        </div>
                      );
                    }}
                  />
                  <Bar dataKey="escalated" name="Escalated" stackId="a" fill="#22C55E" radius={[0, 0, 0, 0]} />
                  <Bar dataKey="resolved" name="Resolved" stackId="a" fill="#22D3EE" />
                  <Bar dataKey="in_progress" name="In Progress" stackId="a" fill="#A855F7" />
                  <Bar dataKey="open" name="Open" stackId="a" fill="#52525B" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Tab Section */}
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList variant="line">
          {[
            { id: 'incidents', label: 'Incidents', icon: SecurityCheckIcon, count: incidents.length },
            { id: 'actions', label: 'Response Actions', icon: FlashIcon, count: actions.length },
            { id: 'guardrails', label: 'Guardrails', icon: Shield },
          ].map((t) => (
            <TabsTrigger key={t.id} value={t.id}>
              <t.icon className="w-4 h-4" size={16} />
              {t.label}
              {t.count !== undefined && (
                <Badge variant="secondary" className="text-[11px] px-1.5 py-0.5 h-auto">{t.count}</Badge>
              )}
            </TabsTrigger>
          ))}
        </TabsList>

        {/* Incidents Tab */}
        <TabsContent value="incidents">
          <div className="space-y-3">
            {incidents.length === 0 ? (
              <Card className="rounded-xl p-12 text-center">
                <SecurityCheckIcon size={48} className="text-[#22C55E] mx-auto mb-3 opacity-50" />
                <p className="text-muted-foreground text-[13px]">No active incidents. Your perimeter is secure.</p>
              </Card>
            ) : (
              incidents.map((incident) => (
                <Card
                  key={incident.id}
                  className="overflow-hidden rounded-xl py-0 transition-all duration-200 hover:border-border/80"
                >
                  <button
                    onClick={() => setExpandedIncident(expandedIncident === incident.id ? null : incident.id)}
                    className="w-full flex items-center justify-between px-4 sm:px-6 py-4 text-left"
                  >
                    <div className="flex items-center gap-3 sm:gap-4 min-w-0">
                      <div className="mt-0.5 shrink-0">
                        <span className={cn('block w-2 h-2 rounded-full', severityDotColor[incident.severity] || 'bg-muted-foreground/50')} />
                      </div>
                      <div className="min-w-0">
                        <p className="text-[13px] font-medium text-foreground truncate">{incident.title}</p>
                        <div className="flex items-center gap-3 mt-1.5">
                          <StatusIndicator status={incident.status} label={incident.status} />
                          {incident.source_ip && (
                            <span className="text-[11px] text-muted-foreground font-mono">{incident.source_ip}</span>
                          )}
                          {incident.mitre_technique && (
                            <Badge variant="outline" className="text-[10px] text-[#A855F7] bg-[#A855F7]/10 border-[#A855F7]/20 px-1.5 py-0.5 h-auto font-mono font-medium">{incident.mitre_technique}</Badge>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 shrink-0 ml-4">
                      <span className="text-[11px] text-muted-foreground/50 font-mono tabular-nums">{formatRelativeTime(incident.detected_at)}</span>
                      {expandedIncident === incident.id ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                    </div>
                  </button>
                  {expandedIncident === incident.id && (
                    <div className="px-4 sm:px-6 pb-5 border-t border-border pt-5 animate-fade-in">
                      <p className="text-[13px] text-muted-foreground mb-4">{incident.description}</p>
                      <div className="grid grid-cols-2 gap-3">
                        {[
                          { label: 'Source', value: incident.source, capitalize: true },
                          { label: 'MITRE Tactic', value: incident.mitre_tactic || 'N/A' },
                          { label: 'Detected', value: formatDate(incident.detected_at) },
                          { label: 'Source IP', value: incident.source_ip || 'Internal', mono: true },
                        ].map((item) => (
                          <div key={item.label} className="bg-background border border-border rounded-xl p-3">
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground/50 font-medium mb-1">{item.label}</p>
                            <p className={cn('text-[13px] text-foreground font-medium', item.capitalize && 'capitalize', item.mono && 'font-mono')}>{item.value}</p>
                          </div>
                        ))}
                      </div>
                      {actions.filter((a) => a.incident_id === incident.id).length > 0 && (
                        <div className="mt-4">
                          <p className="text-[10px] font-medium text-muted-foreground/50 uppercase tracking-wider mb-2">Response Actions</p>
                          <div className="space-y-2">
                            {actions.filter((a) => a.incident_id === incident.id).map((action) => (
                              <div key={action.id} className="flex items-center justify-between bg-background border border-border p-3 rounded-xl">
                                <div className="flex items-center gap-3">
                                  <StatusIndicator status={action.status} />
                                  <div>
                                    <p className="text-[13px] text-foreground capitalize">{action.action_type.replace(/_/g, ' ')}</p>
                                    <p className="text-[11px] text-muted-foreground font-mono">{action.target}</p>
                                  </div>
                                </div>
                                {action.status === 'pending' && action.requires_approval && (
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => handleApprove(action.id)}
                                    className="text-[11px] bg-[#22C55E]/10 text-[#22C55E] hover:bg-[#22C55E]/20 font-medium"
                                  >
                                    Approve
                                  </Button>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </Card>
              ))
            )}
          </div>
        </TabsContent>

        {/* Actions Tab */}
        <TabsContent value="actions">
          <div className="space-y-3">
            {actions.length === 0 ? (
              <Card className="rounded-xl p-12 text-center">
                <FlashIcon size={48} className="text-muted-foreground/50 mx-auto mb-3 opacity-50" />
                <p className="text-muted-foreground text-[13px]">No response actions recorded yet.</p>
              </Card>
            ) : (
              actions.map((action) => (
                <Card key={action.id} className="rounded-xl p-4 py-4 hover:border-border/80 transition-colors">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <StatusIndicator status={action.status} />
                      <span className="text-[13px] font-medium text-foreground capitalize">{action.action_type.replace(/_/g, ' ')}</span>
                      <Badge variant="outline" className="text-[11px] font-mono text-[#22D3EE] bg-[#22D3EE]/10 border-[#22D3EE]/20">{action.target}</Badge>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-[11px] text-muted-foreground/50 font-mono tabular-nums">{formatRelativeTime(action.created_at)}</span>
                      {action.status === 'pending' && action.requires_approval && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleApprove(action.id)}
                          className="text-[11px] bg-[#22C55E]/10 text-[#22C55E] hover:bg-[#22C55E]/20 font-medium"
                        >
                          <CheckCircle className="w-3 h-3" />
                          Approve
                        </Button>
                      )}
                    </div>
                  </div>
                  {action.ai_reasoning && (
                    <div className="bg-background border border-border rounded-xl p-4">
                      <p className="text-[10px] text-muted-foreground/50 mb-1 font-medium uppercase tracking-wider">AI Reasoning</p>
                      <p className="text-[13px] text-muted-foreground">{action.ai_reasoning}</p>
                    </div>
                  )}
                </Card>
              ))
            )}
          </div>
        </TabsContent>

        {/* Guardrails Tab */}
        <TabsContent value="guardrails">
          <Card className="overflow-hidden rounded-xl py-0">
            <CardHeader className="border-b border-border px-6 py-4">
              <CardTitle className="text-[13px] font-medium uppercase tracking-wider">Autonomous Response Configuration</CardTitle>
              <CardDescription className="text-[11px] mt-0.5">Control which actions AEGIS can execute automatically without human approval</CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              {Object.keys(guardrails).length === 0 ? (
                <div className="p-12 text-center">
                  <Shield className="w-12 h-12 text-muted-foreground/50 mx-auto mb-3 opacity-50" />
                  <p className="text-muted-foreground text-[13px]">No guardrails configured yet.</p>
                </div>
              ) : (
                <div>
                  {Object.entries(guardrails).map(([key, enabled], index) => (
                    <div key={key} className={cn('flex items-center justify-between px-6 py-4', index < Object.entries(guardrails).length - 1 && 'border-b border-border/50')}>
                      <div>
                        <p className="text-[13px] font-medium text-foreground capitalize">{key.replace(/^auto_/, '').replace(/_/g, ' ')}</p>
                        <p className="text-[11px] text-muted-foreground mt-0.5">
                          {enabled ? 'Autonomous \u2014 executes immediately (Sigma rules + playbooks, no AI required)' : 'Manual \u2014 requires admin approval before execution'}
                        </p>
                      </div>
                      <button
                        onClick={() => toggleGuardrail(key)}
                        className={cn(
                          'relative w-11 h-6 rounded-full transition-colors duration-200',
                          enabled ? 'bg-[#22D3EE]' : 'bg-muted'
                        )}
                      >
                        <span
                          className={cn(
                            'absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform duration-200',
                            enabled && 'translate-x-5'
                          )}
                        />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
