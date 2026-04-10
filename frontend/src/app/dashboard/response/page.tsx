'use client';

import { useState, useEffect } from 'react';
import { SecurityCheckIcon, Clock01Icon, FlashIcon } from 'hugeicons-react';
import { CheckCircle, ChevronDown, ChevronUp, Shield } from 'lucide-react';
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
  backgroundColor: '#0A0A0A',
  border: '1px solid rgba(255,255,255,0.04)',
  borderRadius: '8px',
  color: '#E5E5E5',
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
  if (value === 0) return 'bg-white/[0.02]';
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
  const [tab, setTab] = useState<'incidents' | 'actions' | 'guardrails'>('incidents');

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
          <h1 className="text-[22px] sm:text-[28px] font-bold text-[#E5E5E5] tracking-tight">Incident Response</h1>
          <p className="text-sm text-[#737373] mt-1 hidden sm:block">Autonomous threat analysis and response actions</p>
        </div>
        {pendingActions.length > 0 && (
          <div className="flex items-center gap-2 bg-[#F59E0B]/10 border border-[#F59E0B]/20 rounded-xl px-3 sm:px-4 py-2 shrink-0">
            <Clock01Icon size={16} className="text-[#F59E0B]" />
            <span className="text-[12px] sm:text-[13px] font-medium text-[#F59E0B]">{pendingActions.length} pending</span>
          </div>
        )}
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Threat Tactics Activity Heatmap */}
        <div className="bg-[#0A0A0A] border border-white/[0.04] rounded-xl overflow-hidden">
          <div className="px-4 sm:px-6 py-4 border-b border-white/[0.04]">
            <span className="text-[13px] font-medium text-[#E5E5E5] uppercase tracking-wider">Threat Tactics Activity</span>
            <p className="text-[11px] text-[#737373] mt-0.5 hidden sm:block">MITRE ATT&CK tactic frequency over the past 7 days</p>
          </div>
          <div className="p-4 sm:p-6 overflow-x-auto">
            {!hasIncidents ? (
              <div className="h-40 flex items-center justify-center">
                <p className="text-[#525252] text-[13px]">No data yet</p>
              </div>
            ) : (
              <>
                <div className="flex mb-2">
                  <div className="w-32 shrink-0" />
                  {heatmapDays.map((day) => (
                    <div key={day} className="flex-1 text-center text-[10px] text-[#525252] font-mono">{day.split(' ')[1]}</div>
                  ))}
                </div>
                {TACTICS.map((tactic, rowIdx) => (
                  <div key={tactic} className="flex items-center mb-1">
                    <div className="w-32 shrink-0 text-[11px] text-[#737373] font-medium truncate pr-3">{tactic}</div>
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
                  <span className="text-[10px] text-[#525252]">Less</span>
                  {[0, 1, 2, 3, 4].map((v) => (
                    <div key={v} className={cn('w-4 h-4 rounded', heatmapCellColor(v))} />
                  ))}
                  <span className="text-[10px] text-[#525252]">More</span>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Response Status Distribution */}
        <div className="bg-[#0A0A0A] border border-white/[0.04] rounded-xl overflow-hidden">
          <div className="px-4 sm:px-6 py-4 border-b border-white/[0.04]">
            <span className="text-[13px] font-medium text-[#E5E5E5] uppercase tracking-wider">Response Status</span>
            <p className="text-[11px] text-[#737373] mt-0.5 hidden sm:block">Incident outcomes by day of the week</p>
          </div>
          <div className="p-4 sm:p-6 h-[200px] sm:h-[240px]">
            {!hasIncidents ? (
              <div className="h-full flex items-center justify-center">
                <p className="text-[#525252] text-[13px]">No data yet</p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={statusDistData} barCategoryGap={6}>
                  <XAxis
                    dataKey="day"
                    tick={{ fill: '#737373', fontSize: 11, fontFamily: 'Azeret Mono' }}
                    axisLine={{ stroke: 'rgba(255,255,255,0.04)' }}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fill: '#737373', fontSize: 11, fontFamily: 'Azeret Mono' }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ fill: 'rgba(255,255,255,0.02)' }} />
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
                              <span style={{ fontSize: '11px', fontFamily: 'Azeret Mono', color: '#737373' }}>{entry.value}</span>
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
          </div>
        </div>
      </div>

      {/* Tab Bar */}
      <div className="flex items-center gap-4 border-b border-white/[0.04]">
        {[
          { id: 'incidents' as const, label: 'Incidents', icon: SecurityCheckIcon, count: incidents.length },
          { id: 'actions' as const, label: 'Response Actions', icon: FlashIcon, count: actions.length },
          { id: 'guardrails' as const, label: 'Guardrails', icon: Shield },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={cn(
              'pb-3 text-[13px] font-medium border-b-2 transition-colors -mb-px flex items-center gap-2',
              tab === t.id ? 'border-[#22D3EE] text-[#22D3EE]' : 'border-transparent text-[#737373] hover:text-[#E5E5E5]'
            )}
          >
            <t.icon className="w-4 h-4" size={16} />
            {t.label}
            {t.count !== undefined && (
              <span className="text-[11px] bg-white/[0.04] px-1.5 py-0.5 rounded-md">{t.count}</span>
            )}
          </button>
        ))}
      </div>

      {/* Incidents Tab */}
      {tab === 'incidents' && (
        <div className="space-y-3">
          {incidents.length === 0 ? (
            <div className="bg-[#0A0A0A] border border-white/[0.04] rounded-xl p-12 text-center">
              <SecurityCheckIcon size={48} className="text-[#22C55E] mx-auto mb-3 opacity-50" />
              <p className="text-[#737373] text-[13px]">No active incidents. Your perimeter is secure.</p>
            </div>
          ) : (
            incidents.map((incident) => (
              <div
                key={incident.id}
                className="bg-[#0A0A0A] border border-white/[0.04] rounded-xl overflow-hidden transition-all duration-200 hover:border-white/[0.08]"
              >
                <button
                  onClick={() => setExpandedIncident(expandedIncident === incident.id ? null : incident.id)}
                  className="w-full flex items-center justify-between px-4 sm:px-6 py-4 text-left"
                >
                  <div className="flex items-center gap-3 sm:gap-4 min-w-0">
                    <div className="mt-0.5 shrink-0">
                      <span className={cn('block w-2 h-2 rounded-full', severityDotColor[incident.severity] || 'bg-[#525252]')} />
                    </div>
                    <div className="min-w-0">
                      <p className="text-[13px] font-medium text-[#E5E5E5] truncate">{incident.title}</p>
                      <div className="flex items-center gap-3 mt-1.5">
                        <StatusIndicator status={incident.status} label={incident.status} />
                        {incident.source_ip && (
                          <span className="text-[11px] text-[#737373] font-mono">{incident.source_ip}</span>
                        )}
                        {incident.mitre_technique && (
                          <span className="text-[10px] text-[#A855F7] bg-[#A855F7]/10 px-1.5 py-0.5 rounded-md font-mono font-medium">{incident.mitre_technique}</span>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0 ml-4">
                    <span className="text-[11px] text-[#525252] font-mono tabular-nums">{formatRelativeTime(incident.detected_at)}</span>
                    {expandedIncident === incident.id ? <ChevronUp className="w-4 h-4 text-[#737373]" /> : <ChevronDown className="w-4 h-4 text-[#737373]" />}
                  </div>
                </button>
                {expandedIncident === incident.id && (
                  <div className="px-4 sm:px-6 pb-5 border-t border-white/[0.04] pt-5 animate-fade-in">
                    <p className="text-[13px] text-[#737373] mb-4">{incident.description}</p>
                    <div className="grid grid-cols-2 gap-3">
                      {[
                        { label: 'Source', value: incident.source, capitalize: true },
                        { label: 'MITRE Tactic', value: incident.mitre_tactic || 'N/A' },
                        { label: 'Detected', value: formatDate(incident.detected_at) },
                        { label: 'Source IP', value: incident.source_ip || 'Internal', mono: true },
                      ].map((item) => (
                        <div key={item.label} className="bg-[#09090B] border border-white/[0.04] rounded-xl p-3">
                          <p className="text-[10px] uppercase tracking-wider text-[#525252] font-medium mb-1">{item.label}</p>
                          <p className={cn('text-[13px] text-[#E5E5E5] font-medium', item.capitalize && 'capitalize', item.mono && 'font-mono')}>{item.value}</p>
                        </div>
                      ))}
                    </div>
                    {actions.filter((a) => a.incident_id === incident.id).length > 0 && (
                      <div className="mt-4">
                        <p className="text-[10px] font-medium text-[#525252] uppercase tracking-wider mb-2">Response Actions</p>
                        <div className="space-y-2">
                          {actions.filter((a) => a.incident_id === incident.id).map((action) => (
                            <div key={action.id} className="flex items-center justify-between bg-[#09090B] border border-white/[0.04] p-3 rounded-xl">
                              <div className="flex items-center gap-3">
                                <StatusIndicator status={action.status} />
                                <div>
                                  <p className="text-[13px] text-[#E5E5E5] capitalize">{action.action_type.replace(/_/g, ' ')}</p>
                                  <p className="text-[11px] text-[#737373] font-mono">{action.target}</p>
                                </div>
                              </div>
                              {action.status === 'pending' && action.requires_approval && (
                                <button
                                  onClick={() => handleApprove(action.id)}
                                  className="text-[11px] bg-[#22C55E]/10 text-[#22C55E] px-3 py-1.5 rounded-lg hover:bg-[#22C55E]/20 transition-colors font-medium"
                                >
                                  Approve
                                </button>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {/* Actions Tab */}
      {tab === 'actions' && (
        <div className="space-y-3">
          {actions.length === 0 ? (
            <div className="bg-[#0A0A0A] border border-white/[0.04] rounded-xl p-12 text-center">
              <FlashIcon size={48} className="text-[#525252] mx-auto mb-3 opacity-50" />
              <p className="text-[#737373] text-[13px]">No response actions recorded yet.</p>
            </div>
          ) : (
            actions.map((action) => (
              <div key={action.id} className="bg-[#0A0A0A] border border-white/[0.04] rounded-xl p-4 hover:border-white/[0.08] transition-colors">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <StatusIndicator status={action.status} />
                    <span className="text-[13px] font-medium text-[#E5E5E5] capitalize">{action.action_type.replace(/_/g, ' ')}</span>
                    <span className="text-[11px] font-mono text-[#22D3EE] bg-[#22D3EE]/10 px-2 py-0.5 rounded-md">{action.target}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-[11px] text-[#525252] font-mono tabular-nums">{formatRelativeTime(action.created_at)}</span>
                    {action.status === 'pending' && action.requires_approval && (
                      <button
                        onClick={() => handleApprove(action.id)}
                        className="flex items-center gap-1 text-[11px] bg-[#22C55E]/10 text-[#22C55E] px-3 py-1.5 rounded-lg hover:bg-[#22C55E]/20 transition-colors font-medium"
                      >
                        <CheckCircle className="w-3 h-3" />
                        Approve
                      </button>
                    )}
                  </div>
                </div>
                {action.ai_reasoning && (
                  <div className="bg-[#09090B] border border-white/[0.04] rounded-xl p-4">
                    <p className="text-[10px] text-[#525252] mb-1 font-medium uppercase tracking-wider">AI Reasoning</p>
                    <p className="text-[13px] text-[#737373]">{action.ai_reasoning}</p>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {/* Guardrails Tab */}
      {tab === 'guardrails' && (
        <div className="bg-[#0A0A0A] border border-white/[0.04] rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-white/[0.04]">
            <h3 className="text-[13px] font-medium text-[#E5E5E5] uppercase tracking-wider">Autonomous Response Configuration</h3>
            <p className="text-[11px] text-[#737373] mt-0.5">Control which actions AEGIS can execute automatically without human approval</p>
          </div>
          {Object.keys(guardrails).length === 0 ? (
            <div className="p-12 text-center">
              <Shield className="w-12 h-12 text-[#525252] mx-auto mb-3 opacity-50" />
              <p className="text-[#737373] text-[13px]">No guardrails configured yet.</p>
            </div>
          ) : (
            <div>
              {Object.entries(guardrails).map(([key, enabled], index) => (
                <div key={key} className={cn('flex items-center justify-between px-6 py-4', index < Object.entries(guardrails).length - 1 && 'border-b border-white/[0.02]')}>
                  <div>
                    <p className="text-[13px] font-medium text-[#E5E5E5] capitalize">{key.replace(/^auto_/, '').replace(/_/g, ' ')}</p>
                    <p className="text-[11px] text-[#737373] mt-0.5">
                      {enabled ? 'Autonomous \u2014 executes immediately (Sigma rules + playbooks, no AI required)' : 'Manual \u2014 requires admin approval before execution'}
                    </p>
                  </div>
                  <button
                    onClick={() => toggleGuardrail(key)}
                    className={cn(
                      'relative w-11 h-6 rounded-full transition-colors duration-200',
                      enabled ? 'bg-[#22D3EE]' : 'bg-white/[0.06]'
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
        </div>
      )}
    </div>
  );
}
