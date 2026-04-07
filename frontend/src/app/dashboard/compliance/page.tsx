'use client';

import { useState, useEffect } from 'react';
import { CheckCircle, XCircle, AlertTriangle, ChevronDown, ChevronRight, FileCheck, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { api } from '@/lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────

type ControlStatus = 'met' | 'partial' | 'not_met';

interface Control {
  id: string;
  name: string;
  module: string;
  status: ControlStatus;
  evidence: string;
}

interface Framework {
  name: string;
  shortName: string;
  description: string;
  controls: Control[];
}

// ─── Fallback Compliance Data ────────────────────────────────────────────────

const FALLBACK_FRAMEWORKS: Framework[] = [
  {
    name: 'ISO 27001:2022',
    shortName: 'ISO 27001',
    description: 'Information security management systems',
    controls: [
      { id: 'A.5', name: 'Information Security Policies', module: 'Settings / Guardrails', status: 'met', evidence: 'AI guardrails system with auto_approve / require_approval / never_auto policies configured' },
      { id: 'A.6', name: 'Organization of Information Security', module: 'Auth / RBAC', status: 'met', evidence: 'Multi-tenant architecture with API key auth, JWT tokens, and role-based access control' },
      { id: 'A.7', name: 'Human Resource Security', module: '-', status: 'not_met', evidence: 'HR security controls are outside AEGIS scope' },
      { id: 'A.8', name: 'Asset Management', module: 'Surface Scanner', status: 'met', evidence: 'Automated asset discovery via nmap, continuous scanning (full 2h, quick 30min, discovery 1h)' },
      { id: 'A.9', name: 'Access Control', module: 'Auth / RBAC', status: 'met', evidence: 'API key authentication, JWT sessions, middleware-level enforcement' },
      { id: 'A.10', name: 'Cryptography', module: 'Quantum Module', status: 'met', evidence: 'Post-quantum cryptography assessment, algorithm vulnerability timeline tracking' },
      { id: 'A.11', name: 'Physical Security', module: '-', status: 'not_met', evidence: 'Physical security controls are outside AEGIS scope' },
      { id: 'A.12', name: 'Operations Security', module: 'Log Watcher / Scanner', status: 'met', evidence: 'PM2 log tailing for SQLi, XSS, brute force patterns; scheduled vulnerability scanning' },
      { id: 'A.13', name: 'Communications Security', module: 'NDR / DNS Monitor', status: 'met', evidence: 'Network traffic analysis, DNS monitoring, threat intelligence correlation' },
      { id: 'A.14', name: 'System Development Security', module: 'Surface / SBOM', status: 'met', evidence: 'SBOM scanning, technology fingerprinting, vulnerability assessment with nuclei' },
      { id: 'A.15', name: 'Supplier Relationships', module: '-', status: 'not_met', evidence: 'Supplier management is outside AEGIS scope' },
      { id: 'A.16', name: 'Incident Management', module: 'Response Module', status: 'met', evidence: 'Autonomous AI-driven triage, classification, decision, execution, verification, and audit pipeline' },
      { id: 'A.17', name: 'Business Continuity', module: 'Infra / PM2', status: 'partial', evidence: 'PM2 process management with auto-restart, but no full DR/BCP implementation' },
      { id: 'A.18', name: 'Compliance', module: 'Compliance Dashboard', status: 'met', evidence: 'This compliance dashboard providing framework mapping and gap analysis' },
    ],
  },
  {
    name: 'NIS2 Directive',
    shortName: 'NIS2',
    description: 'EU Network and Information Security directive',
    controls: [
      { id: 'Art.21.a', name: 'Risk Analysis & IS Policies', module: 'Surface / Guardrails', status: 'met', evidence: 'AI risk scoring on assets, configurable security policies via guardrails' },
      { id: 'Art.21.b', name: 'Incident Handling', module: 'Response Module', status: 'met', evidence: 'Automated incident detection, AI analysis, response actions with dual-layer IP blocking' },
      { id: 'Art.21.c', name: 'Business Continuity & Crisis Mgmt', module: 'Infra', status: 'partial', evidence: 'PM2 auto-restart and monitoring, but limited crisis management capabilities' },
      { id: 'Art.21.d', name: 'Supply Chain Security', module: 'Surface / SBOM', status: 'partial', evidence: 'SBOM scanning and technology fingerprinting cover some supply chain risks' },
      { id: 'Art.21.e', name: 'Network & IS Acquisition/Dev', module: 'Surface Scanner', status: 'met', evidence: 'Vulnerability scanning with nuclei, asset discovery, port analysis' },
      { id: 'Art.21.f', name: 'Effectiveness Assessment', module: 'Phantom / Honeypots', status: 'met', evidence: 'Honeypot deception system validates detection capabilities against real attackers' },
      { id: 'Art.21.g', name: 'Cybersecurity Hygiene & Training', module: '-', status: 'not_met', evidence: 'Training and hygiene programs are outside AEGIS scope' },
      { id: 'Art.21.h', name: 'Cryptography Policies', module: 'Quantum Module', status: 'met', evidence: 'Quantum readiness assessment, crypto algorithm timeline, PQC recommendations' },
      { id: 'Art.21.i', name: 'HR Security & Access Control', module: 'Auth / RBAC', status: 'met', evidence: 'Role-based access control, API key management, multi-tenant isolation' },
      { id: 'Art.21.j', name: 'Multi-factor Authentication', module: 'Auth', status: 'partial', evidence: 'API key + JWT auth implemented, MFA not yet enforced' },
      { id: 'Art.23', name: 'Incident Reporting (24h/72h)', module: 'Response / Notifications', status: 'met', evidence: 'Real-time Telegram and webhook notifications for incidents, configurable thresholds' },
    ],
  },
  {
    name: 'SOC 2 Type II',
    shortName: 'SOC2',
    description: 'Service Organization Control - Trust Services Criteria',
    controls: [
      { id: 'CC1', name: 'Control Environment', module: 'Settings / Guardrails', status: 'met', evidence: 'Configurable guardrails, AI decision audit trail, client settings management' },
      { id: 'CC2', name: 'Communication & Information', module: 'Notifications', status: 'met', evidence: 'Telegram, webhook, and email notification channels for security events' },
      { id: 'CC3', name: 'Risk Assessment', module: 'Surface Scanner', status: 'met', evidence: 'Automated risk scoring, vulnerability assessment, adaptive scanning frequency' },
      { id: 'CC4', name: 'Monitoring Activities', module: 'Log Watcher / Phantom', status: 'met', evidence: 'Continuous log monitoring, honeypot interaction tracking, anomaly detection' },
      { id: 'CC5', name: 'Control Activities', module: 'Response Module', status: 'met', evidence: 'Automated response actions, approval workflows, dual-layer IP blocking' },
      { id: 'CC6', name: 'Logical & Physical Access', module: 'Auth / RBAC', status: 'met', evidence: 'API key auth, JWT sessions, role-based access, middleware enforcement' },
      { id: 'CC7', name: 'System Operations', module: 'Infra / Scheduled Scanner', status: 'met', evidence: 'PM2 process management, scheduled scanning, system health monitoring' },
      { id: 'CC8', name: 'Change Management', module: '-', status: 'not_met', evidence: 'Formal change management process not implemented in AEGIS' },
      { id: 'CC9', name: 'Risk Mitigation', module: 'Response / Firewall', status: 'met', evidence: 'Automated IP blocking via external firewall integration + local blocklist, AI-driven remediation' },
      { id: 'A1', name: 'Availability', module: 'Infra / PM2', status: 'partial', evidence: 'PM2 auto-restart, health checks, but no formal SLA or redundancy' },
      { id: 'PI1', name: 'Processing Integrity', module: 'AI Engine', status: 'met', evidence: 'Multi-step AI pipeline with verification step, audit logging for all actions' },
      { id: 'C1', name: 'Confidentiality', module: 'Auth / Multi-tenant', status: 'met', evidence: 'Tenant isolation, encrypted API keys, JWT-based session management' },
    ],
  },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function calculateFrameworkScore(framework: Framework): number {
  const weights: Record<ControlStatus, number> = { met: 1, partial: 0.5, not_met: 0 };
  const total = framework.controls.reduce((sum, c) => sum + weights[c.status], 0);
  return Math.round((total / framework.controls.length) * 100);
}

function statusIcon(status: ControlStatus) {
  if (status === 'met') return <CheckCircle size={14} className="text-[#22C55E]" />;
  if (status === 'partial') return <AlertTriangle size={14} className="text-[#F59E0B]" />;
  return <XCircle size={14} className="text-[#EF4444]" />;
}

function statusLabel(status: ControlStatus): string {
  if (status === 'met') return 'Met';
  if (status === 'partial') return 'Partial';
  return 'Not Met';
}

function statusBadgeStyle(status: ControlStatus): string {
  if (status === 'met') return 'bg-[#22C55E]/10 text-[#22C55E] border-[#22C55E]/20';
  if (status === 'partial') return 'bg-[#F59E0B]/10 text-[#F59E0B] border-[#F59E0B]/20';
  return 'bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/20';
}

function scoreColor(score: number): string {
  if (score >= 80) return '#22C55E';
  if (score >= 60) return '#F59E0B';
  return '#EF4444';
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function CompliancePage() {
  const [frameworks, setFrameworks] = useState<Framework[]>(FALLBACK_FRAMEWORKS);
  const [loading, setLoading] = useState(true);
  const [expandedFramework, setExpandedFramework] = useState<string | null>('ISO 27001');
  const [filterStatus, setFilterStatus] = useState<ControlStatus | 'all'>('all');

  useEffect(() => {
    (async () => {
      try {
        const data = await api.compliance.frameworks();
        if (data && data.frameworks && data.frameworks.length > 0) {
          setFrameworks(data.frameworks.map((fw: { short_name: string; name: string; description: string; controls: Array<{ id: string; name: string; module: string; status: string; evidence: string }> }) => ({
            name: fw.name,
            shortName: fw.short_name,
            description: fw.description,
            controls: fw.controls.map(c => ({
              ...c,
              status: c.status as ControlStatus,
            })),
          })));
        }
      } catch {
        // Use fallback data
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const gaps = frameworks.flatMap(fw =>
    fw.controls
      .filter(c => c.status === 'not_met')
      .map(c => ({ framework: fw.shortName, ...c }))
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 size={24} className="text-[#22D3EE] animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 rounded-xl bg-[#18181B] border border-white/[0.06] flex items-center justify-center">
            <FileCheck className="text-[#22D3EE]" size={20} />
          </div>
          <div>
            <h1 className="text-2xl font-semibold text-white tracking-tight">Compliance</h1>
            <p className="text-sm text-zinc-500 mt-0.5">
              Security framework mapping and compliance posture
            </p>
          </div>
        </div>
      </div>

      {/* Framework Score Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {frameworks.map(fw => {
          const score = calculateFrameworkScore(fw);
          const met = fw.controls.filter(c => c.status === 'met').length;
          const partial = fw.controls.filter(c => c.status === 'partial').length;
          const notMet = fw.controls.filter(c => c.status === 'not_met').length;

          return (
            <button
              key={fw.shortName}
              onClick={() => setExpandedFramework(expandedFramework === fw.shortName ? null : fw.shortName)}
              className={cn(
                'bg-[#18181B] border rounded-2xl p-5 text-left transition-all duration-200 hover:border-white/[0.1]',
                expandedFramework === fw.shortName ? 'border-[#22D3EE]/30 ring-1 ring-[#22D3EE]/10' : 'border-white/[0.06]'
              )}
            >
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-[15px] font-semibold text-white">{fw.shortName}</h3>
                  <p className="text-[11px] text-zinc-500 mt-0.5">{fw.description}</p>
                </div>
                <div className="relative w-14 h-14 shrink-0">
                  <svg viewBox="0 0 48 48" className="w-full h-full -rotate-90">
                    <circle cx="24" cy="24" r="20" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="4" />
                    <circle
                      cx="24" cy="24" r="20"
                      fill="none"
                      stroke={scoreColor(score)}
                      strokeWidth="4"
                      strokeLinecap="round"
                      strokeDasharray={`${(score / 100) * 2 * Math.PI * 20} ${2 * Math.PI * 20}`}
                      className="transition-all duration-700"
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-data text-sm font-bold" style={{ color: scoreColor(score) }}>
                      {score}%
                    </span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-1.5">
                  <CheckCircle size={12} className="text-[#22C55E]" />
                  <span className="text-data text-[12px] text-zinc-400">{met} met</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <AlertTriangle size={12} className="text-[#F59E0B]" />
                  <span className="text-data text-[12px] text-zinc-400">{partial} partial</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <XCircle size={12} className="text-[#EF4444]" />
                  <span className="text-data text-[12px] text-zinc-400">{notMet} gaps</span>
                </div>
              </div>
              {/* Coverage bar */}
              <div className="mt-3 h-1.5 bg-white/[0.04] rounded-full overflow-hidden flex">
                <div
                  className="h-full bg-[#22C55E] transition-all duration-700"
                  style={{ width: `${(met / fw.controls.length) * 100}%` }}
                />
                <div
                  className="h-full bg-[#F59E0B] transition-all duration-700"
                  style={{ width: `${(partial / fw.controls.length) * 100}%` }}
                />
              </div>
            </button>
          );
        })}
      </div>

      {/* Controls Table */}
      {expandedFramework && (() => {
        const fw = frameworks.find(f => f.shortName === expandedFramework);
        if (!fw) return null;

        const filtered = filterStatus === 'all'
          ? fw.controls
          : fw.controls.filter(c => c.status === filterStatus);

        return (
          <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <ChevronDown size={16} className="text-[#22D3EE]" />
                <h2 className="text-sm font-semibold text-white">{fw.name} Controls</h2>
                <span className="text-data text-[11px] text-zinc-600 ml-1">{filtered.length} controls</span>
              </div>
              {/* Filter */}
              <div className="flex items-center gap-1">
                {(['all', 'met', 'partial', 'not_met'] as const).map(f => (
                  <button
                    key={f}
                    onClick={() => setFilterStatus(f)}
                    className={cn(
                      'px-2.5 py-1 rounded-lg text-[11px] font-medium transition-colors',
                      filterStatus === f
                        ? 'bg-[#22D3EE]/10 text-[#22D3EE]'
                        : 'text-zinc-500 hover:text-zinc-300 hover:bg-white/[0.03]'
                    )}
                  >
                    {f === 'all' ? 'All' : f === 'not_met' ? 'Gaps' : f.charAt(0).toUpperCase() + f.slice(1)}
                  </button>
                ))}
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-white/[0.06]">
                    {['Control ID', 'Control Name', 'AEGIS Module', 'Status', 'Evidence'].map(h => (
                      <th key={h} className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest pb-3 pr-4 whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(c => (
                    <tr key={c.id} className="border-b border-white/[0.03] hover:bg-white/[0.02] transition-colors">
                      <td className="py-3 pr-4">
                        <span className="text-data text-[13px] text-[#22D3EE] font-medium">{c.id}</span>
                      </td>
                      <td className="py-3 pr-4">
                        <span className="text-[13px] text-white">{c.name}</span>
                      </td>
                      <td className="py-3 pr-4">
                        <span className={cn(
                          'text-data text-[12px]',
                          c.module === '-' ? 'text-zinc-600' : 'text-zinc-400'
                        )}>
                          {c.module}
                        </span>
                      </td>
                      <td className="py-3 pr-4">
                        <span className={cn(
                          'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold border',
                          statusBadgeStyle(c.status)
                        )}>
                          {statusIcon(c.status)}
                          {statusLabel(c.status)}
                        </span>
                      </td>
                      <td className="py-3 max-w-[320px]">
                        <span className="text-[12px] text-zinc-500 leading-relaxed">{c.evidence}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );
      })()}

      {/* Gaps Summary */}
      <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-6">
        <div className="flex items-center gap-2 mb-4">
          <XCircle size={16} className="text-[#EF4444]" />
          <h2 className="text-sm font-semibold text-white">Coverage Gaps</h2>
          <span className="text-data text-[11px] text-zinc-600 ml-1">{gaps.length} controls not covered</span>
        </div>
        {gaps.length === 0 ? (
          <div className="flex items-center gap-2 py-4">
            <CheckCircle size={16} className="text-[#22C55E]" />
            <span className="text-sm text-zinc-400">Full coverage across all frameworks</span>
          </div>
        ) : (
          <div className="space-y-2">
            {gaps.map(gap => (
              <div
                key={`${gap.framework}-${gap.id}`}
                className="flex items-start gap-3 p-3 rounded-xl bg-[#09090B] border border-white/[0.04] hover:border-[#EF4444]/10 transition-colors"
              >
                <div className="shrink-0 mt-0.5">
                  <XCircle size={14} className="text-[#EF4444]" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-data text-[11px] text-[#22D3EE] font-medium">{gap.framework}</span>
                    <ChevronRight size={10} className="text-zinc-600" />
                    <span className="text-data text-[12px] text-zinc-300 font-medium">{gap.id}</span>
                    <span className="text-[12px] text-zinc-400">{gap.name}</span>
                  </div>
                  <p className="text-[11px] text-zinc-600">{gap.evidence}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
