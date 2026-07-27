'use client';

import * as React from 'react';
import { X, Server, Globe, Cloud, Code, Wifi, RefreshCw, Cpu, Layers, CheckCircle2, Lock } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { StatusBadge, ProvenanceBadge } from '@/components/aegis';
import { SeverityBadge } from '@/components/shared/SeverityBadge';
import { api } from '@/lib/api';
import { cn, formatDate } from '@/lib/utils';

export interface AssetPort {
  port: number;
  protocol?: string;
  service?: string;
  version?: string;
  state?: string;
}

export interface AssetDriver {
  port: number;
  protocol: string;
  service: string;
  klass: string;
  label: string;
  weight: number;
  host_wide: boolean;
  contribution: number;
}

export interface AssetServiceClassItem {
  klass: string;
  label: string;
  weight: number;
  count: number;
}

export interface AssetData {
  id: string;
  hostname: string;
  ip_address: string;
  asset_type: string;
  ports: (number | AssetPort)[];
  technologies: string[];
  status: string;
  risk_score: number;
  last_scan_at: string | null;
  risk_band?: string;
  risk_method?: string;
  risk_ai_used?: boolean;
  exposure?: string;
  exposure_multiplier?: number;
  base_score?: number;
  vuln_term?: number;
  risk_drivers?: AssetDriver[];
  service_classes?: AssetServiceClassItem[];
  vulnerability_count?: number;
}

export interface VulnData {
  id: string;
  asset_id: string;
  title: string;
  description?: string | null;
  severity: string;
  cvss_score?: number | null;
  cve_id?: string | null;
  status: string;
  found_at?: string | null;
}

export interface AssetInspectionDrawerProps {
  asset: AssetData | null;
  open: boolean;
  onClose: () => void;
  associatedVulns?: VulnData[];
  onTriggerScan?: (target: string) => void;
  onSelectVuln?: (vuln: VulnData) => void;
}

const typeIcons: Record<string, typeof Server> = {
  server: Server,
  web: Globe,
  cloud: Cloud,
  api: Code,
  dns: Wifi,
};

function riskScoreColor(score: number): string {
  if (score >= 8) return 'text-[var(--danger)] border-[var(--danger)]/30 bg-[var(--danger)]/10';
  if (score >= 6) return 'text-[var(--brand-accent)] border-[var(--brand-accent)]/30 bg-[var(--brand-accent)]/10';
  if (score >= 4) return 'text-[var(--warning)] border-[var(--warning)]/30 bg-[var(--warning)]/10';
  return 'text-[var(--success)] border-[var(--success)]/30 bg-[var(--success)]/10';
}

function cleanHostname(hostname: string): string {
  const fakePattern = /^(www|mail)\.(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/;
  const match = hostname.match(fakePattern);
  if (match) return match[2];
  return hostname;
}

export function AssetInspectionDrawer({
  asset,
  open,
  onClose,
  associatedVulns = [],
  onTriggerScan,
  onSelectVuln,
}: AssetInspectionDrawerProps) {
  const [activeTab, setActiveTab] = React.useState<'overview' | 'drivers' | 'ports' | 'vulns' | 'hardening'>('overview');
  const [rescanning, setRescanning] = React.useState(false);
  const [rescanSuccess, setRescanSuccess] = React.useState(false);
  const [hardeningData, setHardeningData] = React.useState<{
    ai_recommendations: Record<string, unknown>;
    checklist: Array<{ item: string; priority: string; category: string }>;
  } | null>(null);
  const [loadingHardening, setLoadingHardening] = React.useState(false);

  React.useEffect(() => {
    if (open && asset && activeTab === 'hardening' && !hardeningData) {
      setLoadingHardening(true);
      api.surface
        .harden(asset.hostname, asset.asset_type)
        .then((res) => {
          setHardeningData({
            ai_recommendations: res.ai_recommendations || {},
            checklist: res.checklist || [],
          });
        })
        .catch(() => {
          setHardeningData({ ai_recommendations: {}, checklist: [] });
        })
        .finally(() => {
          setLoadingHardening(false);
        });
    }
  }, [open, asset, activeTab, hardeningData]);

  React.useEffect(() => {
    if (open) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
      setHardeningData(null);
      setRescanSuccess(false);
      setActiveTab('overview');
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [open]);

  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && open) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, onClose]);

  if (!open || !asset) return null;

  const IconComp = typeIcons[asset.asset_type] || Server;
  const normalizedPorts: AssetPort[] = (asset.ports || []).map((p) => {
    if (typeof p === 'number') return { port: p, protocol: 'tcp', service: 'unknown' };
    return p;
  });

  const assetVulns = associatedVulns.filter((v) => v.asset_id === asset.id);

  const handleRescan = async () => {
    setRescanning(true);
    try {
      if (onTriggerScan) {
        onTriggerScan(asset.hostname);
      } else {
        await api.surface.scan(asset.hostname, 'full');
      }
      setRescanSuccess(true);
      setTimeout(() => setRescanSuccess(false), 4000);
    } catch {
      // ignore error best-effort
    } finally {
      setRescanning(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[200] overflow-hidden bg-black/85 backdrop-blur-md animate-in fade-in duration-200">
      {/* Backdrop overlay click to close */}
      <div className="absolute inset-0 bg-transparent" onClick={onClose} />

      <div className="absolute inset-y-0 right-0 flex max-w-full pl-10 pointer-events-none">
        <div className="w-screen max-w-2xl bg-[#0F0F12] border-l border-white/10 flex flex-col font-sans text-zinc-100 pointer-events-auto shadow-none">
          
          {/* Header */}
          <div className="p-6 border-b border-white/10 bg-[#141418] flex items-start justify-between gap-4 shrink-0">
            <div className="flex items-center gap-3 min-w-0">
              <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 shrink-0">
                <IconComp className="w-5 h-5" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className="font-mono text-lg font-bold text-white truncate tracking-tight">
                    {cleanHostname(asset.hostname)}
                  </h2>
                  <StatusBadge
                    variant={asset.status === 'active' ? 'accent' : 'muted'}
                    size="sm"
                  >
                    {asset.status}
                  </StatusBadge>
                </div>
                <div className="flex items-center gap-3 mt-1 text-xs text-zinc-400 font-mono">
                  <span>{asset.ip_address || 'No IP'}</span>
                  <span>•</span>
                  <span className="capitalize">{asset.asset_type}</span>
                  {asset.last_scan_at && (
                    <>
                      <span>•</span>
                      <span>Scanned {formatDate(asset.last_scan_at)}</span>
                    </>
                  )}
                </div>
              </div>
            </div>

            <button
              onClick={onClose}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-white/10 hover:bg-white/20 text-white text-xs font-mono font-semibold transition-all shrink-0 cursor-pointer"
              aria-label="Close drawer"
            >
              <X className="w-4 h-4" />
              <span>CLOSE</span>
            </button>
          </div>

          {/* Quick Telemetry Bar & Rescan Button */}
          <div className="px-6 py-4 bg-[#141418]/80 border-b border-white/10 flex items-center justify-between gap-4 flex-wrap">
            <div className="flex items-center gap-4">
              <div className={cn('px-3 py-1.5 rounded-xl border flex items-center gap-2', riskScoreColor(asset.risk_score))}>
                <span className="text-xs uppercase tracking-wider font-semibold font-outfit">Risk Score</span>
                <span className="font-mono text-base font-bold tabular-nums">
                  {asset.risk_score ? asset.risk_score.toFixed(1) : '0.0'}
                </span>
              </div>

              {asset.risk_band && (
                <Badge variant="outline" className="font-mono text-xs uppercase bg-white/[0.03] text-zinc-300 border-white/15">
                  {asset.risk_band}
                </Badge>
              )}

              <div className="text-xs text-zinc-400">
                <span className="font-mono font-semibold text-white">{assetVulns.length}</span> Open Vulns
              </div>
            </div>

            <Button
              size="sm"
              variant="outline"
              disabled={rescanning}
              onClick={handleRescan}
              className="gap-2 border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10 bg-cyan-500/5"
            >
              <RefreshCw className={cn('w-3.5 h-3.5', rescanning && 'animate-spin')} />
              {rescanning ? 'Scanning...' : rescanSuccess ? 'Scan Triggered!' : 'Re-scan Target'}
            </Button>
          </div>

          {/* Tabs Navigation */}
          <div className="px-6 border-b border-white/10 flex items-center gap-1 bg-[#141418]/60 overflow-x-auto">
            <button
              onClick={() => setActiveTab('overview')}
              className={cn(
                'px-4 py-3 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors whitespace-nowrap',
                activeTab === 'overview'
                  ? 'border-cyan-400 text-cyan-400'
                  : 'border-transparent text-zinc-400 hover:text-white'
              )}
            >
              Overview
            </button>
            <button
              onClick={() => setActiveTab('drivers')}
              className={cn(
                'px-4 py-3 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors whitespace-nowrap',
                activeTab === 'drivers'
                  ? 'border-cyan-400 text-cyan-400'
                  : 'border-transparent text-zinc-400 hover:text-white'
              )}
            >
              Risk Drivers ({asset.risk_drivers?.length || 0})
            </button>
            <button
              onClick={() => setActiveTab('ports')}
              className={cn(
                'px-4 py-3 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors whitespace-nowrap',
                activeTab === 'ports'
                  ? 'border-cyan-400 text-cyan-400'
                  : 'border-transparent text-zinc-400 hover:text-white'
              )}
            >
              Ports ({normalizedPorts.length})
            </button>
            <button
              onClick={() => setActiveTab('vulns')}
              className={cn(
                'px-4 py-3 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors whitespace-nowrap',
                activeTab === 'vulns'
                  ? 'border-cyan-400 text-cyan-400'
                  : 'border-transparent text-zinc-400 hover:text-white'
              )}
            >
              Vulnerabilities ({assetVulns.length})
            </button>
            <button
              onClick={() => setActiveTab('hardening')}
              className={cn(
                'px-4 py-3 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors whitespace-nowrap',
                activeTab === 'hardening'
                  ? 'border-cyan-400 text-cyan-400'
                  : 'border-transparent text-zinc-400 hover:text-white'
              )}
            >
              Hardening Checklist
            </button>
          </div>

          {/* Drawer Body Content */}
          <div className="flex-1 overflow-y-auto p-6 space-y-6 bg-[#0F0F12]">

            {/* TAB: Overview */}
            {activeTab === 'overview' && (
              <div className="space-y-6">
                
                {/* Risk Score Derivation Box */}
                <div className="p-5 rounded-2xl bg-[#16161A] border border-white/10 space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400 flex items-center gap-2">
                      <Cpu className="w-4 h-4 text-cyan-400" />
                      Risk Calculation (service_weighted_v1)
                    </h3>
                    <ProvenanceBadge source="algorithm" label="Deterministic" />
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
                    <div className="p-3 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                      <div className="text-[10px] text-zinc-400 uppercase font-mono">Base Score</div>
                      <div className="font-mono text-base font-bold text-white mt-1">
                        {asset.base_score !== undefined && asset.base_score !== null ? asset.base_score.toFixed(1) : '—'}
                      </div>
                    </div>
                    <div className="p-3 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                      <div className="text-[10px] text-zinc-400 uppercase font-mono">Exposure Mult</div>
                      <div className="font-mono text-base font-bold text-white mt-1">
                        {asset.exposure_multiplier !== undefined && asset.exposure_multiplier !== null ? `×${asset.exposure_multiplier}` : '—'}
                      </div>
                    </div>
                    <div className="p-3 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                      <div className="text-[10px] text-zinc-400 uppercase font-mono">Vuln Term</div>
                      <div className="font-mono text-base font-bold text-white mt-1">
                        {asset.vuln_term !== undefined && asset.vuln_term !== null ? `+${asset.vuln_term.toFixed(1)}` : '—'}
                      </div>
                    </div>
                    <div className="p-3 rounded-xl bg-white/[0.03] border border-white/[0.06]">
                      <div className="text-[10px] text-zinc-400 uppercase font-mono">Exposure</div>
                      <div className="font-mono text-sm font-bold text-white capitalize mt-1">
                        {asset.exposure || 'unknown'}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Discovered Tech Stack */}
                <div className="p-5 rounded-2xl bg-[#16161A] border border-white/10 space-y-3">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400 flex items-center gap-2">
                    <Layers className="w-4 h-4 text-cyan-400" />
                    Discovered Tech Stack
                  </h3>
                  {asset.technologies && asset.technologies.length > 0 ? (
                    <div className="flex flex-wrap gap-2 pt-1">
                      {asset.technologies.map((tech, idx) => (
                        <Badge key={idx} variant="secondary" className="font-mono text-xs py-1 px-3 bg-white/[0.06] text-zinc-200 border-white/10">
                          {tech}
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-zinc-400 italic">No specialized technologies identified on last scan.</p>
                  )}
                </div>

                {/* Service Classes Breakdown */}
                {asset.service_classes && asset.service_classes.length > 0 && (
                  <div className="p-5 rounded-2xl bg-[#16161A] border border-white/10 space-y-3">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400">Service Classes</h3>
                    <div className="space-y-2">
                      {asset.service_classes.map((sc, idx) => (
                        <div key={idx} className="flex items-center justify-between text-xs font-mono p-2.5 rounded-lg bg-white/[0.03] border border-white/[0.05]">
                          <span className="text-zinc-200">{sc.label} ({sc.klass})</span>
                          <span className="text-zinc-400">Weight: <strong className="text-cyan-400">{sc.weight}</strong></span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

              </div>
            )}

            {/* TAB: Risk Drivers */}
            {activeTab === 'drivers' && (
              <div className="space-y-4">
                {asset.risk_drivers && asset.risk_drivers.length > 0 ? (
                  <div className="space-y-3">
                    {asset.risk_drivers.map((driver, idx) => (
                      <div key={idx} className="p-4 rounded-xl bg-[#16161A] border border-white/10 space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-sm text-white">Port {driver.port}</span>
                            <Badge variant="outline" className="font-mono text-[10px] uppercase text-zinc-300 border-white/15">
                              {driver.service} ({driver.protocol})
                            </Badge>
                            {driver.host_wide && (
                              <Badge variant="secondary" className="text-[10px] bg-amber-500/10 text-amber-400 border border-amber-500/20">
                                Host-Wide Damped
                              </Badge>
                            )}
                          </div>
                          <span className="font-mono text-xs font-bold text-cyan-400">
                            +{driver.contribution.toFixed(1)} pts
                          </span>
                        </div>
                        <div className="text-xs text-zinc-400 flex items-center justify-between font-mono">
                          <span>Class: {driver.label}</span>
                          <span>Base Weight: {driver.weight}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-zinc-400 text-xs font-mono">
                    No individual high-risk drivers flagged for this asset.
                  </div>
                )}
              </div>
            )}

            {/* TAB: Ports */}
            {activeTab === 'ports' && (
              <div className="space-y-3">
                {normalizedPorts.length > 0 ? (
                  <div className="divide-y divide-white/10 rounded-xl bg-[#16161A] border border-white/10 overflow-hidden">
                    {normalizedPorts.map((p, idx) => (
                      <div key={idx} className="p-3.5 flex items-center justify-between font-mono text-xs hover:bg-white/[0.04] transition-colors">
                        <div className="flex items-center gap-3">
                          <span className="font-bold text-white w-16">{p.port}</span>
                          <span className="text-zinc-400 uppercase">{p.protocol || 'tcp'}</span>
                          {p.service && <span className="text-cyan-400 font-semibold">{p.service}</span>}
                        </div>
                        <div className="flex items-center gap-3">
                          {p.version && <span className="text-zinc-400 text-[11px]">{p.version}</span>}
                          <Badge variant="outline" className="text-[10px] uppercase border-emerald-500/30 text-emerald-400 bg-emerald-500/10">
                            {p.state || 'open'}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8 text-zinc-400 text-xs font-mono">
                    No open ports registered for this asset.
                  </div>
                )}
              </div>
            )}

            {/* TAB: Vulnerabilities */}
            {activeTab === 'vulns' && (
              <div className="space-y-3">
                {assetVulns.length > 0 ? (
                  assetVulns.map((v) => (
                    <div
                      key={v.id}
                      onClick={() => onSelectVuln && onSelectVuln(v)}
                      className="p-4 rounded-xl bg-[#16161A] border border-white/10 hover:border-cyan-500/50 transition-colors cursor-pointer space-y-2 group"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <h4 className="text-sm font-semibold text-white group-hover:text-cyan-400 transition-colors">
                          {v.title}
                        </h4>
                        <SeverityBadge severity={v.severity} />
                      </div>
                      <div className="flex items-center gap-4 text-xs font-mono text-zinc-400">
                        {v.cve_id && <span>{v.cve_id}</span>}
                        {v.cvss_score !== undefined && v.cvss_score !== null && (
                          <span>CVSS {v.cvss_score.toFixed(1)}</span>
                        )}
                        <StatusBadge variant={v.status === 'open' ? 'danger' : 'success'} size="sm">
                          {v.status}
                        </StatusBadge>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-center py-8 text-zinc-400 text-xs font-mono">
                    No vulnerabilities currently associated with this asset.
                  </div>
                )}
              </div>
            )}

            {/* TAB: Hardening Checklist */}
            {activeTab === 'hardening' && (
              <div className="space-y-4">
                {loadingHardening ? (
                  <div className="text-center py-10 text-xs font-mono text-zinc-400 animate-pulse">
                    Generating automated hardening checklist...
                  </div>
                ) : hardeningData ? (
                  <div className="space-y-6">
                    {/* Hardening Checklist Items */}
                    <div className="space-y-3">
                      <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400 flex items-center gap-2">
                        <Lock className="w-4 h-4 text-cyan-400" />
                        Hardening Checklist ({hardeningData.checklist.length} Controls)
                      </h3>
                      <div className="space-y-2">
                        {hardeningData.checklist.map((item, idx) => (
                          <div key={idx} className="p-3.5 rounded-xl bg-[#16161A] border border-white/10 flex items-center justify-between gap-3">
                            <div className="flex items-center gap-3">
                              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                              <span className="text-xs text-white font-medium">{item.item}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge variant="outline" className="font-mono text-[10px] uppercase text-zinc-300 border-white/15">
                                {item.category}
                              </Badge>
                              <Badge
                                className={cn(
                                  'font-mono text-[10px] uppercase',
                                  item.priority === 'critical' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                                  item.priority === 'high' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' :
                                  'bg-blue-500/10 text-blue-400 border-blue-500/20'
                                )}
                              >
                                {item.priority}
                              </Badge>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-xs font-mono text-zinc-400">
                    Failed to load hardening recommendations.
                  </div>
                )}
              </div>
            )}

          </div>

        </div>
      </div>
    </div>
  );
}
