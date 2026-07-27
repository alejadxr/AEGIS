'use client';

import * as React from 'react';
import { X, ShieldAlert, FileText, Cpu, Check, Clock } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { ProvenanceBadge } from '@/components/aegis';
import { SeverityBadge } from '@/components/shared/SeverityBadge';
import { api } from '@/lib/api';
import { cn, formatDate } from '@/lib/utils';

export interface VulnDataFull {
  id: string;
  asset_id: string;
  title: string;
  description?: string | null;
  severity: string;
  cvss_score?: number | null;
  cve_id?: string | null;
  status: string;
  ai_risk_score?: number | null;
  remediation?: string | null;
  found_at?: string | null;
  asset_hostname?: string;
  asset_ip?: string;
}

export interface VulnInspectionDrawerProps {
  vuln: VulnDataFull | null;
  open: boolean;
  onClose: () => void;
  onStatusUpdated?: (vulnId: string, newStatus: string) => void;
}

const statusOptions = [
  { value: 'open', label: 'Open', color: 'border-red-500/40 text-red-400 bg-red-500/10' },
  { value: 'remediated', label: 'Remediated', color: 'border-emerald-500/40 text-emerald-400 bg-emerald-500/10' },
  { value: 'accepted', label: 'Risk Accepted', color: 'border-amber-500/40 text-amber-400 bg-amber-500/10' },
  { value: 'false_positive', label: 'False Positive', color: 'border-blue-500/40 text-blue-400 bg-blue-500/10' },
];

export function VulnInspectionDrawer({
  vuln,
  open,
  onClose,
  onStatusUpdated,
}: VulnInspectionDrawerProps) {
  const [currentStatus, setCurrentStatus] = React.useState<string>('open');
  const [updating, setUpdating] = React.useState(false);
  const [updateSuccess, setUpdateSuccess] = React.useState(false);
  const [updateError, setUpdateError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (open) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
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

  React.useEffect(() => {
    if (vuln) {
      setCurrentStatus(vuln.status || 'open');
    }
  }, [vuln]);

  if (!open || !vuln) return null;

  const handleStatusChange = async (newStatus: string) => {
    if (newStatus === currentStatus || updating) return;
    setUpdating(true);
    setUpdateError(null);
    try {
      await api.surface.updateVulnerability(vuln.id, { status: newStatus });
      setCurrentStatus(newStatus);
      setUpdateSuccess(true);
      if (onStatusUpdated) {
        onStatusUpdated(vuln.id, newStatus);
      }
      setTimeout(() => setUpdateSuccess(false), 3000);
    } catch (err: unknown) {
      setUpdateError(err instanceof Error ? err.message : 'Failed to update vulnerability status');
    } finally {
      setUpdating(false);
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
            <div className="flex items-start gap-3 min-w-0">
              <div className="p-2.5 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 shrink-0 mt-0.5">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <div className="min-w-0 space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <SeverityBadge severity={vuln.severity} />
                  {vuln.cve_id && (
                    <Badge variant="outline" className="font-mono text-xs uppercase bg-white/[0.03] text-zinc-300 border-white/15">
                      {vuln.cve_id}
                    </Badge>
                  )}
                  {vuln.cvss_score !== undefined && vuln.cvss_score !== null && (
                    <Badge variant="secondary" className="font-mono text-xs bg-amber-500/10 text-amber-300 border border-amber-500/20">
                      CVSS {vuln.cvss_score.toFixed(1)}
                    </Badge>
                  )}
                </div>
                <h2 className="text-base font-bold text-white leading-snug tracking-tight">
                  {vuln.title}
                </h2>
                {vuln.found_at && (
                  <p className="text-xs text-zinc-400 font-mono flex items-center gap-1.5 pt-0.5">
                    <Clock className="w-3.5 h-3.5" />
                    First detected on {formatDate(vuln.found_at)}
                  </p>
                )}
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

          {/* Interactive Status Selector Bar */}
          <div className="px-6 py-4 bg-[#141418]/80 border-b border-white/10 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-zinc-400 font-outfit">
                Vulnerability Status Selector
              </span>
              {updateSuccess && (
                <span className="text-xs text-emerald-400 font-mono flex items-center gap-1">
                  <Check className="w-3.5 h-3.5" /> Status saved!
                </span>
              )}
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
              {statusOptions.map((opt) => {
                const isActive = currentStatus === opt.value;
                return (
                  <button
                    key={opt.value}
                    disabled={updating}
                    onClick={() => handleStatusChange(opt.value)}
                    className={cn(
                      'px-3 py-2 rounded-xl text-xs font-mono font-semibold border transition-all text-center',
                      isActive
                        ? opt.color + ' ring-1 ring-white/20'
                        : 'border-white/10 text-zinc-400 hover:bg-white/10 hover:text-white'
                    )}
                  >
                    {opt.label}
                  </button>
                );
              })}
            </div>

            {updateError && (
              <p className="text-xs text-red-400 font-mono mt-1">{updateError}</p>
            )}
          </div>

          {/* Body Content */}
          <div className="flex-1 overflow-y-auto p-6 space-y-6 bg-[#0F0F12]">

            {/* Affected Asset Card */}
            {(vuln.asset_hostname || vuln.asset_ip) && (
              <div className="p-4 rounded-xl bg-[#16161A] border border-white/10 flex items-center justify-between font-mono text-xs">
                <div className="space-y-0.5">
                  <div className="text-[10px] text-zinc-400 uppercase">Affected Asset</div>
                  <div className="font-bold text-white">{vuln.asset_hostname || 'Unknown'}</div>
                </div>
                {vuln.asset_ip && (
                  <Badge variant="outline" className="font-mono text-xs text-zinc-300 border-white/15">
                    {vuln.asset_ip}
                  </Badge>
                )}
              </div>
            )}

            {/* Description Section */}
            <div className="p-5 rounded-2xl bg-[#16161A] border border-white/10 space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-400 flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                Vulnerability Description
              </h3>
              <p className="text-xs text-zinc-300 leading-relaxed">
                {vuln.description || 'No detailed technical description provided for this vulnerability record.'}
              </p>
            </div>

            {/* AI Remediation Guidance */}
            <div className="p-5 rounded-2xl bg-[#16161A] border border-cyan-500/30 space-y-3 relative overflow-hidden">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-cyan-400" />
                  AI Remediation Recommendation
                </h3>
                <ProvenanceBadge source="agent" label="AI Remediation" />
              </div>

              <div className="p-4 rounded-xl bg-white/[0.03] border border-white/[0.06] text-xs text-zinc-200 font-mono space-y-2">
                {vuln.remediation ? (
                  <p className="leading-relaxed whitespace-pre-wrap">{vuln.remediation}</p>
                ) : (
                  <div className="space-y-2 text-zinc-400 font-sans">
                    <p>Standard remediation protocol for {vuln.cve_id || 'this vulnerability'}:</p>
                    <ul className="list-disc pl-4 space-y-1 text-xs">
                      <li>Apply the latest vendor security patches and updates.</li>
                      <li>Restrict external access to affected ports via firewall rules.</li>
                      <li>Review server configurations to enforce least privilege access.</li>
                    </ul>
                  </div>
                )}
              </div>
            </div>

            {/* AI Risk Score Detail */}
            {vuln.ai_risk_score !== undefined && vuln.ai_risk_score !== null && (
              <div className="p-4 rounded-xl bg-[#16161A] border border-white/10 flex items-center justify-between font-mono text-xs">
                <div className="text-zinc-400">AI Risk Evaluation Score</div>
                <div className="font-bold text-cyan-400">{vuln.ai_risk_score.toFixed(1)} / 10.0</div>
              </div>
            )}

          </div>

        </div>
      </div>
    </div>
  );
}
