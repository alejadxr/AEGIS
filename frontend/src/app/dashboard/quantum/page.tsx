'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import { Atom, AlertTriangle, CheckCircle, XCircle, Info, Loader2, Crown, Lock, Check, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { api } from '@/lib/api';

// ─── Types ────────────────────────────────────────────────────────────────────

interface QuantumReadiness {
  score: number;
  quantum_safe_count: number;
  total_assets: number;
  last_assessed: string | null;
}

interface CryptoTimelineEntry {
  algorithm: string;
  key_bits: number;
  type: string;
  vulnerable_by: number;
  status: 'safe' | 'at_risk' | 'vulnerable' | 'broken';
}

interface AlgorithmAssessment {
  algorithm: string;
  key_bits: number;
  type: string;
  classical_security: string;
  quantum_security: string;
  status: 'safe' | 'at_risk' | 'vulnerable' | 'broken';
  recommendation: string;
}

interface EntropyResult {
  timestamp: string;
  source: string;
  renyi_orders: { alpha: number; entropy: number }[];
  anomaly_detected: boolean;
  detection_type: string | null;
  confidence: number | null;
}

// ─── Status helpers ───────────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score > 70) return 'var(--success)';
  if (score >= 40) return 'var(--warning)';
  return 'var(--danger)';
}

function statusBadge(status: string) {
  const map: Record<string, { bg: string; text: string; label: string }> = {
    safe: { bg: 'bg-[var(--success)]/10', text: 'text-[var(--success)]', label: 'Safe' },
    at_risk: { bg: 'bg-[var(--warning)]/10', text: 'text-[var(--warning)]', label: 'At Risk' },
    vulnerable: { bg: 'bg-[var(--brand-accent)]/10', text: 'text-[var(--brand-accent)]', label: 'Vulnerable' },
    broken: { bg: 'bg-[var(--danger)]/10', text: 'text-[var(--danger)]', label: 'Broken' },
  };
  const s = map[status] || map.safe;
  return (
    <span className={cn('inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold border', s.bg, s.text, `border-current/20`)}>
      {status === 'safe' && <CheckCircle size={12} />}
      {status === 'at_risk' && <AlertTriangle size={12} />}
      {status === 'vulnerable' && <AlertTriangle size={12} />}
      {status === 'broken' && <XCircle size={12} />}
      {s.label}
    </span>
  );
}

function timelineBarColor(status: string): string {
  if (status === 'safe') return 'var(--success)';
  if (status === 'at_risk') return 'var(--warning)';
  if (status === 'vulnerable') return 'var(--brand-accent)';
  return 'var(--danger)';
}

// ─── Fallback data ────────────────────────────────────────────────────────────

const FALLBACK_READINESS: QuantumReadiness = {
  score: 0,
  quantum_safe_count: 0,
  total_assets: 0,
  last_assessed: null,
};

const FALLBACK_TIMELINE: CryptoTimelineEntry[] = [
  { algorithm: 'RSA-2048', key_bits: 2048, type: 'Asymmetric', vulnerable_by: 2030, status: 'at_risk' },
  { algorithm: 'RSA-4096', key_bits: 4096, type: 'Asymmetric', vulnerable_by: 2035, status: 'at_risk' },
  { algorithm: 'ECDSA-256', key_bits: 256, type: 'Asymmetric', vulnerable_by: 2029, status: 'vulnerable' },
  { algorithm: 'AES-128', key_bits: 128, type: 'Symmetric', vulnerable_by: 2035, status: 'at_risk' },
  { algorithm: 'AES-256', key_bits: 256, type: 'Symmetric', vulnerable_by: 2050, status: 'safe' },
  { algorithm: 'SHA-256', key_bits: 256, type: 'Hash', vulnerable_by: 2040, status: 'safe' },
  { algorithm: 'ChaCha20', key_bits: 256, type: 'Symmetric', vulnerable_by: 2050, status: 'safe' },
  { algorithm: 'ED25519', key_bits: 256, type: 'Asymmetric', vulnerable_by: 2029, status: 'vulnerable' },
  { algorithm: 'Dilithium', key_bits: 2048, type: 'PQC', vulnerable_by: 2070, status: 'safe' },
  { algorithm: 'CRYSTALS-Kyber', key_bits: 1024, type: 'PQC', vulnerable_by: 2070, status: 'safe' },
];

const FALLBACK_ASSESSMENTS: AlgorithmAssessment[] = [
  { algorithm: 'RSA-2048', key_bits: 2048, type: 'Asymmetric', classical_security: '112-bit', quantum_security: '~0-bit (Shor)', status: 'vulnerable', recommendation: 'Migrate to CRYSTALS-Kyber or ML-KEM' },
  { algorithm: 'RSA-4096', key_bits: 4096, type: 'Asymmetric', classical_security: '140-bit', quantum_security: '~0-bit (Shor)', status: 'at_risk', recommendation: 'Migrate to CRYSTALS-Kyber or ML-KEM' },
  { algorithm: 'ECDSA-256', key_bits: 256, type: 'Asymmetric', classical_security: '128-bit', quantum_security: '~0-bit (Shor)', status: 'vulnerable', recommendation: 'Migrate to Dilithium or SLH-DSA' },
  { algorithm: 'ED25519', key_bits: 256, type: 'Asymmetric', classical_security: '128-bit', quantum_security: '~0-bit (Shor)', status: 'vulnerable', recommendation: 'Migrate to Dilithium or SLH-DSA' },
  { algorithm: 'AES-128', key_bits: 128, type: 'Symmetric', classical_security: '128-bit', quantum_security: '64-bit (Grover)', status: 'at_risk', recommendation: 'Upgrade to AES-256' },
  { algorithm: 'AES-256', key_bits: 256, type: 'Symmetric', classical_security: '256-bit', quantum_security: '128-bit (Grover)', status: 'safe', recommendation: 'Continue use, quantum-resistant' },
  { algorithm: 'ChaCha20', key_bits: 256, type: 'Symmetric', classical_security: '256-bit', quantum_security: '128-bit (Grover)', status: 'safe', recommendation: 'Continue use, quantum-resistant' },
  { algorithm: 'SHA-256', key_bits: 256, type: 'Hash', classical_security: '256-bit', quantum_security: '128-bit (Grover)', status: 'safe', recommendation: 'Continue use, quantum-resistant' },
  { algorithm: 'Dilithium', key_bits: 2048, type: 'PQC', classical_security: '128-bit', quantum_security: '128-bit', status: 'safe', recommendation: 'NIST standard, recommended for signatures' },
  { algorithm: 'CRYSTALS-Kyber', key_bits: 1024, type: 'PQC', classical_security: '128-bit', quantum_security: '128-bit', status: 'safe', recommendation: 'NIST standard, recommended for key encapsulation' },
];

// ─── Component ────────────────────────────────────────────────────────────────

// Check if an API error indicates an upgrade is required
function isUpgradeRequired(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  // Check for 403 status with upgrade_required in body
  if ('status' in err && (err as { status: number }).status === 403) {
    try {
      const msg = (err as { message?: string }).message || '';
      const parsed = JSON.parse(msg);
      return parsed.upgrade_required === true;
    } catch {
      // Body might contain "upgrade_required" as a string
      return ((err as { message?: string }).message || '').includes('upgrade_required');
    }
  }
  return false;
}

// Check if a successful response signals an upgrade is needed
function responseNeedsUpgrade(data: unknown): boolean {
  return !!data && typeof data === 'object' && 'upgrade_required' in data && (data as Record<string, unknown>).upgrade_required === true;
}

type GatedSection = 'timeline' | 'assessments' | 'entropy';

export default function QuantumPage() {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const router = useRouter();
  const [readiness, setReadiness] = useState<QuantumReadiness>(FALLBACK_READINESS);
  const [timeline, setTimeline] = useState<CryptoTimelineEntry[]>(FALLBACK_TIMELINE);
  const [assessments, setAssessments] = useState<AlgorithmAssessment[]>(FALLBACK_ASSESSMENTS);
  const [entropy, setEntropy] = useState<EntropyResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [usingFallback, setUsingFallback] = useState(false);
  const [gatedSections, setGatedSections] = useState<Set<GatedSection>>(new Set());
  const [showUpgradeModal, setShowUpgradeModal] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    let usedFallback = false;
    const gated = new Set<GatedSection>();

    // Readiness is available to all tiers
    try {
      const raw = await api.quantum.readiness() as Record<string, unknown>;
      if (responseNeedsUpgrade(raw)) {
        usedFallback = true;
      } else {
        const summary = (raw.summary || {}) as Record<string, unknown>;
        setReadiness({
          score: (raw.quantum_readiness_score ?? raw.score ?? 0) as number,
          quantum_safe_count: (summary.quantum_safe ?? raw.quantum_safe_count ?? 0) as number,
          total_assets: (summary.total_algorithms_tracked ?? raw.total_assets ?? 0) as number,
          last_assessed: (raw.assessed_at ?? raw.last_assessed ?? null) as string | null,
        });
      }
    } catch (err) {
      usedFallback = true;
      if (isUpgradeRequired(err)) {
        // Readiness still shows fallback data, no gating needed
      }
      // Calculate readiness from fallback assessments
      const safeCount = FALLBACK_ASSESSMENTS.filter(a => a.status === 'safe').length;
      setReadiness({
        score: Math.round((safeCount / FALLBACK_ASSESSMENTS.length) * 100),
        quantum_safe_count: safeCount,
        total_assets: FALLBACK_ASSESSMENTS.length,
        last_assessed: null,
      });
    }

    try {
      const data = await api.quantum.timeline();
      if (responseNeedsUpgrade(data)) {
        gated.add('timeline');
      } else {
        setTimeline(data as CryptoTimelineEntry[]);
      }
    } catch (err) {
      if (isUpgradeRequired(err)) {
        gated.add('timeline');
      }
      usedFallback = true;
    }

    try {
      const data = await api.quantum.assessAll();
      if (responseNeedsUpgrade(data)) {
        gated.add('assessments');
      } else {
        setAssessments(data as AlgorithmAssessment[]);
      }
    } catch (err) {
      if (isUpgradeRequired(err)) {
        gated.add('assessments');
      }
      usedFallback = true;
    }

    try {
      const data = await api.quantum.entropy('system_check');
      if (responseNeedsUpgrade(data)) {
        gated.add('entropy');
      } else if (data && Array.isArray(data)) {
        setEntropy(data as EntropyResult[]);
      }
    } catch (err) {
      if (isUpgradeRequired(err)) {
        gated.add('entropy');
      }
      // Entropy is optional
    }

    setGatedSections(gated);
    setUsingFallback(usedFallback);
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const currentYear = new Date().getFullYear();
  const timelineStart = currentYear;
  const timelineEnd = 2050;
  const timelineRange = timelineEnd - timelineStart;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-10 h-10 rounded-xl bg-card border border-border flex items-center justify-center">
              <Atom className="text-[var(--brand)]" size={20} />
            </div>
            <div>
              <h1 className="text-2xl font-semibold text-foreground tracking-tight">Quantum Security</h1>
              <p className="text-sm text-muted-foreground mt-0.5">
                Post-quantum cryptography assessment and advanced entropy analysis
              </p>
            </div>
          </div>
        </div>
        {usingFallback && (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--warning)]/10 border border-[var(--warning)]/20">
            <Info size={14} className="text-[var(--warning)]" />
            <span className="text-[12px] text-[var(--warning)] font-medium">Using reference data</span>
          </div>
        )}
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 size={24} className="text-[var(--brand)] animate-spin" />
        </div>
      ) : (
        <>
          {/* Quantum Readiness Score */}
          <div className="bg-card border border-border rounded-2xl p-6">
            <h2 className="text-sm font-semibold text-muted-foreground tracking-wide uppercase mb-6">Quantum Readiness Score</h2>
            <div className="flex items-center gap-8">
              <div className="relative w-36 h-36 shrink-0">
                <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
                  <circle cx="60" cy="60" r="52" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
                  <circle
                    cx="60" cy="60" r="52"
                    fill="none"
                    stroke={scoreColor(readiness.score)}
                    strokeWidth="8"
                    strokeLinecap="round"
                    strokeDasharray={`${(readiness.score / 100) * 2 * Math.PI * 52} ${2 * Math.PI * 52}`}
                    className="transition-all duration-1000"
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-data text-3xl font-bold" style={{ color: scoreColor(readiness.score) }}>
                    {readiness.score}
                  </span>
                  <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider">Score</span>
                </div>
              </div>
              <div className="space-y-3 flex-1">
                <p className="text-sm text-foreground/80">
                  <span className="text-data font-semibold" style={{ color: scoreColor(readiness.score) }}>
                    {readiness.quantum_safe_count}
                  </span>
                  <span className="text-muted-foreground"> of </span>
                  <span className="text-data font-semibold text-foreground">{readiness.total_assets}</span>
                  <span className="text-muted-foreground"> algorithms are quantum-safe</span>
                </p>
                <div className="grid grid-cols-4 gap-3">
                  {(['safe', 'at_risk', 'vulnerable', 'broken'] as const).map(status => {
                    const count = assessments.filter(a => a.status === status).length;
                    return (
                      <div key={status} className="bg-background rounded-xl p-3 border border-border">
                        <p className="text-data text-lg font-bold text-foreground">{count}</p>
                        <p className="text-[10px] text-muted-foreground uppercase tracking-wider mt-0.5">
                          {status.replace('_', ' ')}
                        </p>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>

          {/* Crypto Vulnerability Timeline */}
          <div className="bg-card border border-border rounded-2xl p-6">
            <h2 className="text-sm font-semibold text-muted-foreground tracking-wide uppercase mb-6">
              Crypto Vulnerability Timeline
            </h2>
            {gatedSections.has('timeline') ? (
              <UpgradeGateBanner
                feature="Crypto Vulnerability Timeline"
                onUpgrade={() => setShowUpgradeModal(true)}
              />
            ) : (
            <div className="space-y-2">
              {/* Year axis */}
              <div className="flex items-center ml-[140px] mb-4">
                {Array.from({ length: 6 }, (_, i) => {
                  const year = timelineStart + Math.round((i / 5) * timelineRange);
                  return (
                    <span
                      key={year}
                      className="text-data text-[10px] text-muted-foreground/60"
                      style={{ position: 'absolute', left: `calc(140px + ${(i / 5) * 100}% * (1 - 140/100))` }}
                    >
                      {year}
                    </span>
                  );
                })}
              </div>
              {/* Year markers row */}
              <div className="relative h-5 ml-[140px] mr-4 mb-2">
                {[0, 0.2, 0.4, 0.6, 0.8, 1].map((pct, i) => {
                  const year = timelineStart + Math.round(pct * timelineRange);
                  return (
                    <span
                      key={i}
                      className="absolute text-data text-[10px] text-muted-foreground/60 -translate-x-1/2"
                      style={{ left: `${pct * 100}%` }}
                    >
                      {year}
                    </span>
                  );
                })}
              </div>
              {/* Bars */}
              {timeline.map(entry => {
                const vulnerableYear = Math.min(entry.vulnerable_by, timelineEnd);
                const barWidth = Math.max(0, ((vulnerableYear - timelineStart) / timelineRange) * 100);
                return (
                  <div key={entry.algorithm} className="flex items-center gap-3 group">
                    <div className="w-[128px] shrink-0 text-right">
                      <span className="text-data text-[12px] text-foreground/80 font-medium">{entry.algorithm}</span>
                    </div>
                    <div className="flex-1 h-7 bg-background rounded-md relative overflow-hidden border border-border/30">
                      <div
                        className="h-full rounded-md transition-all duration-700 relative"
                        style={{
                          width: `${Math.min(barWidth, 100)}%`,
                          backgroundColor: timelineBarColor(entry.status),
                          opacity: 0.7,
                        }}
                      >
                        <div
                          className="absolute inset-0 rounded-md"
                          style={{
                            background: `linear-gradient(90deg, ${timelineBarColor(entry.status)}33, ${timelineBarColor(entry.status)}cc)`,
                          }}
                        />
                      </div>
                      <div className="absolute inset-0 flex items-center justify-end pr-2 pointer-events-none">
                        <span className="text-data text-[10px] text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity">
                          {entry.status === 'safe' ? 'Safe beyond 2050' : `Vulnerable by ${entry.vulnerable_by}`}
                        </span>
                      </div>
                    </div>
                    <div className="w-[80px] shrink-0">{statusBadge(entry.status)}</div>
                  </div>
                );
              })}
              {/* Legend */}
              <div className="flex items-center gap-6 mt-4 pt-4 border-t border-border">
                {[
                  { color: 'var(--success)', label: 'Quantum-Safe' },
                  { color: 'var(--warning)', label: 'At Risk' },
                  { color: 'var(--brand-accent)', label: 'Vulnerable' },
                  { color: 'var(--danger)', label: 'Broken' },
                ].map(l => (
                  <div key={l.label} className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: l.color, opacity: 0.7 }} />
                    <span className="text-[11px] text-muted-foreground">{l.label}</span>
                  </div>
                ))}
              </div>
            </div>
            )}
          </div>

          {/* Algorithm Assessment Table */}
          <div className="bg-card border border-border rounded-2xl p-6">
            <h2 className="text-sm font-semibold text-muted-foreground tracking-wide uppercase mb-4">
              Algorithm Assessment
            </h2>
            {gatedSections.has('assessments') ? (
              <UpgradeGateBanner
                feature="Algorithm Assessment"
                onUpgrade={() => setShowUpgradeModal(true)}
              />
            ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-border">
                    {['Algorithm', 'Key Bits', 'Type', 'Classical Security', 'Quantum Security', 'Status', 'Recommendation'].map(h => (
                      <th key={h} className="text-[10px] font-semibold text-muted-foreground/60 uppercase tracking-widest pb-3 pr-4 whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {assessments.map(a => (
                    <tr key={a.algorithm} className="border-b border-border/30 hover:bg-white/[0.02] transition-colors">
                      <td className="py-3 pr-4">
                        <span className="text-data text-[13px] text-foreground font-medium">{a.algorithm}</span>
                      </td>
                      <td className="py-3 pr-4">
                        <span className="text-data text-[12px] text-muted-foreground">{a.key_bits}</span>
                      </td>
                      <td className="py-3 pr-4">
                        <span className={cn(
                          'text-[11px] font-medium px-2 py-0.5 rounded-full border',
                          a.type === 'PQC'
                            ? 'bg-[var(--brand)]/10 text-[var(--brand)] border-[var(--brand)]/20'
                            : a.type === 'Symmetric'
                              ? 'bg-[#A78BFA]/10 text-[#A78BFA] border-[#A78BFA]/20'
                              : a.type === 'Hash'
                                ? 'bg-zinc-500/10 text-muted-foreground border-zinc-500/20'
                                : 'bg-[var(--brand-accent)]/10 text-[var(--brand-accent)] border-[var(--brand-accent)]/20'
                        )}>
                          {a.type}
                        </span>
                      </td>
                      <td className="py-3 pr-4">
                        <span className="text-data text-[12px] text-foreground/80">{a.classical_security}</span>
                      </td>
                      <td className="py-3 pr-4">
                        <span className={cn(
                          'text-data text-[12px]',
                          a.quantum_security.includes('~0') ? 'text-[var(--danger)]' : 'text-foreground/80'
                        )}>
                          {a.quantum_security}
                        </span>
                      </td>
                      <td className="py-3 pr-4">{statusBadge(a.status)}</td>
                      <td className="py-3">
                        <span className="text-[12px] text-muted-foreground leading-relaxed">{a.recommendation}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            )}
          </div>

          {/* Entropy Analysis */}
          {(entropy.length > 0 || gatedSections.has('entropy')) && (
            <div className="bg-card border border-border rounded-2xl p-6">
              <h2 className="text-sm font-semibold text-muted-foreground tracking-wide uppercase mb-4">
                Entropy Analysis
              </h2>
              {gatedSections.has('entropy') ? (
                <UpgradeGateBanner
                  feature="Advanced Entropy Analysis"
                  onUpgrade={() => setShowUpgradeModal(true)}
                />
              ) : (
              <div className="space-y-4">
                {entropy.map((result, idx) => (
                  <div key={idx} className="bg-background rounded-xl p-4 border border-border">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-2">
                        <span className="text-data text-[12px] text-foreground/80">{result.source}</span>
                        {result.anomaly_detected && (
                          <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-[var(--danger)]/10 text-[var(--danger)] text-[10px] font-semibold border border-[var(--danger)]/20">
                            <AlertTriangle size={10} />
                            {result.detection_type || 'Anomaly'}
                          </span>
                        )}
                      </div>
                      <span className="text-data text-[10px] text-muted-foreground/60">
                        {result.timestamp ? new Date(result.timestamp).toLocaleString() : ''}
                      </span>
                    </div>
                    {/* Renyi entropy bars */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      {result.renyi_orders.map(order => (
                        <div key={order.alpha} className="space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] text-muted-foreground/60">alpha={order.alpha}</span>
                            <span className="text-data text-[11px] text-foreground/80">{order.entropy.toFixed(4)}</span>
                          </div>
                          <div className="h-1.5 bg-white/[0.04] rounded-full overflow-hidden">
                            <div
                              className="h-full rounded-full transition-all duration-500"
                              style={{
                                width: `${Math.min(order.entropy * 12.5, 100)}%`,
                                backgroundColor: order.entropy > 7 ? 'var(--success)' : order.entropy > 5 ? 'var(--warning)' : 'var(--danger)',
                              }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                    {result.confidence !== null && (
                      <div className="mt-3 pt-3 border-t border-border">
                        <span className="text-[11px] text-muted-foreground">
                          Detection confidence: <span className="text-data text-foreground/80">{(result.confidence * 100).toFixed(1)}%</span>
                        </span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Upgrade Modal */}
      {showUpgradeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setShowUpgradeModal(false)} />
          <div className="relative bg-card border border-border rounded-2xl p-8 max-w-md w-full shadow-2xl">
            <button
              onClick={() => setShowUpgradeModal(false)}
              className="absolute top-4 right-4 text-muted-foreground hover:text-foreground transition-colors"
            >
              <X size={20} />
            </button>
            <div className="text-center mb-6">
              <div className="inline-flex items-center justify-center w-14 h-14 rounded-xl bg-[var(--brand)]/10 border border-[var(--brand)]/20 mb-4">
                <Atom size={28} className="text-[var(--brand)]" />
              </div>
              <h3 className="text-xl font-bold text-foreground">Upgrade to Enterprise</h3>
              <p className="text-sm text-muted-foreground mt-2">
                Unlock the full Quantum Security module with real-time cryptographic assessment of your infrastructure.
              </p>
            </div>
            <div className="space-y-2 mb-6">
              {[
                'Live cryptographic inventory of your assets',
                'Real-time vulnerability timeline updates',
                'Advanced Renyi entropy analysis',
                'AI-powered migration recommendations',
              ].map(f => (
                <div key={f} className="flex items-center gap-2 text-sm text-foreground/80">
                  <Check size={16} className="text-[var(--brand)] flex-shrink-0" />
                  {f}
                </div>
              ))}
            </div>
            <button
              onClick={() => {
                setShowUpgradeModal(false);
                router.push('/dashboard/settings');
              }}
              className="w-full bg-[var(--brand)] hover:bg-[var(--brand)] text-[#09090B] font-semibold py-3 rounded-xl transition-all duration-200 hover:shadow-lg hover:shadow-[var(--brand)]/20 active:scale-[0.98] flex items-center justify-center gap-2"
            >
              <Crown size={16} />
              Upgrade to Enterprise
            </button>
            <button
              onClick={() => setShowUpgradeModal(false)}
              className="w-full mt-2 py-2 text-sm text-muted-foreground hover:text-foreground/80 transition-colors"
            >
              Maybe later
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Upgrade Gate Banner ─────────────────────────────────────────────────────

function UpgradeGateBanner({ feature, onUpgrade }: { feature: string; onUpgrade: () => void }) {
  return (
    <div className="rounded-xl border border-[var(--brand)]/10 bg-[var(--brand)]/[0.03] p-6 flex flex-col items-center text-center">
      <div className="w-10 h-10 rounded-xl bg-[var(--brand)]/10 border border-[var(--brand)]/20 flex items-center justify-center mb-3">
        <Lock size={18} className="text-[var(--brand)]" />
      </div>
      <p className="text-sm font-medium text-foreground mb-1">Upgrade to unlock full analysis</p>
      <p className="text-xs text-muted-foreground mb-4">
        {feature} requires an Enterprise subscription for live data from your infrastructure.
      </p>
      <button
        onClick={onUpgrade}
        className="px-5 py-2 rounded-xl bg-[var(--brand)]/10 border border-[var(--brand)]/20 text-[var(--brand)] text-sm font-medium hover:bg-[var(--brand)]/20 transition-all duration-200 flex items-center gap-2"
      >
        <Crown size={14} />
        Upgrade to Enterprise
      </button>
    </div>
  );
}
