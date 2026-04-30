'use client';

import { useEffect, useState } from 'react';
import { Sparkles, ArrowRight, Loader2, Check } from 'lucide-react';
import { api, DeceptionCampaign } from '@/lib/api';
import { cn } from '@/lib/utils';

interface ThemeOption {
  name: string;
  label: string;
  description: string;
  industry: string;
  bait_kinds: string[];
}

interface Props {
  open: boolean;
  onClose: () => void;
  onCreated: (campaign: DeceptionCampaign) => void;
}

type Step = 'theme' | 'mix' | 'count' | 'review';

const STEPS: { id: Step; label: string }[] = [
  { id: 'theme', label: 'Theme' },
  { id: 'mix', label: 'Service Mix' },
  { id: 'count', label: 'Decoy Count' },
  { id: 'review', label: 'Deploy' },
];

export function CampaignBuilder({ open, onClose, onCreated }: Props) {
  const [step, setStep] = useState<Step>('theme');
  const [themes, setThemes] = useState<ThemeOption[]>([]);
  const [name, setName] = useState('fake_fintech_lite');
  const [theme, setTheme] = useState('fintech');
  const [decoyCount, setDecoyCount] = useState(50);
  const [rotationHours, setRotationHours] = useState(6);
  const [mix, setMix] = useState({ web: 40, db: 30, files: 20, admin: 10 });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    api.deception
      .themes()
      .then(setThemes)
      .catch(() => setThemes([]));
  }, [open]);

  if (!open) return null;

  const mixTotal = mix.web + mix.db + mix.files + mix.admin;

  const handleDeploy = async () => {
    if (mixTotal !== 100) {
      setError('Service mix must sum to 100%');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const created = await api.deception.createCampaign({
        name,
        theme,
        decoy_count: decoyCount,
        service_mix: mix,
        rotation_hours: rotationHours,
      });
      onCreated(created);
      onClose();
      // reset for next open
      setStep('theme');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Deploy failed');
    } finally {
      setSubmitting(false);
    }
  };

  const stepIdx = STEPS.findIndex((s) => s.id === step);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="px-6 py-4 border-b border-white/[0.06] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-[var(--brand-accent)]/10 border border-[var(--brand-accent)]/30 flex items-center justify-center">
              <Sparkles className="w-4 h-4 text-[var(--brand-accent)]" />
            </div>
            <div>
              <h2 className="text-[16px] font-semibold text-white">New Deception Campaign</h2>
              <p className="text-[12px] text-zinc-500 mt-0.5">
                Step {stepIdx + 1} of {STEPS.length} — {STEPS[stepIdx].label}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-zinc-500 hover:text-white text-[13px]"
          >
            Close
          </button>
        </div>

        {/* Progress */}
        <div className="px-6 pt-4 flex gap-2">
          {STEPS.map((s, i) => (
            <div
              key={s.id}
              className={cn(
                'flex-1 h-1 rounded-full',
                i <= stepIdx ? 'bg-[var(--brand-accent)]' : 'bg-white/[0.06]',
              )}
            />
          ))}
        </div>

        {/* Body */}
        <div className="p-6">
          {step === 'theme' && (
            <div className="space-y-4">
              <div>
                <label className="text-[12px] text-zinc-500 uppercase tracking-wide">
                  Campaign Name
                </label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="mt-1 w-full px-3 py-2 bg-[#09090B] border border-white/[0.06] rounded-lg text-white text-[14px] focus:border-[var(--brand-accent)] focus:outline-none"
                />
              </div>
              <div>
                <label className="text-[12px] text-zinc-500 uppercase tracking-wide">
                  Theme
                </label>
                <div className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {(themes.length
                    ? themes
                    : [
                        { name: 'fintech', label: 'Fintech', description: 'Banking, payments, wallets', industry: 'finance', bait_kinds: [] },
                        { name: 'healthcare', label: 'Healthcare', description: 'EHR, claims, patient data', industry: 'healthcare', bait_kinds: [] },
                        { name: 'ecommerce', label: 'E-commerce', description: 'Orders, customers, payments', industry: 'retail', bait_kinds: [] },
                        { name: 'devops', label: 'DevOps', description: 'CI/CD secrets, k8s, cloud keys', industry: 'devops', bait_kinds: [] },
                      ]
                  ).map((t) => (
                    <button
                      key={t.name}
                      type="button"
                      onClick={() => setTheme(t.name)}
                      className={cn(
                        'text-left px-3 py-3 rounded-lg border transition-colors',
                        theme === t.name
                          ? 'bg-[var(--brand-accent)]/10 border-[var(--brand-accent)]/40'
                          : 'bg-[#09090B] border-white/[0.06] hover:border-white/[0.14]',
                      )}
                    >
                      <div className="text-[13px] font-semibold text-white flex items-center gap-2">
                        {t.label}
                        {theme === t.name && <Check className="w-3 h-3 text-[var(--brand-accent)]" />}
                      </div>
                      <div className="text-[11px] text-zinc-500 mt-1">{t.description}</div>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {step === 'mix' && (
            <div className="space-y-4">
              <p className="text-[12px] text-zinc-500">
                Distribute percentages across decoy kinds. Must sum to 100.
              </p>
              {(['web', 'db', 'files', 'admin'] as const).map((kind) => (
                <div key={kind}>
                  <div className="flex items-center justify-between text-[12px]">
                    <span className="text-zinc-400 capitalize">{kind}</span>
                    <span className="font-mono text-white">{mix[kind]}%</span>
                  </div>
                  <input
                    type="range"
                    min={0}
                    max={100}
                    value={mix[kind]}
                    onChange={(e) =>
                      setMix({ ...mix, [kind]: parseInt(e.target.value, 10) })
                    }
                    className="w-full mt-1 accent-[var(--brand-accent)]"
                  />
                </div>
              ))}
              <div
                className={cn(
                  'text-[12px] px-3 py-2 rounded-lg border',
                  mixTotal === 100
                    ? 'text-emerald-400 bg-emerald-500/5 border-emerald-500/20'
                    : 'text-amber-400 bg-amber-500/5 border-amber-500/20',
                )}
              >
                Total: {mixTotal}% {mixTotal !== 100 && ' — must be 100'}
              </div>
            </div>
          )}

          {step === 'count' && (
            <div className="space-y-4">
              <div>
                <label className="text-[12px] text-zinc-500 uppercase tracking-wide">
                  Decoy Count
                </label>
                <input
                  type="range"
                  min={5}
                  max={200}
                  value={decoyCount}
                  onChange={(e) => setDecoyCount(parseInt(e.target.value, 10))}
                  className="w-full mt-2 accent-[var(--brand-accent)]"
                />
                <div className="text-[22px] font-bold text-white mt-1 font-mono">
                  {decoyCount}
                </div>
                <div className="text-[11px] text-zinc-500">fake services to spin up</div>
              </div>
              <div>
                <label className="text-[12px] text-zinc-500 uppercase tracking-wide">
                  Rotation (hours)
                </label>
                <input
                  type="number"
                  value={rotationHours}
                  min={1}
                  max={168}
                  onChange={(e) => setRotationHours(parseInt(e.target.value, 10))}
                  className="mt-1 w-full px-3 py-2 bg-[#09090B] border border-white/[0.06] rounded-lg text-white text-[14px] focus:border-[var(--brand-accent)] focus:outline-none"
                />
              </div>
            </div>
          )}

          {step === 'review' && (
            <div className="space-y-3 text-[13px]">
              <ReviewRow label="Name" value={name} />
              <ReviewRow label="Theme" value={theme} />
              <ReviewRow label="Decoy count" value={decoyCount.toString()} />
              <ReviewRow
                label="Mix"
                value={`web ${mix.web} / db ${mix.db} / files ${mix.files} / admin ${mix.admin}`}
              />
              <ReviewRow label="Rotation" value={`${rotationHours}h`} />
              {error && (
                <div className="text-[12px] text-red-400 px-3 py-2 bg-red-500/5 border border-red-500/20 rounded-lg">
                  {error}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-white/[0.06] flex items-center justify-between gap-3">
          <button
            type="button"
            onClick={() => {
              if (stepIdx === 0) {
                onClose();
              } else {
                setStep(STEPS[stepIdx - 1].id);
              }
            }}
            className="text-[13px] text-zinc-400 hover:text-white px-3 py-2"
          >
            {stepIdx === 0 ? 'Cancel' : 'Back'}
          </button>
          {stepIdx < STEPS.length - 1 ? (
            <button
              type="button"
              disabled={step === 'mix' && mixTotal !== 100}
              onClick={() => setStep(STEPS[stepIdx + 1].id)}
              className="flex items-center gap-2 bg-[var(--brand-accent)] hover:bg-[var(--brand-accent)] disabled:opacity-40 disabled:cursor-not-allowed text-[#09090B] font-semibold px-4 py-2 rounded-lg text-[13px] transition-colors"
            >
              Next <ArrowRight className="w-3.5 h-3.5" />
            </button>
          ) : (
            <button
              type="button"
              disabled={submitting}
              onClick={handleDeploy}
              className="flex items-center gap-2 bg-[var(--brand-accent)] hover:bg-[var(--brand-accent)] disabled:opacity-40 text-[#09090B] font-semibold px-4 py-2 rounded-lg text-[13px] transition-colors"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" /> Deploying
                </>
              ) : (
                <>
                  Deploy Campaign <Sparkles className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function ReviewRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between px-3 py-2 bg-[#09090B] border border-white/[0.06] rounded-lg">
      <span className="text-zinc-500 text-[12px] uppercase tracking-wide">{label}</span>
      <span className="text-white font-mono text-[13px]">{value}</span>
    </div>
  );
}
