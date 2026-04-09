'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import {
  Activity, Globe, Zap, Bug, Fingerprint, Flame,
  Bot, ArrowRight, ArrowLeft,
  ShieldCheck, ChevronRight, BookOpen, Crown, Layers,
  X, Check, AlertTriangle,
} from 'lucide-react';

interface TourStep {
  icon: typeof Activity;
  color: string;
  title: string;
  subtitle: string;
  description: string;
  highlights: string[];
  tip: string;
  action: { label: string; href: string };
}

const STEPS: TourStep[] = [
  {
    icon: BookOpen,
    color: '#22D3EE',
    title: 'Welcome to AEGIS',
    subtitle: 'Your autonomous cybersecurity platform',
    description: 'AEGIS detects, analyzes, and neutralizes cyber threats without human intervention. From the moment you deploy it, 5 detection layers work simultaneously to protect your infrastructure.',
    highlights: [
      'Everything runs autonomously — zero human approval needed',
      '18-microsecond detection in the first layer',
      '11/11 verified attack detection score',
      'Self-hosted: your data never leaves your servers',
    ],
    tip: 'AEGIS works out of the box. The AI features activate when you add an OpenRouter or Ollama API key in Settings.',
    action: { label: 'Continue the tour', href: '' },
  },
  {
    icon: Layers,
    color: '#22D3EE',
    title: 'The 5-Layer Pipeline',
    subtitle: 'How AEGIS catches everything',
    description: 'Every request to your server passes through 5 detection layers. Each layer catches what the previous one missed. The fast path resolves known threats in <300ms without even calling the AI.',
    highlights: [
      'L1: Attack Detector — regex + URL decode on every request (18us)',
      'L2: Log Watcher — monitors PM2/syslog for security patterns in real-time',
      'L3: Sigma Correlation — 122 rules + 5 chain rules detect multi-step attacks',
      'L4: AI Triage — classifies unknown threats + maps to MITRE ATT&CK',
      'L5: Auto-Response — executes playbooks + blocks IPs autonomously',
    ],
    tip: 'The fast path (L1->L3->Playbook) resolves in <300ms without AI. Only complex/unknown threats trigger the full AI triage (2-5s).',
    action: { label: 'See it live', href: '/dashboard' },
  },
  {
    icon: Activity,
    color: '#22D3EE',
    title: 'Live Dashboard',
    subtitle: 'Real-time SOC command center',
    description: 'The Dashboard is your main screen. It uses WebSocket streaming to push every event to your browser instantly — no polling, no refresh needed. Every attack, every blocked IP, every honeypot interaction appears the moment it happens.',
    highlights: [
      'Live attack feed — new incidents slide in with severity colors',
      'Global threat map — pulsing dots show attacker locations',
      'Events/sec chart — 60-second rolling line chart',
      'Top 10 attackers, targets, and attack types (updates every 2s)',
      'Raw log stream — scrolling terminal with color-coded levels',
      'Node heartbeat grid — green/red dots for every endpoint agent',
    ],
    tip: 'Open the Dashboard and keep it on a second monitor. When you get attacked, you will see it instantly.',
    action: { label: 'Open Dashboard', href: '/dashboard' },
  },
  {
    icon: Globe,
    color: '#34D399',
    title: 'Surface — Attack Surface Management',
    subtitle: 'Discover everything exposed on your network',
    description: 'Surface finds every service running on your infrastructure. It uses nmap to scan 150+ ports, then passes results through AI for intelligent identification. You will see exactly what is exposed and how risky it is.',
    highlights: [
      'Auto-discovery with AI enrichment (identifies Next.js, PostgreSQL, etc.)',
      'Vulnerability scanning via Nuclei templates',
      'AI risk score per asset (0-100) with color coding',
      'Scheduled scans: full every 2 hours, quick every 30 minutes',
      'Hardening checks with step-by-step remediation',
    ],
    tip: 'Start here. Put your server IP in the scan field and let AEGIS discover what you are running. The AI will tell you what it found.',
    action: { label: 'Scan your network', href: '/dashboard/surface' },
  },
  {
    icon: Zap,
    color: '#F87171',
    title: 'Response — Autonomous Incident Response',
    subtitle: 'AEGIS acts. You review.',
    description: 'When a threat is detected, AEGIS does not wait for you. It classifies the threat, decides the response, executes it, verifies it worked, and logs everything — all in seconds. Every AI decision includes reasoning, confidence score, and token cost.',
    highlights: [
      '10 deterministic playbooks execute in <50ms each',
      'AI triage: classify -> decide -> execute -> verify -> audit',
      'MITRE ATT&CK technique mapped to every incident',
      'Full audit trail: model used, reasoning, confidence, cost',
      'All actions auto-approved — override per action in Settings if needed',
    ],
    tip: 'By default, everything is autonomous (auto_approve). If you need human review for destructive actions like kill_process or isolate_host, change those guardrails in Settings.',
    action: { label: 'View incidents', href: '/dashboard/response' },
  },
  {
    icon: Bug,
    color: '#F97316',
    title: 'Phantom — Honeypot Deception',
    subtitle: 'Trap attackers with fake services',
    description: 'AEGIS deploys fake SSH servers and web applications that look real. When an attacker connects, it captures their credentials, commands, and tools. The killer feature: breadcrumb traps — fake .env files with trap API keys. When the attacker tries those keys on your real API, AEGIS instantly knows.',
    highlights: [
      'SSH honeypot on port 2222 — captures credentials and commands',
      'HTTP honeypot on port 8888 — rotates WordPress/Jenkins/phpMyAdmin',
      'Breadcrumb .env files with trap credentials',
      'Attacker profiling: tools, techniques, geolocation, MITRE mapping',
      'Template rotation every 4 hours to avoid fingerprinting',
    ],
    tip: 'The breadcrumb chain is the most powerful detection: attacker finds fake creds in honeypot -> tries on real API -> CRITICAL incident + auto-block. No one else does this.',
    action: { label: 'View honeypots', href: '/dashboard/phantom' },
  },
  {
    icon: Flame,
    color: '#EF4444',
    title: 'Ransomware Protection',
    subtitle: 'Detect, kill, and rollback in <500ms',
    description: 'The Rust node agent plants 10 hidden canary files across your user directories. If ransomware tries to encrypt them, AEGIS kills the entire process tree instantly and restores the affected files from shadow copies — all before the ransomware can finish.',
    highlights: [
      '10 hidden canary files in Documents/Desktop/Downloads',
      'Shannon entropy detection: >7.5 bits = encryption suspected',
      'Mass file extension change tracking (>20 in 5 seconds)',
      'Process tree killed via TerminateProcess / SIGKILL',
      'Auto-rollback: VSS (Windows), Btrfs/LVM (Linux)',
      'Complete forensic chain uploaded as CRITICAL incident',
    ],
    tip: 'This runs on the endpoint agent, not the server. Install the AEGIS Node Agent on every machine you want to protect.',
    action: { label: 'View response', href: '/dashboard/response' },
  },
  {
    icon: Fingerprint,
    color: '#A78BFA',
    title: 'EDR/XDR Core',
    subtitle: 'See everything. Miss nothing.',
    description: 'Enterprise endpoint detection using kernel-level telemetry. On Windows, AEGIS reads ETW (Event Tracing for Windows) for every process, network connection, and file write. On Linux, it uses eBPF programs. The backend reconstructs the full process tree so you can trace any attack chain.',
    highlights: [
      'ETW: Kernel-Process, Network, File, Registry, AMSI (Windows)',
      'eBPF: process exec, connect, openat, unlink (Linux)',
      'Process tree with ancestors + descendants for any process',
      '6 MITRE attack chain rules (macro malware, LOTL, credential dump)',
      'Tiered: works without admin (polling), better with admin (ETW/eBPF)',
    ],
    tip: 'Open the EDR page, enter a host and PID to see the full process tree. You can trace cmd.exe -> powershell.exe -> curl.exe chains in real time.',
    action: { label: 'Open EDR', href: '/dashboard/edr' },
  },
  {
    icon: ShieldCheck,
    color: '#10B981',
    title: 'Configurable Firewall',
    subtitle: 'Your rules. Hot reload.',
    description: 'Define custom detection rules in YAML or via the visual editor. Block SSH brute force, port scans, known scanner user-agents — or create your own logic. Rules apply in <1 second without restarting anything.',
    highlights: [
      'YAML DSL with CIDR matching, port, protocol, user-agent regex, rate limiting',
      'Actions: block_ip, allow (short-circuit), alert, quarantine_host',
      'Priority system: highest priority rule wins',
      'Rule tester: test against synthetic events before deploying',
      '6 built-in templates ready to use',
      'Hot reload: create -> save -> active in <1s',
    ],
    tip: 'Start with the templates. Click "Use Template" to clone a pre-built rule like "Block SSH brute force" and customize it.',
    action: { label: 'Create rules', href: '/dashboard/firewall' },
  },
  {
    icon: Bot,
    color: '#F97316',
    title: 'Honey-AI — Deception at Scale',
    subtitle: 'The killer differentiator',
    description: 'Deploy 50+ fake services that look real — fake web apps, REST APIs, and MySQL databases, all with AI-generated content. Every fake asset embeds a tracking UUID. When an attacker steals data from a fake service and tries to use it on a real one, AEGIS links the two events and raises a CRITICAL alert.',
    highlights: [
      'Deploy entire deception campaigns with one click',
      '4 industry themes: fintech, healthcare, ecommerce, devops',
      'AI generates realistic responses (LLM with Faker fallback)',
      'Smart HTTP: imitates Next.js/WordPress/Laravel',
      'Smart API: fake /api/users with plausible data',
      'Smart DB: MySQL wire protocol with fake schemas',
      'Breadcrumb UUID tracking across all fake assets',
    ],
    tip: 'This is what makes AEGIS unique. No other platform generates entire fake infrastructures to waste attackers\' time and reveal their methods.',
    action: { label: 'Build a campaign', href: '/dashboard/deception' },
  },
  {
    icon: Crown,
    color: '#FBBF24',
    title: 'You are ready.',
    subtitle: 'AEGIS is protecting you now.',
    description: 'Everything is autonomous. AEGIS is already watching your infrastructure, correlating events, profiling attackers, and executing response actions. Open the Dashboard to see it in action.',
    highlights: [
      'Open the Dashboard and watch threats arrive in real time',
      'Run a network scan in Surface to discover your assets',
      'Deploy honeypots in Phantom to trap the next attacker',
      'Create firewall rules to block known bad patterns',
      'Install the Node Agent on endpoints for ransomware + EDR protection',
      'Check Settings -> Feature Guide for a quick reference of all modules',
    ],
    tip: 'Bookmark the Dashboard. That is your home now.',
    action: { label: 'Go to Dashboard', href: '/dashboard' },
  },
];

export function GuideTour({ onClose }: { onClose: () => void }) {
  const router = useRouter();
  const [step, setStep] = useState(0);
  const current = STEPS[step];
  const isLast = step === STEPS.length - 1;
  const isFirst = step === 0;
  const progress = ((step + 1) / STEPS.length) * 100;

  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (e.key === 'ArrowRight' && !isLast) setStep(s => s + 1);
    if (e.key === 'ArrowLeft' && !isFirst) setStep(s => s - 1);
    if (e.key === 'Escape') onClose();
  }, [isLast, isFirst, onClose]);

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm animate-fade-in">
      <div className="absolute inset-0" onClick={onClose} />

      <div className="relative z-10 w-full max-w-3xl mx-4">
        {/* Progress bar */}
        <div className="w-full mb-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-mono text-zinc-500">
              Step {step + 1} of {STEPS.length}
            </span>
            <button
              onClick={onClose}
              className="text-[11px] text-zinc-600 hover:text-zinc-400 transition-colors flex items-center gap-1"
            >
              Skip tour <X className="w-3 h-3" />
            </button>
          </div>
          <div className="w-full h-1 rounded-full bg-white/[0.06] overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-500 ease-out"
              style={{ width: `${progress}%`, background: current.color }}
            />
          </div>
          <div className="flex items-center justify-center gap-1.5 mt-3">
            {STEPS.map((_, i) => (
              <button
                key={i}
                onClick={() => setStep(i)}
                className="transition-all duration-200"
                style={{
                  width: i === step ? 20 : 6,
                  height: 6,
                  borderRadius: 3,
                  background: i === step ? current.color : i < step ? `${current.color}60` : 'rgba(255,255,255,0.08)',
                }}
              />
            ))}
          </div>
        </div>

        {/* Card */}
        <div className="w-full rounded-2xl border border-white/[0.08] bg-[#111114] overflow-hidden max-h-[80vh] overflow-y-auto">
          <div className="p-8 pb-0">
            <div className="flex items-center gap-4 mb-6">
              <div
                className="w-14 h-14 rounded-2xl flex items-center justify-center shrink-0"
                style={{ background: `${current.color}12`, border: `1px solid ${current.color}25` }}
              >
                <current.icon className="w-7 h-7" style={{ color: current.color }} />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">{current.title}</h1>
                <p className="text-sm text-zinc-500 mt-0.5">{current.subtitle}</p>
              </div>
            </div>
            <p className="text-[14px] text-zinc-300 leading-relaxed mb-6">
              {current.description}
            </p>
          </div>

          <div className="px-8 pb-6">
            <div className="space-y-2">
              {current.highlights.map((h, i) => (
                <div
                  key={i}
                  className="flex items-start gap-3 text-[13px] text-zinc-400 bg-white/[0.02] rounded-lg px-4 py-2.5 border border-white/[0.04]"
                >
                  <Check className="w-4 h-4 shrink-0 mt-0.5" style={{ color: current.color }} />
                  <span>{h}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="mx-8 mb-6 rounded-xl border border-[#FBBF24]/15 bg-[#FBBF24]/[0.04] p-4">
            <div className="flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-[#FBBF24] shrink-0 mt-0.5" />
              <div>
                <span className="text-[11px] font-semibold text-[#FBBF24] uppercase tracking-wider">Pro tip</span>
                <p className="text-[12px] text-zinc-400 mt-1 leading-relaxed">{current.tip}</p>
              </div>
            </div>
          </div>

          <div className="border-t border-white/[0.06] px-8 py-5 flex items-center justify-between">
            <button
              onClick={() => setStep(s => Math.max(0, s - 1))}
              disabled={isFirst}
              className="flex items-center gap-2 text-[13px] text-zinc-500 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            >
              <ArrowLeft className="w-4 h-4" /> Back
            </button>

            <div className="flex items-center gap-3">
              {current.action.href && !isLast && (
                <button
                  onClick={() => { onClose(); router.push(current.action.href); }}
                  className="text-[12px] font-medium px-4 py-2 rounded-xl border transition-colors"
                  style={{
                    color: current.color,
                    borderColor: `${current.color}30`,
                    background: `${current.color}08`,
                  }}
                >
                  {current.action.label} <ArrowRight className="w-3 h-3 inline ml-1" />
                </button>
              )}

              <button
                onClick={() => {
                  if (isLast) {
                    onClose();
                    router.push(current.action.href || '/dashboard');
                  } else {
                    setStep(s => s + 1);
                  }
                }}
                className="flex items-center gap-2 text-[13px] font-semibold text-[#09090B] px-5 py-2.5 rounded-xl transition-all hover:opacity-90 active:scale-[0.98]"
                style={{ background: current.color }}
              >
                {isLast ? 'Go to Dashboard' : 'Next'}
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>

        <p className="text-[10px] text-zinc-700 mt-4 text-center">
          Use <kbd className="px-1.5 py-0.5 bg-white/[0.04] rounded text-zinc-500 text-[10px]">Esc</kbd> to close, <kbd className="px-1.5 py-0.5 bg-white/[0.04] rounded text-zinc-500 text-[10px]">&larr;</kbd> <kbd className="px-1.5 py-0.5 bg-white/[0.04] rounded text-zinc-500 text-[10px]">&rarr;</kbd> to navigate
        </p>
      </div>
    </div>
  );
}
