'use client';

import { useRouter } from 'next/navigation';
import {
  Activity, Shield, Globe, Zap, Bug, Fingerprint, Flame, Radar,
  Bot, Sparkles, BookOpen, ArrowRight, Monitor, Server, Lock,
  FileText, Settings, ChevronRight, ShieldCheck,
  Cpu, Database, Wifi, Search, BarChart3, AlertTriangle,
  Network, Crown, Terminal, HardDrive, Layers, Radio,
} from 'lucide-react';

/* ─── Types ─── */
interface ModuleCard {
  icon: typeof Activity;
  name: string;
  tagline: string;
  description: string;
  features: string[];
  href: string;
  color: string;
  free: boolean;
  category: 'core' | 'endpoint' | 'intelligence' | 'enterprise';
}

interface QuickAction {
  icon: typeof Activity;
  label: string;
  description: string;
  href: string;
  color: string;
}

/* ─── Data ─── */
const MODULES: ModuleCard[] = [
  // CORE DEFENSE
  {
    icon: Activity,
    name: 'Live Dashboard',
    tagline: 'Real-time SOC command center',
    description: 'CrowdStrike Falcon-style dense view with 10 WebSocket-powered widgets. Every incident, every blocked IP, every honeypot interaction appears instantly — no refresh needed.',
    features: [
      'Live attack feed with slide-in animations',
      'Global threat map with pulsing attacker dots',
      'Events/sec rolling line chart (60s window)',
      'Top 10 attackers, targets, and attack types',
      'Raw log stream with color-coded severity',
      'Node heartbeat grid (green/red per agent)',
      'Counters: events/sec, blocked/min, AI decisions/min',
    ],
    href: '/dashboard/live',
    color: '#22D3EE',
    free: true,
    category: 'core',
  },
  {
    icon: Globe,
    name: 'Surface (ASM)',
    tagline: 'Attack surface management',
    description: 'Discover everything exposed on your network. AI-powered nmap scans find services, Nuclei checks for vulnerabilities, and the risk scorer tells you what to fix first.',
    features: [
      'Auto-discovery: nmap scans 150+ ports + AI enrichment',
      'Vulnerability scanning via Nuclei templates',
      'AI risk scoring per asset (0-100)',
      'SBOM analysis for dependency tracking (Enterprise)',
      'Scheduled scans: full (2h), quick (30m), discovery (1h)',
      'Hardening checks with remediation steps',
    ],
    href: '/dashboard/surface',
    color: '#34D399',
    free: true,
    category: 'core',
  },
  {
    icon: Zap,
    name: 'Response (SOAR)',
    tagline: 'Autonomous incident response',
    description: 'When AEGIS detects a threat, it acts autonomously. The fast path resolves known patterns in <300ms without AI. Complex threats get full AI triage with MITRE ATT&CK mapping in 2-5 seconds.',
    features: [
      '18-microsecond detection in Layer 1 middleware',
      '10 deterministic playbooks (<50ms each)',
      'AI triage: classify → decide → execute → verify → audit',
      'MITRE ATT&CK technique mapping on every incident',
      'Fully autonomous — all actions auto-approved by default',
      'Override any action to require manual approval in Settings',
      'Full audit trail: model used, reasoning, confidence, cost',
    ],
    href: '/dashboard/response',
    color: '#F87171',
    free: true,
    category: 'core',
  },
  {
    icon: Bug,
    name: 'Phantom (Deception)',
    tagline: 'Honeypot traps for attackers',
    description: 'Deploy fake SSH servers and web apps that look real. When an attacker connects, AEGIS captures their credentials, commands, and tools — then profiles them with AI.',
    features: [
      'SSH honeypot on port 2222 (fake Ubuntu banner)',
      'HTTP honeypot on port 8888 (rotating WordPress/Jenkins/phpMyAdmin)',
      'Breadcrumb traps: fake .env files with trap API keys',
      'Breadcrumb alert chain: attacker steals fake creds → tries on real API → CRITICAL incident + auto-block',
      'Template rotation every 4 hours (anti-fingerprint)',
      'Attacker profiling with MITRE ATT&CK TTPs and geolocation',
    ],
    href: '/dashboard/phantom',
    color: '#F97316',
    free: true,
    category: 'core',
  },
  {
    icon: Shield,
    name: 'Threats (TIP)',
    tagline: 'Threat intelligence platform',
    description: 'Aggregate threat data from 5 feeds, correlate with your detections, and share anonymized IOCs with the AEGIS community. Track coordinated attack campaigns across phases.',
    features: [
      '5 feeds: AbuseIPDB, AlienVault OTX, Emerging Threats, Tor Exit Nodes, Feodo Tracker',
      'STIX 2.1 export for sharing with other platforms',
      'Community Intel Cloud hub (opt-in, anonymized)',
      'Campaign tracking: recon → exploit → persist → exfil → lateral',
      'IOC database with confidence scoring',
      '122 Sigma correlation rules + 5 chain detection rules',
    ],
    href: '/dashboard/threats',
    color: '#FBBF24',
    free: true,
    category: 'intelligence',
  },
  {
    icon: ShieldCheck,
    name: 'Configurable Firewall',
    tagline: 'YAML rule engine with UI editor',
    description: 'Define custom detection rules in YAML or via the visual editor. Rate limiting, CIDR matching, user-agent regex — all with hot reload. Rules apply in <1 second without restart.',
    features: [
      'YAML DSL: source_ip, port, protocol, user_agent, rate_limit',
      'Actions: block_ip, allow (short-circuit), alert, quarantine_host',
      'Priority-based evaluation (highest wins)',
      'Stateful rate limiting per source IP',
      'Rule tester: test rules against synthetic events',
      '6 default templates (SSH brute force, port scan, scanner block, etc.)',
      'Hot reload: create a rule → applies in <1s, no restart',
    ],
    href: '/dashboard/firewall',
    color: '#10B981',
    free: true,
    category: 'core',
  },

  // ENDPOINT PROTECTION
  {
    icon: Flame,
    name: 'Ransomware Protection',
    tagline: 'Detect + kill + rollback in <500ms',
    description: 'Canary files planted across user directories detect encryption attempts. When triggered, AEGIS kills the process tree instantly and restores affected files from shadow copies — all in under half a second.',
    features: [
      '10 hidden canary files in Documents/Desktop/Downloads',
      'Shannon entropy spike detection (threshold >7.5 bits)',
      'Mass file extension change detection (>20 in 5 seconds)',
      'VSS shadow copy deletion monitoring (Windows)',
      'Process tree kill via TerminateProcess / SIGKILL',
      'Auto-rollback: VSS (Windows), Btrfs/LVM (Linux), userspace ring buffer (ext4/xfs)',
      'Complete forensic chain uploaded as CRITICAL incident',
    ],
    href: '/dashboard/response',
    color: '#EF4444',
    free: true,
    category: 'endpoint',
  },
  {
    icon: Fingerprint,
    name: 'EDR/XDR Core',
    tagline: 'Endpoint detection and response',
    description: 'Kernel-level visibility into every process, network connection, file write, and registry change. Reconstruct attack chains and detect living-off-the-land techniques that bypass traditional AV.',
    features: [
      'ETW telemetry (Windows): Kernel-Process, Network, File, Registry, AMSI',
      'eBPF telemetry (Linux): process exec, connect, openat, unlink',
      'Process tree reconstruction (full ancestor + descendant chain)',
      '6 MITRE attack chain rules: macro malware, phishing payload, credential dump, LOTL download, rundll32 abuse',
      'Tiered: works without admin (polling) → better with admin (ETW/eBPF)',
      'Gzip-compressed 1-second batch uploads, 16K event ring buffer',
    ],
    href: '/dashboard/edr',
    color: '#A78BFA',
    free: true,
    category: 'endpoint',
  },
  {
    icon: Radar,
    name: 'Antivirus Engine',
    tagline: 'YARA + ClamAV + hash reputation',
    description: 'Signature-based detection as a complementary layer under behavioral analysis. On-access scanning catches known malware on file write. Daily scheduled scans cover the full filesystem.',
    features: [
      'YARA rules scanning (on-access + scheduled)',
      'ClamAV integration via clamscan CLI (optional)',
      'SHA256 hash reputation cache (sled embedded DB, >95% hit rate)',
      'Encrypted quarantine: infected files XOR-obfuscated in ~/.aegis/quarantine/',
      'Daily auto-update from YARA-Forge community + MalwareBazaar hashes',
      'EICAR test detection built-in (works without external rules)',
      'Release from quarantine via dashboard',
    ],
    href: '/dashboard/antivirus',
    color: '#06B6D4',
    free: true,
    category: 'endpoint',
  },

  // ENTERPRISE / INTELLIGENCE
  {
    icon: Sparkles,
    name: 'Quantum Analytics',
    tagline: 'Post-quantum + entropy analysis',
    description: 'Detect encrypted C2 traffic without decrypting it using Renyi entropy analysis. Assess your cryptographic posture against quantum computing threats with the Grover calculator.',
    features: [
      'Renyi entropy analysis (detects Cobalt Strike, Metasploit, Sliver beacons)',
      'Grover algorithm calculator (quantum brute-force time estimator)',
      'Post-quantum readiness score (0-100) — free tier gets basic score',
      'Adversarial ML poisoning detection (Enterprise)',
      'Steganography detection via file entropy deviation',
      'Crypto migration recommendations per asset',
    ],
    href: '/dashboard/quantum',
    color: '#A78BFA',
    free: false,
    category: 'enterprise',
  },
  {
    icon: Bot,
    name: 'Honey-AI Deception',
    tagline: 'AI-generated fake infrastructure at scale',
    description: 'The killer differentiator. Deploy 50+ fake services that look real — web apps, REST APIs, MySQL databases — all with AI-generated content. When an attacker interacts with any of them, a breadcrumb UUID triggers a CRITICAL alert.',
    features: [
      'Deception campaigns: deploy 50+ fake services in <30s',
      '4 industry themes: fintech, healthcare, ecommerce, devops',
      'AI-generated responses (LLM) with Faker fallback',
      'Smart HTTP honeypot: imitates Next.js/WordPress/Laravel',
      'Smart API honeypot: /api/users, /api/config with fake data',
      'Smart DB honeypot: MySQL wire protocol with fake schemas',
      'Breadcrumb UUID tracking: stolen data reused → CRITICAL alert',
      'Auto-rotation every 6 hours (anti-fingerprint)',
    ],
    href: '/dashboard/deception',
    color: '#F97316',
    free: false,
    category: 'enterprise',
  },
  {
    icon: FileText,
    name: 'Compliance Dashboard',
    tagline: 'ISO 27001 / NIS2 / SOC 2 mapping',
    description: 'See how your AEGIS deployment maps to major compliance frameworks. Identify gaps and track your coverage score as you enable more modules.',
    features: [
      'ISO 27001 Annex A control mapping',
      'NIS2 directive compliance tracking',
      'SOC 2 Trust Services Criteria assessment',
      'Coverage percentage per framework',
      'Gap analysis with remediation suggestions',
    ],
    href: '/dashboard/compliance',
    color: '#8B5CF6',
    free: false,
    category: 'enterprise',
  },
];

const QUICK_ACTIONS: QuickAction[] = [
  { icon: Search, label: 'Scan your network', description: 'Discover all services running on your infrastructure', href: '/dashboard/surface', color: '#34D399' },
  { icon: Bug, label: 'Deploy honeypots', description: 'Set up SSH + HTTP traps to catch attackers', href: '/dashboard/phantom', color: '#F97316' },
  { icon: ShieldCheck, label: 'Create firewall rules', description: 'Block brute force, port scans, and scanners', href: '/dashboard/firewall', color: '#10B981' },
  { icon: Activity, label: 'Open Live View', description: 'Watch threats in real-time as they happen', href: '/dashboard/live', color: '#22D3EE' },
  { icon: Monitor, label: 'Enroll endpoints', description: 'Install the Rust agent on your servers', href: '/dashboard/infra', color: '#A78BFA' },
  { icon: Settings, label: 'Configure AI', description: 'Set up OpenRouter, Ollama, or OpenAI provider', href: '/dashboard/settings', color: '#FBBF24' },
];

const CATEGORIES: { id: string; label: string; description: string }[] = [
  { id: 'core', label: 'Core Defense', description: 'Detection, response, and monitoring — included in the free tier.' },
  { id: 'endpoint', label: 'Endpoint Protection', description: 'Ransomware, EDR, and antivirus — runs on the Rust node agent.' },
  { id: 'intelligence', label: 'Threat Intelligence', description: 'Feeds, correlation, and community sharing.' },
  { id: 'enterprise', label: 'Enterprise Modules', description: 'Advanced features for companies. Custom pricing.' },
];

/* ─── Page ─── */
export default function GuidePage() {
  const router = useRouter();

  return (
    <div className="space-y-8 max-w-[1200px] mx-auto">
      {/* Hero */}
      <div className="rounded-2xl border border-white/[0.06] bg-gradient-to-br from-[#22D3EE]/[0.04] to-transparent p-8">
        <div className="flex items-start gap-4 mb-6">
          <div className="w-12 h-12 rounded-xl bg-[#22D3EE]/10 border border-[#22D3EE]/20 flex items-center justify-center shrink-0">
            <BookOpen className="w-6 h-6 text-[#22D3EE]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white mb-2">Welcome to AEGIS</h1>
            <p className="text-sm text-zinc-400 leading-relaxed max-w-2xl">
              AEGIS is an autonomous cybersecurity defense platform. It detects, analyzes, and neutralizes threats
              without human intervention — from the moment you deploy it. This guide explains every module and
              helps you get the most out of your installation.
            </p>
          </div>
        </div>

        {/* Key stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { val: '18μs', label: 'Detection speed', icon: Zap },
            { val: '11/11', label: 'Attack detection', icon: Shield },
            { val: '122', label: 'Sigma rules', icon: Layers },
            { val: '170+', label: 'API endpoints', icon: Server },
          ].map(s => (
            <div key={s.label} className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3 text-center">
              <s.icon className="w-4 h-4 text-[#22D3EE] mx-auto mb-1" />
              <div className="text-lg font-bold text-white font-mono">{s.val}</div>
              <div className="text-[10px] text-zinc-500 uppercase tracking-wider">{s.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* How it works */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Layers className="w-5 h-5 text-[#22D3EE]" />
          How AEGIS Protects You
        </h2>
        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.02] p-6">
          <div className="grid grid-cols-1 sm:grid-cols-5 gap-4">
            {[
              { step: 'L1', name: 'Attack Detector', desc: 'Regex + URL decode on every request', time: '18μs', color: '#22D3EE' },
              { step: 'L2', name: 'Log Watcher', desc: 'PM2/syslog pattern matching', time: 'real-time', color: '#34D399' },
              { step: 'L3', name: 'Sigma Correlation', desc: '122 rules + chain detection', time: '<100ms', color: '#FBBF24' },
              { step: 'L4', name: 'AI Triage', desc: 'Classify + MITRE ATT&CK map', time: '2-5s', color: '#A78BFA' },
              { step: 'L5', name: 'Auto-Response', desc: 'Playbooks + autonomous execution', time: '<50ms', color: '#F87171' },
            ].map((l, i) => (
              <div key={l.step} className="relative">
                <div className="rounded-xl border border-white/[0.06] p-3 text-center h-full">
                  <div className="text-xs font-bold font-mono mb-1" style={{ color: l.color }}>{l.step}</div>
                  <div className="text-[12px] font-medium text-white mb-1">{l.name}</div>
                  <div className="text-[10px] text-zinc-500 mb-2">{l.desc}</div>
                  <div className="text-[10px] font-mono" style={{ color: l.color }}>{l.time}</div>
                </div>
                {i < 4 && (
                  <ChevronRight className="hidden sm:block absolute -right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-700" />
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Quick actions */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Radio className="w-5 h-5 text-[#34D399]" />
          Quick Start
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {QUICK_ACTIONS.map(a => (
            <button
              key={a.label}
              onClick={() => router.push(a.href)}
              className="flex items-center gap-3 p-4 rounded-xl border border-white/[0.06] hover:border-white/[0.12] bg-white/[0.02] hover:bg-white/[0.04] transition-all text-left group"
            >
              <div
                className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
                style={{ background: `${a.color}15`, border: `1px solid ${a.color}30` }}
              >
                <a.icon className="w-5 h-5" style={{ color: a.color }} />
              </div>
              <div>
                <div className="text-[13px] font-medium text-white group-hover:text-[#22D3EE] transition-colors">{a.label}</div>
                <div className="text-[11px] text-zinc-500">{a.description}</div>
              </div>
              <ArrowRight className="w-4 h-4 text-zinc-600 group-hover:text-zinc-400 ml-auto shrink-0 transition-colors" />
            </button>
          ))}
        </div>
      </div>

      {/* Modules by category */}
      {CATEGORIES.map(cat => {
        const mods = MODULES.filter(m => m.category === cat.id);
        if (mods.length === 0) return null;

        return (
          <div key={cat.id}>
            <h2 className="text-lg font-semibold text-white mb-1 flex items-center gap-2">
              {cat.id === 'enterprise' ? <Crown className="w-5 h-5 text-[#F97316]" /> : <Shield className="w-5 h-5 text-[#22D3EE]" />}
              {cat.label}
            </h2>
            <p className="text-[12px] text-zinc-500 mb-4">{cat.description}</p>

            <div className="space-y-3">
              {mods.map(m => (
                <div
                  key={m.name}
                  className="rounded-2xl border border-white/[0.06] hover:border-white/[0.10] bg-white/[0.02] hover:bg-white/[0.03] transition-all overflow-hidden"
                >
                  <div className="p-5">
                    <div className="flex items-start gap-4">
                      <div
                        className="w-11 h-11 rounded-xl flex items-center justify-center shrink-0"
                        style={{ background: `${m.color}12`, border: `1px solid ${m.color}25` }}
                      >
                        <m.icon className="w-5 h-5" style={{ color: m.color }} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <h3 className="text-[15px] font-semibold text-white">{m.name}</h3>
                          {!m.free && (
                            <span className="text-[9px] font-bold text-[#F97316] bg-[#F97316]/10 border border-[#F97316]/20 px-2 py-0.5 rounded-full">ENTERPRISE</span>
                          )}
                          <span className="text-[10px] text-zinc-600 ml-auto font-mono">{m.tagline}</span>
                        </div>
                        <p className="text-[12px] text-zinc-400 leading-relaxed mb-3">{m.description}</p>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1">
                          {m.features.map(f => (
                            <div key={f} className="flex items-start gap-2 text-[11px] text-zinc-500">
                              <span className="text-[10px] mt-0.5" style={{ color: m.color }}>&#10003;</span>
                              <span>{f}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="border-t border-white/[0.04] px-5 py-3">
                    <button
                      onClick={() => router.push(m.href)}
                      className="text-[12px] font-medium flex items-center gap-1.5 transition-colors hover:gap-2.5"
                      style={{ color: m.color }}
                    >
                      Open {m.name} <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}

      {/* Architecture overview */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Terminal className="w-5 h-5 text-zinc-400" />
          Under the Hood
        </h2>
        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.02] p-6">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { icon: Server, label: 'Backend', val: 'FastAPI + Python 3.12', sub: '27 routers, 170+ endpoints' },
              { icon: Monitor, label: 'Frontend', val: 'Next.js 14 + Tailwind', sub: '21 dashboard pages' },
              { icon: Database, label: 'Database', val: 'PostgreSQL 16 + Redis 7', sub: '18 models, async' },
              { icon: HardDrive, label: 'Agent', val: 'Rust + Tauri v2', sub: 'Windows + Linux EDR' },
              { icon: Cpu, label: 'AI', val: '13 model routes', sub: 'OpenRouter / Ollama / OpenAI' },
              { icon: Lock, label: 'Auth', val: 'JWT + API Key + RBAC', sub: 'admin / analyst / viewer' },
              { icon: Wifi, label: 'Real-time', val: 'WebSocket streaming', sub: 'Topic-based pub/sub' },
              { icon: BarChart3, label: 'ML', val: 'Isolation Forest', sub: 'Behavioral anomaly detection' },
            ].map(item => (
              <div key={item.label} className="rounded-xl border border-white/[0.06] p-3">
                <item.icon className="w-4 h-4 text-zinc-500 mb-2" />
                <div className="text-[11px] text-zinc-400 uppercase tracking-wider mb-0.5">{item.label}</div>
                <div className="text-[12px] font-medium text-white">{item.val}</div>
                <div className="text-[10px] text-zinc-600">{item.sub}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Guardrails */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-[#FBBF24]" />
          Autonomous Guardrails
        </h2>
        <div className="rounded-2xl border border-white/[0.06] bg-white/[0.02] p-6">
          <p className="text-[13px] text-zinc-400 mb-4">
            AEGIS runs fully autonomous by default — every response action (block IP, kill process, isolate host, counter-attack)
            executes automatically without human approval. Every action is logged with AI reasoning, confidence score, and cost.
          </p>
          <p className="text-[13px] text-zinc-400 mb-4">
            If you need human-in-the-loop for specific actions, go to{' '}
            <button onClick={() => router.push('/dashboard/settings')} className="text-[#22D3EE] hover:underline">Settings</button>{' '}
            and override any guardrail to <code className="text-[11px] bg-white/[0.06] px-1.5 py-0.5 rounded text-white">require_approval</code> or{' '}
            <code className="text-[11px] bg-white/[0.06] px-1.5 py-0.5 rounded text-white">never_auto</code>.
          </p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {['block_ip', 'isolate_host', 'kill_process', 'quarantine_file', 'counter_attack', 'recon_attacker', 'deception', 'report_abuse'].map(a => (
              <div key={a} className="flex items-center gap-2 text-[11px] text-zinc-500 bg-white/[0.02] rounded-lg px-3 py-2 border border-white/[0.04]">
                <div className="w-1.5 h-1.5 rounded-full bg-[#34D399]" />
                {a}
              </div>
            ))}
          </div>
          <p className="text-[10px] text-zinc-600 mt-3">All actions shown above are auto_approve by default. Green dot = autonomous.</p>
        </div>
      </div>

      {/* Need help */}
      <div className="rounded-2xl border border-white/[0.06] bg-white/[0.02] p-6 text-center">
        <Network className="w-8 h-8 text-[#22D3EE] mx-auto mb-3" />
        <h3 className="text-[15px] font-semibold text-white mb-2">Need help?</h3>
        <p className="text-[12px] text-zinc-500 mb-4 max-w-md mx-auto">
          Check the README on GitHub for detailed installation, configuration, and API documentation.
          For Enterprise inquiries, contact us.
        </p>
        <div className="flex items-center justify-center gap-3">
          <a
            href="https://github.com/diego1128256-cmd/AEGIS"
            target="_blank"
            rel="noopener"
            className="text-[12px] font-medium text-[#22D3EE] bg-[#22D3EE]/10 hover:bg-[#22D3EE]/20 px-4 py-2 rounded-xl transition-colors"
          >
            GitHub Repository
          </a>
          <a
            href="mailto:alejandxr@icloud.com?subject=AEGIS%20Enterprise%20Inquiry"
            className="text-[12px] font-medium text-zinc-400 bg-white/[0.04] hover:bg-white/[0.08] px-4 py-2 rounded-xl transition-colors"
          >
            Contact Sales
          </a>
        </div>
      </div>
    </div>
  );
}
