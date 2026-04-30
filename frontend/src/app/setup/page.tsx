'use client';

import { useState, useRef, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { setApiKey, setJwtToken, getJwtToken, api } from '@/lib/api';
import { forwardRef } from 'react';
import {
  User, Mail, Lock, KeyRound, ChevronRight, ChevronLeft,
  Cpu, Globe, Wifi, Server, Monitor, Plus, Trash2,
  Bell, Send, Webhook, Check, ArrowRight, Search, Loader2,
  ShieldCheck, X, AlertTriangle, Database, Container, Shield,
  Laptop, Bot, Building2, Share2, Terminal, Bug, Network,
  Zap, Crown, Sparkles,
} from 'lucide-react';

/* ──────────────────────────────────────────────
   Types
   ────────────────────────────────────────────── */

type AuthMethod = 'register' | 'apikey';
type AIProvider = string;
type AssetMode = 'auto' | 'manual';

interface DiscoveredAsset {
  id: string;
  hostname: string;
  ip_address: string;
  asset_type: string;
  ports: number[];
  status: string;
  selected: boolean;
  service_name?: string;
  version?: string;
  risk_score?: number;
  technologies?: string[];
}

interface HoneypotType {
  id: string;
  name: string;
  description: string;
  port: number;
  icon: typeof Terminal;
  premium?: boolean;
}

interface ManualAsset {
  hostname: string;
  ip_address: string;
  asset_type: string;
  ports: string;
}

interface SetupState {
  // Step 1
  authMethod: AuthMethod;
  orgName: string;
  name: string;
  email: string;
  password: string;
  apiKey: string;
  loginMode: boolean;
  // Step 2
  aiProvider: AIProvider;
  aiProviderKey: string;
  ollamaUrl: string;
  // Step 3
  assetMode: AssetMode;
  scanTarget: string;
  scanConsent: boolean;
  discoveredAssets: DiscoveredAsset[];
  manualAssets: ManualAsset[];
  // Step 4 - Honeypots
  selectedHoneypots: string[];
  // Step 5
  webhookEnabled: boolean;
  webhookUrl: string;
  telegramEnabled: boolean;
  telegramBotToken: string;
  telegramChatId: string;
  // Step 6
  intelSharingEnabled: boolean;
}

// Track which steps have been completed (visited and submitted)
type CompletedSteps = Record<number, boolean>;

const STEPS = [
  { id: 1, label: 'Account' },
  { id: 2, label: 'AI Provider' },
  { id: 3, label: 'Assets' },
  { id: 4, label: 'Honeypots' },
  { id: 5, label: 'Alerts' },
  { id: 6, label: 'Threat Intel' },
  { id: 7, label: 'Ready' },
];

const HONEYPOT_TYPES: HoneypotType[] = [
  { id: 'ssh', name: 'SSH Honeypot', description: 'Captures brute-force attempts and credential harvesting', port: 2222, icon: Terminal },
  { id: 'http', name: 'HTTP Honeypot', description: 'Decoy web server to detect web scanners and exploit attempts', port: 8888, icon: Globe },
  { id: 'smb', name: 'SMB Honeypot', description: 'Mimics Windows file shares to detect lateral movement', port: 445, icon: Network },
  { id: 'api', name: 'API Honeypot', description: 'Fake REST API endpoints to detect automated scanners', port: 9090, icon: Webhook },
  { id: 'database', name: 'Database Honeypot', description: 'Mimics database ports to catch data exfil attempts', port: 3306, icon: Database },
  { id: 'smtp', name: 'SMTP Honeypot', description: 'Fake mail server to detect spam bots and phishing', port: 2525, icon: Mail },
];

const SMART_HONEYPOT_TYPES: HoneypotType[] = [
  { id: 'http-mimic', name: 'HTTP App Mimic', description: 'AI clones your real web app to create indistinguishable decoys', port: 8889, icon: Sparkles, premium: true },
  { id: 'api-mimic', name: 'API Mimic', description: 'AI-generated API responses that mirror your real services', port: 9091, icon: Zap, premium: true },
  { id: 'db-mimic', name: 'DB Mimic', description: 'AI-powered database that serves fake but realistic data', port: 3307, icon: Bug, premium: true },
];

// Provider icon mapping (fallback to Cpu for unknown providers)
const PROVIDER_ICONS: Record<string, typeof Cpu> = {
  inception: Zap,
  openrouter: Globe,
  anthropic: Cpu,
  openai: Cpu,
  ollama: Server,
  skip: ChevronRight,
};

// Static fallback in case API is unreachable during setup
const FALLBACK_PROVIDERS: { id: AIProvider; label: string; description: string; icon: typeof Cpu }[] = [
  { id: 'inception', label: 'Inception (Mercury-2)', description: 'Diffusion LLM — fast, free 10M tokens', icon: Zap },
  { id: 'openrouter', label: 'OpenRouter', description: 'Access 100+ models via one API key', icon: Globe },
  { id: 'anthropic', label: 'Anthropic', description: 'Claude models directly', icon: Cpu },
  { id: 'openai', label: 'OpenAI', description: 'GPT-4, GPT-3.5 and more', icon: Cpu },
  { id: 'ollama', label: 'Ollama', description: 'Self-hosted local models', icon: Server },
  { id: 'skip', label: 'Skip for now', description: 'Configure AI later in settings', icon: ChevronRight },
];

const ASSET_TYPES = [
  { value: 'web_application', label: 'Web Application', icon: Globe },
  { value: 'api_server', label: 'API Server', icon: Server },
  { value: 'database', label: 'Database', icon: Database },
  { value: 'server', label: 'Server', icon: Monitor },
  { value: 'workstation', label: 'Workstation', icon: Laptop },
  { value: 'ai_service', label: 'AI Service', icon: Bot },
  { value: 'container_platform', label: 'Container Platform', icon: Container },
  { value: 'security_tools', label: 'Security Tools', icon: Shield },
];

function getAssetIcon(type: string) {
  const found = ASSET_TYPES.find(t => t.value === type);
  return found ? found.icon : Monitor;
}

function getRiskColor(score: number | undefined) {
  if (score === undefined || score < 30) return 'text-[var(--success)]';
  if (score <= 60) return 'text-[var(--warning)]';
  return 'text-[var(--danger)]';
}

function getRiskBgColor(score: number | undefined) {
  if (score === undefined || score < 30) return 'bg-[var(--success)]/10 border-[var(--success)]/20';
  if (score <= 60) return 'bg-[var(--warning)]/10 border-[var(--warning)]/20';
  return 'bg-[var(--danger)]/10 border-[var(--danger)]/20';
}

function getRiskLabel(score: number | undefined) {
  if (score === undefined || score < 30) return 'Low';
  if (score <= 60) return 'Medium';
  return 'High';
}

/* ──────────────────────────────────────────────
   Component
   ────────────────────────────────────────────── */

export default function SetupWizard() {
  const router = useRouter();
  const [step, setStep] = useState(1);
  const [mounted, setMounted] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [stepTransition, setStepTransition] = useState(false);
  const [completedSteps, setCompletedSteps] = useState<CompletedSteps>({});
  const [manualForm, setManualForm] = useState<ManualAsset>({ hostname: '', ip_address: '', asset_type: 'server', ports: '' });

  const nameRef = useRef<HTMLInputElement>(null);
  const apiKeyRef = useRef<HTMLInputElement>(null);

  const [showUpgradeModal, setShowUpgradeModal] = useState(false);

  // Dynamic AI providers — fetched from API, with fallback
  const [aiProviders, setAiProviders] = useState(FALLBACK_PROVIDERS);

  const [state, setState] = useState<SetupState>({
    authMethod: 'register',
    orgName: '',
    name: '',
    email: '',
    password: '',
    apiKey: '',
    loginMode: false,
    aiProvider: 'inception',
    aiProviderKey: '',
    ollamaUrl: 'http://localhost:11434',
    assetMode: 'auto',
    scanTarget: '',
    scanConsent: false,
    discoveredAssets: [],
    manualAssets: [],
    selectedHoneypots: [],
    webhookEnabled: false,
    webhookUrl: '',
    telegramEnabled: false,
    telegramBotToken: '',
    telegramChatId: '',
    intelSharingEnabled: false,
  });

  useEffect(() => {
    setTimeout(() => setMounted(true), 50);

    // Fetch available AI providers from API
    const BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';
    fetch(`${BASE}/ai/providers`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (Array.isArray(data) && data.length > 0) {
          const mapped = data.map((p: { name: string; display_name?: string; active?: boolean }) => ({
            id: p.name,
            label: p.display_name || p.name.charAt(0).toUpperCase() + p.name.slice(1),
            description: p.active ? 'Currently active' : 'Available',
            icon: PROVIDER_ICONS[p.name] || Cpu,
          }));
          // Add skip option at the end
          mapped.push({ id: 'skip', label: 'Skip for now', description: 'Configure AI later', icon: ChevronRight });
          setAiProviders(mapped);
          // Auto-select the active provider
          const active = data.find((p: { active?: boolean }) => p.active);
          if (active) update({ aiProvider: active.name });
        }
      })
      .catch(() => { /* Use fallback providers */ });
  }, []);

  useEffect(() => {
    if (mounted && step === 1) {
      setTimeout(() => {
        if (state.authMethod === 'register') nameRef.current?.focus();
        else apiKeyRef.current?.focus();
      }, 400);
    }
  }, [mounted, step, state.authMethod]);

  // Simulate scan progress
  useEffect(() => {
    if (!scanning) {
      setScanProgress(0);
      return;
    }
    const interval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 95) return prev;
        return prev + Math.random() * 8;
      });
    }, 500);
    return () => clearInterval(interval);
  }, [scanning]);

  const update = useCallback((patch: Partial<SetupState>) => {
    setState(prev => ({ ...prev, ...patch }));
    setError('');
  }, []);

  const markCompleted = (stepId: number) => {
    setCompletedSteps(prev => ({ ...prev, [stepId]: true }));
  };

  const animateStep = (next: number) => {
    setStepTransition(true);
    setTimeout(() => {
      setStep(next);
      setStepTransition(false);
    }, 200);
  };

  /* ── Step Handlers ── */

  const handleStep1 = async () => {
    if (state.authMethod === 'register' && !state.loginMode) {
      if (!state.orgName.trim()) return setError('Organization name is required');
      if (!state.name.trim()) return setError('Name is required');
      if (!state.email.trim()) return setError('Email is required');
      if (!state.password || state.password.length < 6) return setError('Password must be at least 6 characters');
    } else if (state.authMethod === 'register' && state.loginMode) {
      if (!state.email.trim()) return setError('Email is required');
      if (!state.password) return setError('Password is required');
    } else {
      if (!state.apiKey.trim()) return setError('API key is required');
    }

    setLoading(true);
    setError('');
    try {
      if (state.authMethod === 'register') {
        if (state.loginMode) {
          const result = await api.auth.loginCredentials(state.email.trim(), state.password);
          if (result.token) setJwtToken(result.token);
        } else {
          const result = await api.onboarding.signup(
            state.orgName.trim(),
            state.name.trim(),
            state.email.trim(),
            state.password
          );
          if (result.token) setJwtToken(result.token);
          if (result.api_key) setApiKey(result.api_key);
        }
      } else {
        setApiKey(state.apiKey.trim());
        try {
          await api.auth.login(state.apiKey.trim());
        } catch {
          // API key stored locally, continue even if validation fails
        }
      }
      markCompleted(1);
      animateStep(2);
    } catch (err: unknown) {
      // Check if 401 means admin already exists
      const isApiError = err && typeof err === 'object' && 'status' in err;
      if (isApiError && (err as { status: number }).status === 401 && !state.loginMode) {
        setError('An admin account already exists. Please login instead.');
        update({ loginMode: true });
      } else if (isApiError && (err as { status: number }).status === 401 && state.loginMode) {
        setError('Invalid credentials. Please try again.');
      } else {
        // Backend unavailable — allow continuing for setup flow
        if (state.authMethod === 'apikey') {
          setApiKey(state.apiKey.trim());
        }
        markCompleted(1);
        animateStep(2);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleStep2 = async () => {
    if (state.aiProvider !== 'skip') {
      if (state.aiProvider === 'ollama') {
        if (!state.ollamaUrl.trim()) return setError('Ollama URL is required');
      } else if (!state.aiProviderKey.trim()) {
        return setError('API key is required');
      }
    }

    setLoading(true);
    setError('');
    try {
      if (state.aiProvider !== 'skip') {
        try {
          await api.ai.setActive(state.aiProvider);
          const config: Record<string, string> = {};
          if (state.aiProvider === 'ollama') {
            config.base_url = state.ollamaUrl.trim();
          } else {
            config.api_key = state.aiProviderKey.trim();
          }
          await api.ai.configure(state.aiProvider, config);
        } catch {
          // Silently continue if AI config fails (401 or network error)
        }
      }
    } catch {
      // Continue even if AI config fails
    }
    setLoading(false);
    markCompleted(2);
    animateStep(3);
  };

  const handleSkipStep = (currentStep: number) => {
    markCompleted(currentStep);
    animateStep(currentStep + 1);
  };

  const toggleHoneypot = (id: string, isPremium?: boolean) => {
    if (isPremium) {
      setShowUpgradeModal(true);
      return;
    }
    update({
      selectedHoneypots: state.selectedHoneypots.includes(id)
        ? state.selectedHoneypots.filter(h => h !== id)
        : [...state.selectedHoneypots, id],
    });
  };

  const handleStep4Honeypots = async () => {
    setLoading(true);
    setError('');
    try {
      if (state.selectedHoneypots.length > 0) {
        const BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';
        const token = getJwtToken();
        const hdrs: Record<string, string> = { 'Content-Type': 'application/json' };
        if (token) hdrs['Authorization'] = `Bearer ${token}`;
        const res = await fetch(`${BASE}/setup/honeypots`, {
          method: 'POST',
          headers: hdrs,
          body: JSON.stringify({ honeypots: state.selectedHoneypots }),
        });
        if (res.ok) {
          const data = await res.json();
          if (data.upgrade_required) {
            setShowUpgradeModal(true);
            setLoading(false);
            return;
          }
        }
      }
    } catch {
      // Continue even if honeypot config fails
    }
    setLoading(false);
    markCompleted(4);
    animateStep(5);
  };

  const handleDiscover = async () => {
    if (!state.scanTarget.trim()) return setError('Enter an IP address or range to scan');
    if (!state.scanConsent) return setError('Please confirm you understand the scan operation');
    setScanning(true);
    setScanProgress(0);
    setError('');
    try {
      const BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

      // Launch scan
      const token = getJwtToken();
      const authHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) authHeaders['Authorization'] = `Bearer ${token}`;

      const launchRes = await fetch(`${BASE}/setup/discover`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ target: state.scanTarget.trim() }),
      });
      const launch = await launchRes.json();
      const scanId = launch.scan_id as string;
      if (!scanId) throw new Error('No scan_id returned');

      // Poll for results (max 60 seconds)
      for (let i = 0; i < 30; i++) {
        await new Promise(r => setTimeout(r, 2000));
        const res = await fetch(`${BASE}/setup/discover/${scanId}`, {
          headers: authHeaders,
        });
        const data = await res.json();
        if (data.status === 'completed' && data.services) {
          if (data.services.length === 0) {
            setError('No services found. The host may be blocking scans. Try adding assets manually.');
            return;
          }
          const assets: DiscoveredAsset[] = data.services.map(
            (s: { port: number; service: string; hostname?: string; version?: string; risk_estimate?: number; technologies?: string[] }, idx: number) => ({
              id: `disc-${idx}`,
              hostname: s.hostname || `${s.service}-${state.scanTarget}`,
              ip_address: data.target || state.scanTarget.trim(),
              asset_type: s.service?.includes('http') ? 'web_application' : s.service?.includes('ssh') ? 'server' : 'server',
              ports: [s.port],
              status: 'active',
              selected: true,
              service_name: s.service,
              version: s.version,
              risk_score: s.risk_estimate,
              technologies: s.technologies,
            })
          );
          setScanProgress(100);
          update({ discoveredAssets: assets });
          return;
        }
        if (data.status === 'failed') {
          setError(`Scan failed: ${data.error || 'Unknown error'}. Try adding assets manually.`);
          return;
        }
      }
      setError('Scan timed out. Try adding assets manually.');
    } catch {
      setError('Scan failed or backend unavailable. You can add assets manually.');
    } finally {
      setScanning(false);
    }
  };

  const handleAddManual = () => {
    if (!manualForm.hostname.trim()) return setError('Hostname is required');
    if (!manualForm.ip_address.trim()) return setError('IP Address is required');
    const ports = manualForm.ports
      .split(',')
      .map(p => parseInt(p.trim(), 10))
      .filter(p => !isNaN(p) && p > 0 && p <= 65535);
    const newAsset: DiscoveredAsset = {
      id: `manual-${Date.now()}`,
      hostname: manualForm.hostname.trim(),
      ip_address: manualForm.ip_address.trim(),
      asset_type: manualForm.asset_type,
      ports,
      status: 'active',
      selected: true,
    };
    update({ discoveredAssets: [...state.discoveredAssets, newAsset] });
    setManualForm({ hostname: '', ip_address: '', asset_type: 'server', ports: '' });
    setError('');
  };

  const handleRemoveAsset = (id: string) => {
    update({ discoveredAssets: state.discoveredAssets.filter(a => a.id !== id) });
  };

  const toggleAssetSelection = (id: string) => {
    update({
      discoveredAssets: state.discoveredAssets.map(a =>
        a.id === id ? { ...a, selected: !a.selected } : a
      ),
    });
  };

  const handleRegisterAssets = async () => {
    const selectedAssets = state.discoveredAssets.filter(a => a.selected);
    if (selectedAssets.length === 0) return setError('Select at least one asset to register');
    setLoading(true);
    try {
      const BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';
      const token = getJwtToken();
      const hdrs: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) hdrs['Authorization'] = `Bearer ${token}`;
      await fetch(`${BASE}/setup/register-assets`, {
        method: 'POST',
        headers: hdrs,
        body: JSON.stringify({
          assets: selectedAssets.map(a => ({
            hostname: a.hostname,
            ip_address: a.ip_address,
            asset_type: a.asset_type,
          })),
        }),
      });
    } catch {
      // Continue even if registration fails
    }
    setLoading(false);
    markCompleted(3);
    animateStep(4);
  };

  const handleStep3 = async () => {
    const selectedAssets = state.discoveredAssets.filter(a => a.selected);
    if (selectedAssets.length > 0) {
      await handleRegisterAssets();
    } else {
      markCompleted(3);
      animateStep(4);
    }
  };

  const handleStep5Alerts = async () => {
    setLoading(true);
    setError('');
    try {
      const data: Record<string, unknown> = {};
      if (state.webhookEnabled && state.webhookUrl.trim()) {
        data.webhook_url = state.webhookUrl.trim();
      }
      if (state.telegramEnabled) {
        data.telegram_enabled = true;
        data.telegram_bot_token = state.telegramBotToken.trim();
        data.telegram_chat_id = state.telegramChatId.trim();
      }
      if (Object.keys(data).length > 0) {
        try {
          await api.settings.updateNotifications(data);
        } catch {
          // Continue even if notification config fails
        }
      }
    } catch {
      // Continue
    }
    setLoading(false);
    markCompleted(5);
    animateStep(6);
  };

  const handleStep6Intel = async () => {
    setLoading(true);
    setError('');
    try {
      if (state.intelSharingEnabled) {
        try {
          await api.settings.patchClient({ settings: { intel_sharing_enabled: true } });
        } catch {
          // Continue even if setting fails
        }
      }
    } catch {
      // Continue
    }
    setLoading(false);
    markCompleted(6);
    animateStep(7);
  };

  const handleFinish = () => {
    router.push('/dashboard');
  };

  const handleKeyDown = (e: React.KeyboardEvent, handler: () => void) => {
    if (e.key === 'Enter') handler();
  };

  /* ── Summary for Ready step ── */

  const summaryItems = () => {
    const items: { label: string; value: string; done: boolean; icon: typeof User; stepNum: number }[] = [];
    items.push({
      label: 'Account',
      value: state.authMethod === 'register' ? state.email || 'Configured' : 'API Key',
      done: !!completedSteps[1],
      icon: User,
      stepNum: 1,
    });
    items.push({
      label: 'AI Provider',
      value: state.aiProvider === 'skip' ? 'Not configured' : state.aiProvider.charAt(0).toUpperCase() + state.aiProvider.slice(1),
      done: state.aiProvider !== 'skip' && !!completedSteps[2],
      icon: Cpu,
      stepNum: 2,
    });
    const selectedCount = state.discoveredAssets.filter(a => a.selected).length;
    items.push({
      label: 'Assets',
      value: selectedCount > 0 ? `${selectedCount} asset${selectedCount > 1 ? 's' : ''} registered` : 'None added',
      done: selectedCount > 0,
      icon: Wifi,
      stepNum: 3,
    });
    items.push({
      label: 'Honeypots',
      value: state.selectedHoneypots.length > 0 ? `${state.selectedHoneypots.length} honeypot${state.selectedHoneypots.length > 1 ? 's' : ''} selected` : 'None selected',
      done: state.selectedHoneypots.length > 0,
      icon: Bug,
      stepNum: 4,
    });
    items.push({
      label: 'Alerts',
      value: state.webhookEnabled || state.telegramEnabled
        ? [state.webhookEnabled && 'Webhook', state.telegramEnabled && 'Telegram'].filter(Boolean).join(', ')
        : 'Not configured',
      done: state.webhookEnabled || state.telegramEnabled,
      icon: Bell,
      stepNum: 5,
    });
    items.push({
      label: 'Threat Intel',
      value: state.intelSharingEnabled ? 'Community sharing enabled' : 'Not sharing',
      done: !!completedSteps[6],
      icon: Share2,
      stepNum: 6,
    });
    return items;
  };

  /* ──────────────────────────────────────────────
     Render
     ────────────────────────────────────────────── */

  return (
    <div className="min-h-screen bg-[#09090B] flex flex-col items-center justify-center p-4 relative overflow-hidden font-sans">
      {/* Background glows */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] rounded-full pointer-events-none"
        style={{ background: 'radial-gradient(circle, rgba(34,211,238,0.04) 0%, transparent 70%)' }}
      />
      <div className="absolute bottom-1/4 right-1/4 w-[400px] h-[400px] rounded-full pointer-events-none"
        style={{ background: 'radial-gradient(circle, rgba(249,115,22,0.03) 0%, transparent 70%)' }}
      />

      <div className={`relative w-full max-w-2xl z-10 transition-all duration-700 ease-out ${
        mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-6'
      }`}>
        {/* Step Indicator */}
        <div className="flex items-center justify-center gap-2 mb-10">
          {STEPS.map((s, i) => (
            <div key={s.id} className="flex items-center">
              <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium transition-all duration-300 ${
                step === s.id
                  ? 'bg-[var(--brand)]/10 text-[var(--brand)] border border-[var(--brand)]/20'
                  : completedSteps[s.id]
                  ? 'bg-[var(--success)]/10 text-[var(--success)] border border-[var(--success)]/20'
                  : 'text-zinc-600 border border-white/[0.06]'
              }`}>
                {completedSteps[s.id] && step !== s.id ? (
                  <Check className="w-3 h-3" />
                ) : (
                  <span className="font-mono text-[10px]">{s.id}</span>
                )}
                <span className="hidden sm:inline">{s.label}</span>
              </div>
              {i < STEPS.length - 1 && (
                <div className={`w-6 h-px mx-1 transition-colors duration-300 ${
                  completedSteps[s.id] ? 'bg-[var(--success)]/30' : 'bg-white/[0.06]'
                }`} />
              )}
            </div>
          ))}
        </div>

        {/* Content Card */}
        <div className={`bg-[#18181B] border border-white/[0.06] rounded-2xl p-8 transition-all duration-200 ${
          stepTransition ? 'opacity-0 translate-y-2' : 'opacity-100 translate-y-0'
        }`}>

          {/* --- STEP 1: Account --- */}
          {step === 1 && (
            <div className="space-y-6">
              <div className="text-center mb-2">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[var(--brand)]/10 border border-[var(--brand)]/20 mb-4">
                  <ShieldCheck className="w-6 h-6 text-[var(--brand)]" />
                </div>
                <h2 className="text-2xl font-bold text-white">Welcome to AEGIS</h2>
                <p className="text-zinc-500 text-sm mt-2">
                  {state.loginMode ? 'Login to your existing account' : 'Set up your account to get started'}
                </p>
              </div>

              {/* Auth method toggle */}
              <div className="flex rounded-xl bg-[#09090B] border border-white/[0.06] p-1">
                <button
                  onClick={() => update({ authMethod: 'register', loginMode: false })}
                  className={`flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-[13px] font-medium transition-all duration-200 ${
                    state.authMethod === 'register'
                      ? 'bg-white/[0.06] text-[var(--brand)] shadow-sm'
                      : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  <User className="w-3.5 h-3.5" />
                  {state.loginMode ? 'Login' : 'Create Account'}
                </button>
                <button
                  onClick={() => update({ authMethod: 'apikey', loginMode: false })}
                  className={`flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-[13px] font-medium transition-all duration-200 ${
                    state.authMethod === 'apikey'
                      ? 'bg-white/[0.06] text-[var(--brand)] shadow-sm'
                      : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  <KeyRound className="w-3.5 h-3.5" />
                  API Key
                </button>
              </div>

              {state.authMethod === 'register' ? (
                <div className="space-y-4">
                  {!state.loginMode && (
                    <>
                      <InputField
                        label="Organization Name"
                        icon={Building2}
                        value={state.orgName}
                        onChange={v => update({ orgName: v })}
                        onKeyDown={e => handleKeyDown(e, handleStep1)}
                        placeholder="Your company or team name"
                      />
                      <InputField
                        ref={nameRef}
                        label="Name"
                        icon={User}
                        value={state.name}
                        onChange={v => update({ name: v })}
                        onKeyDown={e => handleKeyDown(e, handleStep1)}
                        placeholder="Your name"
                      />
                    </>
                  )}
                  <InputField
                    label="Email"
                    icon={Mail}
                    type="email"
                    value={state.email}
                    onChange={v => update({ email: v })}
                    onKeyDown={e => handleKeyDown(e, handleStep1)}
                    placeholder="admin@organization.com"
                    autoComplete="email"
                  />
                  <InputField
                    label="Password"
                    icon={Lock}
                    type="password"
                    value={state.password}
                    onChange={v => update({ password: v })}
                    onKeyDown={e => handleKeyDown(e, handleStep1)}
                    placeholder={state.loginMode ? 'Your password' : 'Min 6 characters'}
                    autoComplete={state.loginMode ? 'current-password' : 'new-password'}
                  />
                  {state.loginMode && (
                    <button
                      onClick={() => update({ loginMode: false })}
                      className="text-xs text-zinc-500 hover:text-[var(--brand)] transition-colors"
                    >
                      Need to create an account instead?
                    </button>
                  )}
                </div>
              ) : (
                <div className="space-y-4">
                  <InputField
                    ref={apiKeyRef}
                    label="API Key"
                    icon={KeyRound}
                    type="password"
                    value={state.apiKey}
                    onChange={v => update({ apiKey: v })}
                    onKeyDown={e => handleKeyDown(e, handleStep1)}
                    placeholder="Enter your API key"
                  />
                  <p className="text-xs text-zinc-600">
                    The key will be stored locally and used for all API requests.
                  </p>
                </div>
              )}

              {error && <ErrorMessage message={error} />}

              <StepButton label={state.loginMode ? 'Login' : 'Continue'} loading={loading} onClick={handleStep1} />
            </div>
          )}

          {/* --- STEP 2: AI Provider --- */}
          {step === 2 && (
            <div className="space-y-6">
              <div className="text-center mb-2">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[var(--brand)]/10 border border-[var(--brand)]/20 mb-4">
                  <Cpu className="w-6 h-6 text-[var(--brand)]" />
                </div>
                <h2 className="text-2xl font-bold text-white">Connect AI Provider</h2>
                <p className="text-zinc-500 text-sm mt-2">AEGIS uses AI for threat analysis and autonomous response</p>
              </div>

              <div className="space-y-2">
                {aiProviders.map(p => {
                  const Icon = p.icon;
                  return (
                    <button
                      key={p.id}
                      onClick={() => update({ aiProvider: p.id })}
                      className={`w-full flex items-center gap-4 p-4 rounded-xl border transition-all duration-200 text-left ${
                        state.aiProvider === p.id
                          ? 'border-[var(--brand)]/30 bg-[var(--brand)]/5'
                          : 'border-white/[0.06] hover:border-white/[0.1] hover:bg-white/[0.02]'
                      }`}
                    >
                      <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${
                        state.aiProvider === p.id ? 'bg-[var(--brand)]/10' : 'bg-white/[0.04]'
                      }`}>
                        <Icon className={`w-4 h-4 ${state.aiProvider === p.id ? 'text-[var(--brand)]' : 'text-zinc-500'}`} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className={`text-sm font-medium ${state.aiProvider === p.id ? 'text-white' : 'text-zinc-300'}`}>
                          {p.label}
                        </div>
                        <div className="text-xs text-zinc-500">{p.description}</div>
                      </div>
                      {state.aiProvider === p.id && (
                        <div className="w-5 h-5 rounded-full bg-[var(--brand)] flex items-center justify-center">
                          <Check className="w-3 h-3 text-[#09090B]" />
                        </div>
                      )}
                    </button>
                  );
                })}
              </div>

              {state.aiProvider !== 'skip' && state.aiProvider !== 'ollama' && (
                <InputField
                  label={`${state.aiProvider.charAt(0).toUpperCase() + state.aiProvider.slice(1)} API Key`}
                  icon={KeyRound}
                  type="password"
                  value={state.aiProviderKey}
                  onChange={v => update({ aiProviderKey: v })}
                  onKeyDown={e => handleKeyDown(e, handleStep2)}
                  placeholder="sk-..."
                />
              )}

              {state.aiProvider === 'ollama' && (
                <InputField
                  label="Ollama URL"
                  icon={Globe}
                  value={state.ollamaUrl}
                  onChange={v => update({ ollamaUrl: v })}
                  onKeyDown={e => handleKeyDown(e, handleStep2)}
                  placeholder="http://localhost:11434"
                />
              )}

              {error && <ErrorMessage message={error} />}

              <div className="flex gap-3">
                <BackButton onClick={() => animateStep(1)} />
                <StepButton label="Continue" loading={loading} onClick={handleStep2} />
                <SkipButton onClick={() => handleSkipStep(2)} />
              </div>
            </div>
          )}

          {/* --- STEP 3: Discover Assets --- */}
          {step === 3 && (
            <div className="space-y-6">
              <div className="text-center mb-2">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[var(--brand)]/10 border border-[var(--brand)]/20 mb-4">
                  <Wifi className="w-6 h-6 text-[var(--brand)]" />
                </div>
                <h2 className="text-2xl font-bold text-white">Discover Your Assets</h2>
                <p className="text-zinc-500 text-sm mt-2">Scan your network or add assets manually</p>
              </div>

              {/* Mode Toggle */}
              <div className="flex rounded-xl bg-[#09090B] border border-white/[0.06] p-1">
                <button
                  onClick={() => update({ assetMode: 'auto' })}
                  className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-[13px] font-medium transition-all duration-200 ${
                    state.assetMode === 'auto'
                      ? 'bg-white/[0.06] text-[var(--brand)] shadow-sm'
                      : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  <Search className="w-3.5 h-3.5" />
                  Auto-Scan
                </button>
                <button
                  onClick={() => update({ assetMode: 'manual' })}
                  className={`flex-1 flex items-center justify-center gap-2 py-2.5 rounded-lg text-[13px] font-medium transition-all duration-200 ${
                    state.assetMode === 'manual'
                      ? 'bg-white/[0.06] text-[var(--brand)] shadow-sm'
                      : 'text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  <Plus className="w-3.5 h-3.5" />
                  Manual
                </button>
              </div>

              {/* AUTO-SCAN MODE */}
              {state.assetMode === 'auto' && (
                <div className="space-y-4">
                  {/* Warning Card */}
                  <div className="rounded-xl border border-[var(--warning)]/20 bg-[var(--warning)]/5 p-4">
                    <div className="flex gap-3">
                      <AlertTriangle className="w-5 h-5 text-[var(--warning)] flex-shrink-0 mt-0.5" />
                      <div className="space-y-2">
                        <p className="text-sm text-zinc-300">
                          AEGIS will scan your network to discover services.
                          This runs nmap from the server to detect open ports and services.
                        </p>
                        <p className="text-xs text-zinc-500">
                          No changes will be made to your systems -- this is read-only reconnaissance.
                        </p>
                        <label className="flex items-center gap-2 mt-3 cursor-pointer select-none">
                          <button
                            onClick={() => update({ scanConsent: !state.scanConsent })}
                            className={`w-4 h-4 rounded border flex items-center justify-center transition-all flex-shrink-0 ${
                              state.scanConsent
                                ? 'bg-[var(--brand)] border-[var(--brand)]'
                                : 'border-white/20 hover:border-white/40'
                            }`}
                          >
                            {state.scanConsent && <Check className="w-2.5 h-2.5 text-[#09090B]" />}
                          </button>
                          <span className="text-xs text-zinc-400">I understand and want to proceed</span>
                        </label>
                      </div>
                    </div>
                  </div>

                  {/* Scan controls — only visible after consent */}
                  {state.scanConsent && (
                    <div className="space-y-4">
                      <div className="flex gap-2">
                        <div className="flex-1">
                          <InputField
                            label="Target IP / Range"
                            icon={Search}
                            value={state.scanTarget}
                            onChange={v => update({ scanTarget: v })}
                            onKeyDown={e => handleKeyDown(e, handleDiscover)}
                            placeholder="e.g., 192.168.1.0/24 or 10.0.0.1"
                          />
                        </div>
                        <button
                          onClick={handleDiscover}
                          disabled={scanning || !state.scanTarget.trim()}
                          className="self-end mb-[1px] px-5 py-3 rounded-xl bg-[var(--brand)]/10 border border-[var(--brand)]/20 text-[var(--brand)] text-sm font-medium hover:bg-[var(--brand)]/20 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center gap-2"
                        >
                          {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                          {scanning ? 'Scanning' : 'Scan'}
                        </button>
                      </div>

                      {/* Scanning progress with multi-phase status */}
                      {scanning && (
                        <div className="space-y-3">
                          <div className="w-full h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
                            <div
                              className="h-full bg-[var(--brand)] rounded-full transition-all duration-500 ease-out"
                              style={{ width: `${Math.min(scanProgress, 100)}%` }}
                            />
                          </div>
                          <div className="space-y-1.5">
                            {[
                              { label: 'Scanning ports', threshold: 0 },
                              { label: 'Detecting services', threshold: 30 },
                              { label: 'Fingerprinting versions', threshold: 55 },
                              { label: 'AI analyzing risk', threshold: 75 },
                            ].map(phase => {
                              const active = scanProgress >= phase.threshold && scanProgress < (phase.threshold + 30);
                              const done = scanProgress >= phase.threshold + 30;
                              return (
                                <div key={phase.label} className="flex items-center gap-2">
                                  {done ? (
                                    <Check className="w-3.5 h-3.5 text-[var(--success)]" />
                                  ) : active ? (
                                    <Loader2 className="w-3.5 h-3.5 animate-spin text-[var(--brand)]" />
                                  ) : (
                                    <div className="w-3.5 h-3.5 rounded-full border border-white/10" />
                                  )}
                                  <span className={`text-xs ${
                                    active ? 'text-[var(--brand)]' : done ? 'text-zinc-500' : 'text-zinc-700'
                                  }`}>
                                    {phase.label}{active ? '...' : ''}
                                  </span>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* MANUAL MODE */}
              {state.assetMode === 'manual' && (
                <div className="space-y-4">
                  <div className="bg-[#09090B] border border-white/[0.06] rounded-xl p-4 space-y-4">
                    <InputField
                      label="Hostname"
                      icon={Monitor}
                      value={manualForm.hostname}
                      onChange={v => setManualForm(prev => ({ ...prev, hostname: v }))}
                      placeholder="e.g., web-server-01"
                    />
                    <InputField
                      label="IP Address"
                      icon={Globe}
                      value={manualForm.ip_address}
                      onChange={v => setManualForm(prev => ({ ...prev, ip_address: v }))}
                      placeholder="e.g., 192.168.1.100"
                    />
                    <div>
                      <label className="block text-xs font-medium text-zinc-400 mb-2">Type</label>
                      <div className="relative">
                        <Server className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-600" />
                        <select
                          value={manualForm.asset_type}
                          onChange={e => setManualForm(prev => ({ ...prev, asset_type: e.target.value }))}
                          className="w-full bg-[#18181B] border border-white/[0.06] text-white rounded-xl px-4 py-3 pl-11 text-sm focus:outline-none focus:border-[var(--brand)]/40 focus:ring-1 focus:ring-[var(--brand)]/20 transition-all duration-200 appearance-none"
                        >
                          {ASSET_TYPES.map(t => (
                            <option key={t.value} value={t.value}>{t.label}</option>
                          ))}
                        </select>
                      </div>
                    </div>
                    <InputField
                      label="Port(s)"
                      icon={Wifi}
                      value={manualForm.ports}
                      onChange={v => setManualForm(prev => ({ ...prev, ports: v }))}
                      placeholder="e.g., 80, 443, 8080"
                    />
                    <button
                      onClick={handleAddManual}
                      className="w-full px-4 py-2.5 rounded-xl bg-[var(--brand)]/10 border border-[var(--brand)]/20 text-[var(--brand)] text-sm font-medium hover:bg-[var(--brand)]/20 transition-all duration-200 flex items-center justify-center gap-2"
                    >
                      <Plus className="w-4 h-4" />
                      Add Asset
                    </button>
                  </div>
                </div>
              )}

              {/* Discovered / Added assets — enhanced cards */}
              {state.discoveredAssets.length > 0 && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-zinc-400">
                      {state.discoveredAssets.length} service{state.discoveredAssets.length !== 1 ? 's' : ''} found
                      {' '}&middot;{' '}
                      {state.discoveredAssets.filter(a => a.selected).length} selected
                    </span>
                  </div>
                  <div className="max-h-80 overflow-y-auto space-y-2 pr-1">
                    {state.discoveredAssets.map(asset => {
                      const AssetIcon = getAssetIcon(asset.asset_type);
                      return (
                        <div
                          key={asset.id}
                          onClick={() => toggleAssetSelection(asset.id)}
                          className={`relative p-4 rounded-xl border transition-all duration-200 cursor-pointer ${
                            asset.selected
                              ? 'border-[var(--brand)]/20 bg-[var(--brand)]/5'
                              : 'border-white/[0.06] bg-white/[0.02] opacity-60 hover:opacity-80'
                          }`}
                        >
                          <div className="flex items-start gap-3">
                            {/* Checkbox */}
                            <div className={`mt-0.5 w-5 h-5 rounded-md border flex items-center justify-center transition-all flex-shrink-0 ${
                              asset.selected
                                ? 'bg-[var(--brand)] border-[var(--brand)]'
                                : 'border-white/20'
                            }`}>
                              {asset.selected && <Check className="w-3 h-3 text-[#09090B]" />}
                            </div>

                            {/* Icon */}
                            <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 ${
                              asset.selected ? 'bg-[var(--brand)]/10' : 'bg-white/[0.04]'
                            }`}>
                              <AssetIcon className={`w-4 h-4 ${asset.selected ? 'text-[var(--brand)]' : 'text-zinc-500'}`} />
                            </div>

                            {/* Service info */}
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-medium text-white truncate">
                                  {asset.service_name || asset.hostname || 'Unknown Service'}
                                </span>
                                {asset.version && (
                                  <span className="text-[10px] font-mono text-zinc-500 bg-white/[0.04] px-1.5 py-0.5 rounded">
                                    {asset.version}
                                  </span>
                                )}
                              </div>
                              <div className="text-xs text-zinc-500 mt-0.5">
                                {asset.ip_address}:{asset.ports[0]}
                                {asset.ports.length > 1 && `, +${asset.ports.length - 1} ports`}
                              </div>

                              {/* Technology badges */}
                              {asset.technologies && asset.technologies.length > 0 && (
                                <div className="flex flex-wrap gap-1 mt-2">
                                  {asset.technologies.map(tech => (
                                    <span
                                      key={tech}
                                      className="text-[10px] font-medium px-2 py-0.5 rounded-full bg-[var(--brand)]/10 text-[var(--brand)] border border-[var(--brand)]/10"
                                    >
                                      {tech}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>

                            {/* Risk score */}
                            {asset.risk_score !== undefined && (
                              <div className={`flex flex-col items-center px-2.5 py-1.5 rounded-lg border ${getRiskBgColor(asset.risk_score)}`}>
                                <span className={`text-lg font-bold font-mono leading-none ${getRiskColor(asset.risk_score)}`}>
                                  {Math.round(asset.risk_score)}
                                </span>
                                <span className={`text-[9px] font-medium uppercase ${getRiskColor(asset.risk_score)}`}>
                                  {getRiskLabel(asset.risk_score)}
                                </span>
                              </div>
                            )}

                            {/* Remove button */}
                            <button
                              onClick={e => { e.stopPropagation(); handleRemoveAsset(asset.id); }}
                              className="text-zinc-600 hover:text-[var(--danger)] transition-colors flex-shrink-0 mt-1"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Register Selected button */}
                  <button
                    onClick={handleRegisterAssets}
                    disabled={loading || state.discoveredAssets.filter(a => a.selected).length === 0}
                    className="w-full mt-2 px-4 py-2.5 rounded-xl bg-[var(--brand)]/10 border border-[var(--brand)]/20 text-[var(--brand)] text-sm font-medium hover:bg-[var(--brand)]/20 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex items-center justify-center gap-2"
                  >
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
                    Register Selected Assets ({state.discoveredAssets.filter(a => a.selected).length})
                  </button>
                </div>
              )}

              {error && <ErrorMessage message={error} />}

              <div className="flex gap-3">
                <BackButton onClick={() => animateStep(2)} />
                <StepButton
                  label={state.discoveredAssets.filter(a => a.selected).length > 0 ? 'Register & Continue' : 'Continue'}
                  loading={loading}
                  onClick={handleStep3}
                />
                <SkipButton onClick={() => handleSkipStep(3)} />
              </div>
            </div>
          )}

          {/* --- STEP 4: Honeypot Picker --- */}
          {step === 4 && (
            <div className="space-y-6">
              <div className="text-center mb-2">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[var(--brand-accent)]/10 border border-[var(--brand-accent)]/20 mb-4">
                  <Bug className="w-6 h-6 text-[var(--brand-accent)]" />
                </div>
                <h2 className="text-2xl font-bold text-white">Deploy Honeypots</h2>
                <p className="text-zinc-500 text-sm mt-2">Select deception traps to detect and profile attackers</p>
              </div>

              {/* Standard Honeypots */}
              <div className="grid grid-cols-2 gap-2">
                {HONEYPOT_TYPES.map(hp => {
                  const Icon = hp.icon;
                  const isSelected = state.selectedHoneypots.includes(hp.id);
                  return (
                    <button
                      key={hp.id}
                      onClick={() => toggleHoneypot(hp.id)}
                      className={`p-4 rounded-xl border text-left transition-all duration-200 ${
                        isSelected
                          ? 'border-[var(--brand-accent)]/30 bg-[var(--brand-accent)]/5'
                          : 'border-white/[0.06] hover:border-white/[0.1] hover:bg-white/[0.02]'
                      }`}
                    >
                      <div className={`w-9 h-9 rounded-lg flex items-center justify-center mb-3 ${
                        isSelected ? 'bg-[var(--brand-accent)]/10' : 'bg-white/[0.04]'
                      }`}>
                        <Icon className={`w-4 h-4 ${isSelected ? 'text-[var(--brand-accent)]' : 'text-zinc-500'}`} />
                      </div>
                      <div className="text-sm font-medium text-white mb-0.5">{hp.name}</div>
                      <div className="text-[11px] text-zinc-500 leading-tight mb-2">{hp.description}</div>
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono text-zinc-600">Port {hp.port}</span>
                        {isSelected && (
                          <div className="w-5 h-5 rounded-full bg-[var(--brand-accent)] flex items-center justify-center">
                            <Check className="w-3 h-3 text-[#09090B]" />
                          </div>
                        )}
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* Smart Honeypots (Premium) */}
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <Sparkles className="w-4 h-4 text-[var(--brand-accent)]" />
                  <span className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Smart Honeypots</span>
                  <span className="text-[10px] font-bold text-[var(--brand-accent)] bg-[var(--brand-accent)]/10 border border-[var(--brand-accent)]/20 px-2 py-0.5 rounded-full">ENTERPRISE</span>
                </div>
                <div className="grid grid-cols-3 gap-2">
                  {SMART_HONEYPOT_TYPES.map(hp => {
                    const Icon = hp.icon;
                    const isSelected = state.selectedHoneypots.includes(hp.id);
                    return (
                      <button
                        key={hp.id}
                        onClick={() => toggleHoneypot(hp.id, true)}
                        className={`relative p-3 rounded-xl border text-left transition-all duration-200 ${
                          isSelected
                            ? 'border-[var(--brand-accent)]/30 bg-[var(--brand-accent)]/5'
                            : 'border-white/[0.06] hover:border-[var(--brand-accent)]/20 hover:bg-white/[0.02]'
                        }`}
                      >
                        <div className="absolute top-2 right-2">
                          <Crown className="w-3.5 h-3.5 text-[var(--brand-accent)]" />
                        </div>
                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center mb-2 ${
                          isSelected ? 'bg-[var(--brand-accent)]/10' : 'bg-white/[0.04]'
                        }`}>
                          <Icon className={`w-3.5 h-3.5 ${isSelected ? 'text-[var(--brand-accent)]' : 'text-zinc-500'}`} />
                        </div>
                        <div className="text-xs font-medium text-white mb-0.5">{hp.name}</div>
                        <div className="text-[10px] text-zinc-500 leading-tight">{hp.description}</div>
                      </button>
                    );
                  })}
                </div>
              </div>

              {state.selectedHoneypots.length > 0 && (
                <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3">
                  <span className="text-xs text-zinc-400">
                    {state.selectedHoneypots.length} honeypot{state.selectedHoneypots.length > 1 ? 's' : ''} selected:{' '}
                    <span className="text-white">
                      {state.selectedHoneypots
                        .map(id => [...HONEYPOT_TYPES, ...SMART_HONEYPOT_TYPES].find(h => h.id === id)?.name)
                        .filter(Boolean)
                        .join(', ')}
                    </span>
                  </span>
                </div>
              )}

              {error && <ErrorMessage message={error} />}

              <div className="flex gap-3">
                <BackButton onClick={() => animateStep(3)} />
                <StepButton
                  label={state.selectedHoneypots.length > 0 ? 'Deploy & Continue' : 'Continue'}
                  loading={loading}
                  onClick={handleStep4Honeypots}
                />
                <SkipButton onClick={() => handleSkipStep(4)} />
              </div>
            </div>
          )}

          {/* --- STEP 5: Alerts --- */}
          {step === 5 && (
            <div className="space-y-6">
              <div className="text-center mb-2">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[var(--brand)]/10 border border-[var(--brand)]/20 mb-4">
                  <Bell className="w-6 h-6 text-[var(--brand)]" />
                </div>
                <h2 className="text-2xl font-bold text-white">Configure Alerts</h2>
                <p className="text-zinc-500 text-sm mt-2">Get notified when AEGIS detects threats</p>
              </div>

              {/* Webhook */}
              <div className={`p-4 rounded-xl border transition-all duration-200 ${
                state.webhookEnabled ? 'border-[var(--brand)]/20 bg-[var(--brand)]/5' : 'border-white/[0.06]'
              }`}>
                <button
                  onClick={() => update({ webhookEnabled: !state.webhookEnabled })}
                  className="w-full flex items-center gap-3 text-left"
                >
                  <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${
                    state.webhookEnabled ? 'bg-[var(--brand)]/10' : 'bg-white/[0.04]'
                  }`}>
                    <Webhook className={`w-4 h-4 ${state.webhookEnabled ? 'text-[var(--brand)]' : 'text-zinc-500'}`} />
                  </div>
                  <div className="flex-1">
                    <div className="text-sm font-medium text-white">Webhook</div>
                    <div className="text-xs text-zinc-500">Send alerts to a webhook URL</div>
                  </div>
                  <ToggleSwitch enabled={state.webhookEnabled} />
                </button>
                {state.webhookEnabled && (
                  <div className="mt-4">
                    <InputField
                      label="Webhook URL"
                      icon={Globe}
                      value={state.webhookUrl}
                      onChange={v => update({ webhookUrl: v })}
                      placeholder="https://hooks.slack.com/..."
                    />
                  </div>
                )}
              </div>

              {/* Telegram */}
              <div className={`p-4 rounded-xl border transition-all duration-200 ${
                state.telegramEnabled ? 'border-[var(--brand)]/20 bg-[var(--brand)]/5' : 'border-white/[0.06]'
              }`}>
                <button
                  onClick={() => update({ telegramEnabled: !state.telegramEnabled })}
                  className="w-full flex items-center gap-3 text-left"
                >
                  <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${
                    state.telegramEnabled ? 'bg-[var(--brand)]/10' : 'bg-white/[0.04]'
                  }`}>
                    <Send className={`w-4 h-4 ${state.telegramEnabled ? 'text-[var(--brand)]' : 'text-zinc-500'}`} />
                  </div>
                  <div className="flex-1">
                    <div className="text-sm font-medium text-white">Telegram</div>
                    <div className="text-xs text-zinc-500">Send alerts via Telegram bot</div>
                  </div>
                  <ToggleSwitch enabled={state.telegramEnabled} />
                </button>
                {state.telegramEnabled && (
                  <div className="mt-4 space-y-3">
                    <InputField
                      label="Bot Token"
                      icon={KeyRound}
                      value={state.telegramBotToken}
                      onChange={v => update({ telegramBotToken: v })}
                      placeholder="123456:ABC-DEF..."
                    />
                    <InputField
                      label="Chat ID"
                      icon={Mail}
                      value={state.telegramChatId}
                      onChange={v => update({ telegramChatId: v })}
                      placeholder="-1001234567890"
                    />
                  </div>
                )}
              </div>

              {error && <ErrorMessage message={error} />}

              <div className="flex gap-3">
                <BackButton onClick={() => animateStep(4)} />
                <StepButton
                  label={state.webhookEnabled || state.telegramEnabled ? 'Save & Continue' : 'Continue'}
                  loading={loading}
                  onClick={handleStep5Alerts}
                />
                <SkipButton onClick={() => handleSkipStep(5)} />
              </div>
            </div>
          )}

          {/* --- STEP 6: Threat Intel --- */}
          {step === 6 && (
            <div className="space-y-6">
              <div className="text-center mb-2">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[var(--brand)]/10 border border-[var(--brand)]/20 mb-4">
                  <Share2 className="w-6 h-6 text-[var(--brand)]" />
                </div>
                <h2 className="text-2xl font-bold text-white">Threat Intelligence</h2>
                <p className="text-zinc-500 text-sm mt-2">Share and receive threat data from the AEGIS community</p>
              </div>

              <div className={`p-5 rounded-xl border transition-all duration-200 ${
                state.intelSharingEnabled ? 'border-[var(--brand)]/20 bg-[var(--brand)]/5' : 'border-white/[0.06]'
              }`}>
                <button
                  onClick={() => update({ intelSharingEnabled: !state.intelSharingEnabled })}
                  className="w-full flex items-center gap-3 text-left"
                >
                  <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${
                    state.intelSharingEnabled ? 'bg-[var(--brand)]/10' : 'bg-white/[0.04]'
                  }`}>
                    <Share2 className={`w-4 h-4 ${state.intelSharingEnabled ? 'text-[var(--brand)]' : 'text-zinc-500'}`} />
                  </div>
                  <div className="flex-1">
                    <div className="text-sm font-medium text-white">Share Threat Intelligence with AEGIS Community</div>
                    <div className="text-xs text-zinc-500 mt-1">
                      When enabled, anonymized threat indicators are shared with the community.
                      No personal data leaves your system.
                    </div>
                  </div>
                  <ToggleSwitch enabled={state.intelSharingEnabled} />
                </button>
              </div>

              <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
                <h3 className="text-xs font-medium text-zinc-400 uppercase tracking-wider mb-3">What gets shared</h3>
                <ul className="space-y-2 text-xs text-zinc-500">
                  <li className="flex items-center gap-2">
                    <Check className="w-3 h-3 text-[var(--success)]" />
                    Anonymized IP reputation data (hashed IPs)
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-3 h-3 text-[var(--success)]" />
                    Attack patterns and techniques observed
                  </li>
                  <li className="flex items-center gap-2">
                    <Check className="w-3 h-3 text-[var(--success)]" />
                    Malware signatures and indicators of compromise
                  </li>
                  <li className="flex items-center gap-2">
                    <X className="w-3 h-3 text-[var(--danger)]" />
                    No hostnames, internal IPs, or organization data
                  </li>
                </ul>
              </div>

              {error && <ErrorMessage message={error} />}

              <div className="flex gap-3">
                <BackButton onClick={() => animateStep(5)} />
                <StepButton
                  label={state.intelSharingEnabled ? 'Enable & Continue' : 'Continue'}
                  loading={loading}
                  onClick={handleStep6Intel}
                />
                <SkipButton onClick={() => handleSkipStep(6)} />
              </div>
            </div>
          )}

          {/* --- STEP 7: Ready --- */}
          {step === 7 && (
            <div className="space-y-6">
              <div className="text-center mb-2">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-[var(--success)]/10 border border-[var(--success)]/20 mb-4">
                  <ShieldCheck className="w-6 h-6 text-[var(--success)]" />
                </div>
                <h2 className="text-2xl font-bold text-white">You&apos;re All Set</h2>
                <p className="text-zinc-500 text-sm mt-2">Review your configuration before entering the dashboard</p>
              </div>

              <div className="space-y-2">
                {summaryItems().map(item => {
                  const ItemIcon = item.icon;
                  return (
                    <div key={item.label} className={`flex items-center gap-3 p-3.5 rounded-xl border transition-all duration-200 ${
                      item.done ? 'border-[var(--success)]/10 bg-[var(--success)]/[0.02]' : 'border-white/[0.06]'
                    }`}>
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${
                        item.done ? 'bg-[var(--success)]/10' : 'bg-white/[0.04]'
                      }`}>
                        <ItemIcon className={`w-4 h-4 ${item.done ? 'text-[var(--success)]' : 'text-zinc-600'}`} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-white">{item.label}</span>
                          {item.done && <Check className="w-3 h-3 text-[var(--success)]" />}
                        </div>
                        <div className="text-xs text-zinc-500">{item.value}</div>
                      </div>
                      {!item.done && (
                        <button
                          onClick={() => animateStep(item.stepNum)}
                          className="text-[11px] text-[var(--brand)] hover:text-[var(--brand)] font-medium transition-colors flex-shrink-0"
                        >
                          Configure
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>

              {/* Completion stats */}
              <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-medium text-zinc-400">Setup completion</span>
                  <span className="text-xs font-mono text-[var(--brand)]">
                    {summaryItems().filter(i => i.done).length}/{summaryItems().length}
                  </span>
                </div>
                <div className="w-full h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
                  <div
                    className="h-full bg-[var(--success)] rounded-full transition-all duration-700 ease-out"
                    style={{ width: `${(summaryItems().filter(i => i.done).length / summaryItems().length) * 100}%` }}
                  />
                </div>
              </div>

              <button
                onClick={handleFinish}
                className="w-full bg-[var(--brand)] hover:bg-[var(--brand)] text-[#09090B] font-semibold py-3 rounded-xl transition-all duration-200 hover:shadow-lg hover:shadow-[var(--brand)]/10 active:scale-[0.98] flex items-center justify-center gap-2"
              >
                Go to Dashboard
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-zinc-700 mt-8">
          AEGIS Defense Platform &middot; v1.4.0
        </p>
      </div>

      {/* Upgrade Modal */}
      {showUpgradeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={() => setShowUpgradeModal(false)} />
          <div className="relative bg-[#18181B] border border-white/[0.06] rounded-2xl p-8 max-w-md w-full shadow-2xl">
            <button
              onClick={() => setShowUpgradeModal(false)}
              className="absolute top-4 right-4 text-zinc-500 hover:text-white transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
            <div className="text-center mb-6">
              <div className="inline-flex items-center justify-center w-14 h-14 rounded-xl bg-[var(--brand-accent)]/10 border border-[var(--brand-accent)]/20 mb-4">
                <Crown className="w-7 h-7 text-[var(--brand-accent)]" />
              </div>
              <h3 className="text-xl font-bold text-white">Upgrade to Enterprise</h3>
              <p className="text-sm text-zinc-500 mt-2">
                Smart Honeypots use AI to create indistinguishable decoys that mirror your real services, catching even sophisticated attackers.
              </p>
            </div>
            <div className="space-y-2 mb-6">
              {['AI-powered deception that adapts to attackers', 'Automatically mimics your real applications', 'Advanced attacker profiling and forensics'].map(f => (
                <div key={f} className="flex items-center gap-2 text-sm text-zinc-300">
                  <Check className="w-4 h-4 text-[var(--brand-accent)] flex-shrink-0" />
                  {f}
                </div>
              ))}
            </div>
            <button
              onClick={() => {
                setShowUpgradeModal(false);
                router.push('/dashboard/settings');
              }}
              className="w-full bg-[var(--brand-accent)] hover:bg-[var(--brand-accent)] text-white font-semibold py-3 rounded-xl transition-all duration-200 hover:shadow-lg hover:shadow-[var(--brand-accent)]/20 active:scale-[0.98] flex items-center justify-center gap-2"
            >
              <Crown className="w-4 h-4" />
              Contact Sales
            </button>
            <button
              onClick={() => setShowUpgradeModal(false)}
              className="w-full mt-2 py-2 text-sm text-zinc-500 hover:text-zinc-300 transition-colors"
            >
              Maybe later
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/* ──────────────────────────────────────────────
   Sub-components
   ────────────────────────────────────────────── */

interface InputFieldProps {
  label: string;
  icon: typeof Lock;
  value: string;
  onChange: (v: string) => void;
  onKeyDown?: (e: React.KeyboardEvent) => void;
  placeholder?: string;
  type?: string;
  autoComplete?: string;
}

const InputField = forwardRef<HTMLInputElement, InputFieldProps>(function InputField(
  { label, icon: Icon, value, onChange, onKeyDown, placeholder, type = 'text', autoComplete },
  ref
) {
  return (
    <div>
      <label className="block text-xs font-medium text-zinc-400 mb-2">{label}</label>
      <div className="relative">
        <Icon className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-600" />
        <input
          ref={ref}
          type={type}
          value={value}
          onChange={e => onChange(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder={placeholder}
          autoComplete={autoComplete}
          spellCheck={false}
          className="w-full bg-[#09090B] border border-white/[0.06] text-white placeholder-zinc-600 rounded-xl px-4 py-3 pl-11 text-sm focus:outline-none focus:border-[var(--brand)]/40 focus:ring-1 focus:ring-[var(--brand)]/20 transition-all duration-200"
        />
      </div>
    </div>
  );
});

function StepButton({ label, loading, onClick }: { label: string; loading: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      className="flex-1 bg-[var(--brand)] hover:bg-[var(--brand)] disabled:opacity-50 disabled:cursor-not-allowed text-[#09090B] font-semibold py-3 rounded-xl transition-all duration-200 hover:shadow-lg hover:shadow-[var(--brand)]/10 active:scale-[0.98] flex items-center justify-center gap-2"
    >
      {loading ? (
        <>
          <Loader2 className="w-4 h-4 animate-spin" />
          Processing...
        </>
      ) : (
        <>
          {label}
          <ChevronRight className="w-4 h-4" />
        </>
      )}
    </button>
  );
}

function BackButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="px-5 py-3 rounded-xl border border-white/[0.06] text-zinc-400 hover:text-white hover:border-white/[0.1] transition-all duration-200 flex items-center gap-1"
    >
      <ChevronLeft className="w-4 h-4" />
      Back
    </button>
  );
}

function SkipButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="px-4 py-3 rounded-xl text-zinc-600 hover:text-zinc-400 text-sm font-medium transition-all duration-200"
    >
      Skip
    </button>
  );
}

function ErrorMessage({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 text-[var(--danger)] text-xs font-medium bg-[var(--danger)]/5 border border-[var(--danger)]/10 rounded-xl p-3">
      <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
      <span>{message}</span>
    </div>
  );
}

function ToggleSwitch({ enabled }: { enabled: boolean }) {
  return (
    <div className={`w-10 h-5 rounded-full transition-colors duration-200 relative ${
      enabled ? 'bg-[var(--brand)]' : 'bg-white/10'
    }`}>
      <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform duration-200 ${
        enabled ? 'translate-x-5' : 'translate-x-0.5'
      }`} />
    </div>
  );
}
