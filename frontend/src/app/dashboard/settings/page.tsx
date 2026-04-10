'use client';

import { useState, useEffect, useRef } from 'react';
import { Settings01Icon, Radar01Icon, Bug01Icon } from 'hugeicons-react';
import {
  Key, Bell, Cpu, Save, RefreshCw, Eye, EyeOff, Copy, Check,
  Sparkles, ArrowUp, Shield, BellRing, Send, Globe,
  Zap, ChevronDown, TestTube, BookOpen, ExternalLink,
  Activity, Bug, Fingerprint, Flame, Radar, Bot,
} from 'lucide-react';
import { LoadingState } from '@/components/shared/LoadingState';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';
import { MODEL_ROUTING_DEFAULTS } from '@/lib/constants';

/* ──────────────────────────────────────────
   Types
   ────────────────────────────────────────── */

interface ClientInfo {
  id: string;
  name: string;
  slug: string;
  api_key: string;
  settings?: Record<string, unknown>;
}

interface NotifSettings {
  webhook_url: string;
  webhook_format: string;
  email_enabled: boolean;
  email_recipients: string[];
  notify_on_critical: boolean;
  notify_on_high: boolean;
  notify_on_actions: boolean;
  notify_on_scan_completed: boolean;
  telegram_enabled: boolean;
  telegram_bot_token: string;
  telegram_chat_id: string;
  telegram_connected: boolean;
}

interface ScanIntervals {
  full_scan_minutes: number;
  quick_scan_minutes: number;
  discovery_minutes: number;
  adaptive_scanning: boolean;
}

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

/* ──────────────────────────────────────────
   Defaults
   ────────────────────────────────────────── */

const DEMO_CLIENT: ClientInfo = {
  id: 'demo-client-001',
  name: 'Demo Organization',
  slug: 'demo-org',
  api_key: 'your-api-key-here',
};

const DEMO_NOTIFICATIONS: NotifSettings = {
  webhook_url: '',
  webhook_format: 'generic',
  email_enabled: false,
  email_recipients: [],
  notify_on_critical: true,
  notify_on_high: true,
  notify_on_actions: true,
  notify_on_scan_completed: false,
  telegram_enabled: false,
  telegram_bot_token: '',
  telegram_chat_id: '',
  telegram_connected: false,
};

const DEFAULT_SCAN_INTERVALS: ScanIntervals = {
  full_scan_minutes: 120,
  quick_scan_minutes: 30,
  discovery_minutes: 60,
  adaptive_scanning: false,
};

const QUICK_ACTIONS = [
  { label: 'Security Posture', icon: Shield, prompt: "What's the current security posture?" },
  { label: 'Scan Config', icon: Radar01Icon, prompt: 'Scan all my web services every 30 minutes' },
  { label: 'Alert Rules', icon: BellRing, prompt: 'Set critical alerts to notify via webhook' },
  { label: 'Deploy Honeypot', icon: Bug01Icon, prompt: 'Deploy SSH honeypot on port 2222' },
];

const WEBHOOK_FORMATS = [
  { value: 'generic', label: 'Generic JSON' },
  { value: 'discord', label: 'Discord' },
  { value: 'slack', label: 'Slack' },
];

/* ──────────────────────────────────────────
   Helpers
   ────────────────────────────────────────── */

function formatAIContent(text: string) {
  const lines = text.split('\n');
  const elements: React.ReactNode[] = [];

  lines.forEach((line, i) => {
    let processed: React.ReactNode = line;

    if (line.includes('**')) {
      const parts = line.split(/\*\*(.*?)\*\*/g);
      processed = parts.map((part, j) =>
        j % 2 === 1 ? <strong key={j} className="text-[#E5E5E5] font-semibold">{part}</strong> : part
      );
    }

    if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
      elements.push(
        <div key={i} className="flex gap-2 pl-1">
          <span className="text-[#22D3EE] mt-0.5 shrink-0">&#8226;</span>
          <span>{typeof processed === 'string' ? line.trim().slice(2) : processed}</span>
        </div>
      );
      return;
    }

    if (line.trim() === '') {
      elements.push(<div key={i} className="h-2" />);
      return;
    }

    elements.push(<div key={i}>{processed}</div>);
  });

  return elements;
}

function formatMinutes(min: number): string {
  if (min < 60) return `${min}min`;
  const h = Math.floor(min / 60);
  const m = min % 60;
  return m > 0 ? `${h}h ${m}m` : `${h}h`;
}

/* ──────────────────────────────────────────
   Reusable Components
   ────────────────────────────────────────── */

function Toggle({ enabled, onChange, label, description }: {
  enabled: boolean;
  onChange: () => void;
  label: string;
  description?: string;
}) {
  return (
    <div className="flex items-center justify-between py-3">
      <div className="flex-1 min-w-0 mr-4">
        <span className="text-[13px] text-[#E5E5E5] block">{label}</span>
        {description && <span className="text-[11px] text-[#525252] block mt-0.5">{description}</span>}
      </div>
      <button
        onClick={onChange}
        aria-label={`Toggle ${label}`}
        className={cn(
          'relative w-11 h-6 rounded-full transition-colors duration-200 shrink-0',
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
  );
}

function StatusDot({ connected, label }: { connected: boolean; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className={cn(
        'w-1.5 h-1.5 rounded-full shrink-0',
        connected ? 'bg-[#22C55E]' : 'bg-[#525252]'
      )} />
      <span className={cn('text-[11px]', connected ? 'text-[#22C55E]' : 'text-[#737373]')}>
        {label}
      </span>
    </div>
  );
}

function SectionCard({ children, title, description, headerRight }: {
  children: React.ReactNode;
  title: string;
  description?: string;
  headerRight?: React.ReactNode;
}) {
  return (
    <div className="bg-[#0A0A0A] border border-white/[0.04] rounded-xl overflow-hidden">
      <div className="px-4 sm:px-6 py-4 border-b border-white/[0.04] flex items-center justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-[13px] font-medium text-[#E5E5E5] uppercase tracking-wider">{title}</h3>
          {description && <p className="hidden sm:block text-[11px] text-[#737373] mt-0.5">{description}</p>}
        </div>
        {headerRight}
      </div>
      {children}
    </div>
  );
}

function IntervalSlider({ label, value, min, max, step, onChange }: {
  label: string;
  value: number;
  min: number;
  max: number;
  step: number;
  onChange: (v: number) => void;
}) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <label className="text-[13px] text-[#E5E5E5]">{label}</label>
        <span className="text-[13px] font-mono text-[#22D3EE]">{formatMinutes(value)}</span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full h-1.5 bg-white/[0.04] rounded-full appearance-none cursor-pointer accent-[#22D3EE] [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-4 [&::-webkit-slider-thumb]:h-4 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-[#22D3EE] [&::-webkit-slider-thumb]:cursor-pointer"
      />
      <div className="flex justify-between text-[10px] text-[#525252]">
        <span>{formatMinutes(min)}</span>
        <span>{formatMinutes(max)}</span>
      </div>
    </div>
  );
}

/* ──────────────────────────────────────────
   Main Page
   ────────────────────────────────────────── */

export default function SettingsPage() {
  const [loading, setLoading] = useState(true);
  const [client, setClient] = useState<ClientInfo>(DEMO_CLIENT);
  const [models, setModels] = useState<Array<{ task_type: string; model: string; description: string }>>(MODEL_ROUTING_DEFAULTS.map((m) => ({ ...m })));
  const [notifications, setNotifications] = useState<NotifSettings>(DEMO_NOTIFICATIONS);
  const [scanIntervals, setScanIntervals] = useState<ScanIntervals>(DEFAULT_SCAN_INTERVALS);
  const [showApiKey, setShowApiKey] = useState(false);
  const [copied, setCopied] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState<string | null>(null);
  const [tab, setTab] = useState<'client' | 'models' | 'notifications' | 'scanning' | 'apikeys' | 'guide'>('client');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [webhookFormat, setWebhookFormat] = useState('generic');
  const [emailRecipients, setEmailRecipients] = useState('');
  const [clientName, setClientName] = useState('');
  const [activeProvider, setActiveProvider] = useState('openrouter');

  const [showBotToken, setShowBotToken] = useState(false);
  const [telegramBotToken, setTelegramBotToken] = useState('');
  const [telegramChatId, setTelegramChatId] = useState('');
  const [telegramEnabled, setTelegramEnabled] = useState(false);
  const [telegramConnected, setTelegramConnected] = useState(false);
  const [testingTelegram, setTestingTelegram] = useState(false);
  const [telegramTestResult, setTelegramTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const [testingWebhook, setTestingWebhook] = useState(false);
  const [webhookTestResult, setWebhookTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const [testingModel, setTestingModel] = useState<string | null>(null);
  const [modelTestResult, setModelTestResult] = useState<{ task: string; success: boolean; response: string; latency_ms: number } | null>(null);

  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    async function load() {
      try {
        const [c, m, n] = await Promise.allSettled([
          api.settings.client(),
          api.settings.models(),
          api.settings.notifications(),
        ]);
        if (c.status === 'fulfilled') {
          setClient(c.value);
          setClientName(c.value.name);
          const settings = c.value.settings as Record<string, unknown> | undefined;
          if (settings?.scan_intervals) {
            const si = settings.scan_intervals as ScanIntervals;
            setScanIntervals({ ...DEFAULT_SCAN_INTERVALS, ...si });
          }
          if (settings?.ai_provider) {
            setActiveProvider(settings.ai_provider as string);
          }
        }
        if (m.status === 'fulfilled') setModels(m.value.map((v) => ({ ...v })));
        if (n.status === 'fulfilled') {
          setNotifications(n.value);
          setWebhookUrl(n.value.webhook_url || '');
          setWebhookFormat(n.value.webhook_format || 'generic');
          setEmailRecipients((n.value.email_recipients || []).join(', '));
          setTelegramBotToken(n.value.telegram_bot_token || '');
          setTelegramChatId(n.value.telegram_chat_id || '');
          setTelegramEnabled(n.value.telegram_enabled || false);
          setTelegramConnected(n.value.telegram_connected || false);
        }
      } catch {
        // Use demo data
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);


  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatMessages, chatLoading]);

  /* -- Chat handlers -- */

  const sendChatMessage = async (message: string) => {
    if (!message.trim() || chatLoading) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: message.trim(),
      timestamp: 'now',
    };

    setChatMessages((prev) => [...prev, userMsg]);
    setChatInput('');
    setChatLoading(true);

    try {
      const response = await api.ask.send(message.trim(), 'settings');
      const aiMsg: ChatMessage = {
        id: `ai-${Date.now()}`,
        role: 'assistant',
        content: response.answer || 'Configuration updated successfully.',
        timestamp: 'now',
      };
      setChatMessages((prev) => [...prev, aiMsg]);
    } catch {
      const errorMsg: ChatMessage = {
        id: `error-${Date.now()}`,
        role: 'assistant',
        content: 'Unable to process your request. Please check your connection and try again.',
        timestamp: 'now',
      };
      setChatMessages((prev) => [...prev, errorMsg]);
    } finally {
      setChatLoading(false);
    }
  };

  const handleQuickAction = (prompt: string) => {
    setChatInput(prompt);
    inputRef.current?.focus();
  };

  const handleChatKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendChatMessage(chatInput);
    }
  };

  /* -- Save handlers -- */

  const flashSaveSuccess = (msg: string) => {
    setSaveSuccess(msg);
    setTimeout(() => setSaveSuccess(null), 3000);
  };

  const copyApiKey = () => {
    navigator.clipboard.writeText(client.api_key);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const saveClientName = async () => {
    if (!clientName.trim() || clientName === client.name) return;
    setSaving(true);
    try {
      const updated = await api.settings.updateClient({ name: clientName.trim() }) as ClientInfo;
      setClient(updated);
      flashSaveSuccess('Organization name saved');
    } catch {
      // Demo mode
    } finally {
      setSaving(false);
    }
  };

  const saveNotifications = async () => {
    setSaving(true);
    const updated: NotifSettings = {
      ...notifications,
      webhook_url: webhookUrl,
      webhook_format: webhookFormat,
      email_recipients: emailRecipients.split(',').map((e) => e.trim()).filter(Boolean),
      telegram_enabled: telegramEnabled,
      telegram_bot_token: telegramBotToken,
      telegram_chat_id: telegramChatId,
      telegram_connected: telegramConnected,
    };
    try {
      await api.settings.updateNotifications({ ...updated });
      setNotifications(updated);
      flashSaveSuccess('Notification settings saved');
    } catch {
      setNotifications(updated);
    } finally {
      setSaving(false);
    }
  };

  const saveModels = async () => {
    setSaving(true);
    try {
      await api.settings.updateModels(models.map((m) => ({ task_type: m.task_type, model: m.model })));
      flashSaveSuccess('Model routing saved');
    } catch {
      // Demo mode
    } finally {
      setSaving(false);
    }
  };

  const switchProvider = async (provider: string) => {
    setSaving(true);
    try {
      await api.ai.setActive(provider);
      setActiveProvider(provider);
      flashSaveSuccess(`Switched to ${provider}`);
    } catch {
      setActiveProvider(provider);
    } finally {
      setSaving(false);
    }
  };

  const saveScanIntervals = async () => {
    setSaving(true);
    try {
      const updated = await api.settings.updateClient({
        settings: { ...((client.settings as Record<string, unknown>) || {}), scan_intervals: scanIntervals },
      }) as ClientInfo;
      setClient(updated);
      flashSaveSuccess('Scan intervals saved');
    } catch {
      // Demo mode
    } finally {
      setSaving(false);
    }
  };

  /* -- Test handlers -- */

  const testTelegram = async () => {
    setTestingTelegram(true);
    setTelegramTestResult(null);
    try {
      const result = await api.settings.testNotification('telegram');
      setTelegramTestResult(result);
      if (result.success) setTelegramConnected(true);
    } catch {
      setTelegramTestResult({ success: false, message: 'Failed to send test message. Check token and chat ID.' });
    } finally {
      setTestingTelegram(false);
    }
  };

  const testWebhook = async () => {
    setTestingWebhook(true);
    setWebhookTestResult(null);
    try {
      const result = await api.settings.testWebhook();
      setWebhookTestResult(result);
    } catch {
      setWebhookTestResult({ success: false, message: 'Failed to reach webhook URL.' });
    } finally {
      setTestingWebhook(false);
    }
  };

  const testModel = async (taskType: string, model: string) => {
    setTestingModel(taskType);
    setModelTestResult(null);
    try {
      const result = await api.settings.testModel(taskType, model);
      setModelTestResult({ task: taskType, ...result });
    } catch {
      setModelTestResult({ task: taskType, success: false, response: 'Model unreachable or timed out.', latency_ms: 0 });
    } finally {
      setTestingModel(null);
    }
  };

  if (loading) return <LoadingState message="Loading settings..." />;

  const SaveButton = ({ onClick, label }: { onClick: () => void; label?: string }) => (
    <button
      onClick={onClick}
      disabled={saving}
      className="flex items-center gap-2 text-[#E5E5E5] border border-white/[0.04] hover:bg-white/[0.04] font-medium px-3 sm:px-4 py-2 rounded-xl transition-colors text-[13px] disabled:opacity-50 shrink-0"
    >
      {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
      <span className="hidden sm:inline">{label || 'Save Changes'}</span>
      <span className="sm:hidden">Save</span>
    </button>
  );

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-[22px] sm:text-[28px] font-bold text-[#E5E5E5] tracking-tight">Settings</h1>
        <p className="hidden sm:block text-sm text-[#737373] mt-1">Platform configuration, AI model routing, notifications, and scan management</p>
      </div>

      {/* Save success toast */}
      {saveSuccess && (
        <div className="fixed top-4 right-4 z-50 flex items-center gap-2 bg-[#22C55E]/10 border border-[#22C55E]/20 text-[#22C55E] text-[13px] font-medium px-4 py-2.5 rounded-xl animate-fade-in">
          <Check className="w-4 h-4" />
          {saveSuccess}
        </div>
      )}

      {/* AI Configuration Assistant */}
      <div className="bg-[#0A0A0A] border border-white/[0.04] rounded-xl overflow-hidden">
        <div className="px-4 sm:px-6 py-4 border-b border-white/[0.04]">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#22D3EE]/10 flex items-center justify-center">
              <Sparkles className="w-4 h-4 text-[#22D3EE]" />
            </div>
            <div>
              <h3 className="text-[13px] font-medium text-[#E5E5E5]">AI Configuration Assistant</h3>
              <p className="text-[11px] text-[#737373]">Configure AEGIS using natural language</p>
            </div>
          </div>

          <div className="flex flex-wrap gap-2 mt-4">
            {QUICK_ACTIONS.map((action) => (
              <button
                key={action.label}
                onClick={() => handleQuickAction(action.prompt)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.03] border border-white/[0.04] text-[12px] text-[#737373] hover:text-[#22D3EE] hover:border-[#22D3EE]/20 transition-all duration-200"
              >
                <action.icon className="w-3 h-3" size={12} />
                {action.label}
              </button>
            ))}
          </div>
        </div>

        <div className="max-h-[300px] sm:max-h-[400px] overflow-y-auto p-4 sm:p-6 space-y-4">
          {chatMessages.length === 0 && (
            <div className="text-center py-10">
              <div className="w-12 h-12 rounded-xl bg-white/[0.02] flex items-center justify-center mx-auto mb-3">
                <Sparkles className="w-5 h-5 text-[#525252]" />
              </div>
              <p className="text-[13px] text-[#525252]">Ask AEGIS to configure your security platform</p>
              <p className="text-[11px] text-[#525252] mt-1">Try clicking a quick action above to get started</p>
            </div>
          )}

          {chatMessages.map((msg) => (
            <div
              key={msg.id}
              className={cn('flex', msg.role === 'user' ? 'justify-end' : 'justify-start')}
            >
              <div
                className={cn(
                  'max-w-[80%] text-[13px] leading-relaxed',
                  msg.role === 'user'
                    ? 'bg-[#22D3EE]/10 text-[#22D3EE] rounded-xl rounded-br-md px-4 py-2'
                    : 'bg-white/[0.02] text-[#737373] rounded-xl rounded-bl-md px-4 py-3'
                )}
              >
                {msg.role === 'assistant' ? (
                  <div className="space-y-1">{formatAIContent(msg.content)}</div>
                ) : (
                  msg.content
                )}
                <p className={cn(
                  'text-[10px] mt-1.5',
                  msg.role === 'user' ? 'text-[#22D3EE]/40' : 'text-[#525252]'
                )}>
                  {msg.timestamp}
                </p>
              </div>
            </div>
          ))}

          {chatLoading && (
            <div className="flex justify-start">
              <div className="bg-white/[0.02] rounded-xl rounded-bl-md px-4 py-3">
                <div className="flex items-center gap-2 text-[13px] text-[#737373]">
                  <span>AEGIS is thinking</span>
                  <span className="inline-flex gap-0.5">
                    <span className="w-1 h-1 rounded-full bg-[#22D3EE] animate-bounce" style={{ animationDelay: '0ms' }} />
                    <span className="w-1 h-1 rounded-full bg-[#22D3EE] animate-bounce" style={{ animationDelay: '150ms' }} />
                    <span className="w-1 h-1 rounded-full bg-[#22D3EE] animate-bounce" style={{ animationDelay: '300ms' }} />
                  </span>
                </div>
              </div>
            </div>
          )}

          <div ref={chatEndRef} />
        </div>

        <div className="px-4 sm:px-6 py-4 border-t border-white/[0.04]">
          <div className="flex items-center gap-3">
            <input
              ref={inputRef}
              type="text"
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              onKeyDown={handleChatKeyDown}
              placeholder="Tell AEGIS what to configure..."
              className="flex-1 bg-[#09090B] border border-white/[0.04] rounded-xl px-4 py-2.5 text-sm text-[#E5E5E5] placeholder:text-[#525252] focus:outline-none focus:border-[#22D3EE]/30 transition-colors"
            />
            <button
              onClick={() => sendChatMessage(chatInput)}
              disabled={!chatInput.trim() || chatLoading}
              className="w-10 h-10 rounded-xl bg-[#22D3EE] hover:bg-[#06B6D4] disabled:opacity-30 disabled:hover:bg-[#22D3EE] flex items-center justify-center transition-colors shrink-0"
            >
              <ArrowUp className="w-4 h-4 text-[#09090B]" />
            </button>
          </div>
        </div>
      </div>

      {/* Tab Bar -- underline style */}
      <div className="flex items-center gap-2 sm:gap-4 border-b border-white/[0.04] overflow-x-auto">
        {[
          { id: 'client' as const, label: 'Client', icon: Settings01Icon },
          { id: 'models' as const, label: 'AI Models', icon: Cpu },
          { id: 'notifications' as const, label: 'Notifications', icon: Bell },
          { id: 'scanning' as const, label: 'Scanning', icon: Radar01Icon },
          { id: 'apikeys' as const, label: 'API Keys', icon: Key },
          { id: 'guide' as const, label: 'Feature Guide', icon: BookOpen },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={cn(
              'pb-3 text-[13px] font-medium border-b-2 transition-colors -mb-px flex items-center gap-2 whitespace-nowrap',
              tab === t.id ? 'border-[#22D3EE] text-[#22D3EE]' : 'border-transparent text-[#737373] hover:text-[#E5E5E5]'
            )}
          >
            <t.icon className="w-4 h-4" size={16} />
            {t.label}
          </button>
        ))}
      </div>

      {/* Client Tab */}
      {tab === 'client' && (
        <SectionCard
          title="Client Information"
          headerRight={
            clientName !== client.name ? (
              <SaveButton onClick={saveClientName} label="Save Name" />
            ) : undefined
          }
        >
          <div className="p-4 sm:p-6 space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="text-[10px] font-medium text-[#525252] uppercase tracking-wider block mb-1.5">Organization Name</label>
                <input
                  type="text"
                  value={clientName}
                  onChange={(e) => setClientName(e.target.value)}
                  className="w-full bg-[#09090B] border border-white/[0.04] rounded-xl px-4 py-2.5 text-sm text-[#E5E5E5] focus:outline-none focus:border-[#22D3EE]/30 transition-colors"
                />
              </div>
              <div>
                <label className="text-[10px] font-medium text-[#525252] uppercase tracking-wider block mb-1.5">Slug</label>
                <input
                  type="text"
                  value={client.slug}
                  readOnly
                  className="w-full bg-[#09090B] border border-white/[0.04] rounded-xl px-4 py-2.5 text-sm text-[#E5E5E5] font-mono"
                />
              </div>
            </div>
            <div>
              <label className="text-[10px] font-medium text-[#525252] uppercase tracking-wider block mb-1.5">Client ID</label>
              <input
                type="text"
                value={client.id}
                readOnly
                className="w-full bg-[#09090B] border border-white/[0.04] rounded-xl px-4 py-2.5 text-sm text-[#737373] font-mono"
              />
            </div>
          </div>
        </SectionCard>
      )}

      {/* AI Models Tab */}
      {tab === 'models' && (
        <div className="space-y-4">
          <SectionCard
            title="AI Provider"
            description="Select the AI provider for all model routing"
            headerRight={
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[#22C55E]/10 border border-[#22C55E]/20 text-[11px] font-medium text-[#22C55E]">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#22C55E] animate-pulse" />
                  Active
                </span>
              </div>
            }
          >
            <div className="p-4 sm:p-6">
              <div className="flex flex-wrap gap-2">
                {['openrouter', 'inception', 'openai', 'anthropic'].map((p) => (
                  <button
                    key={p}
                    onClick={() => switchProvider(p)}
                    disabled={saving}
                    className={cn(
                      'px-4 py-2 rounded-xl text-[13px] font-medium transition-all border',
                      activeProvider === p
                        ? 'bg-[#22D3EE]/10 border-[#22D3EE]/20 text-[#22D3EE]'
                        : 'bg-white/[0.02] border-white/[0.04] text-[#737373] hover:text-[#E5E5E5] hover:border-white/[0.08]'
                    )}
                  >
                    {p.charAt(0).toUpperCase() + p.slice(1)}
                    {activeProvider === p && <Check className="inline w-3.5 h-3.5 ml-1.5" />}
                  </button>
                ))}
              </div>
            </div>
          </SectionCard>

          <SectionCard
            title="Model Routing"
            description="Assign models per task type. Click the test tube to verify connectivity."
            headerRight={<SaveButton onClick={saveModels} />}
          >
            <div>
              {models.map((model, idx) => (
                <div key={model.task_type} className={cn('px-4 sm:px-6 py-4 flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4', idx < models.length - 1 && 'border-b border-white/[0.02]')}>
                  <div className="flex-1 min-w-0">
                    <p className="text-[13px] font-medium text-[#E5E5E5] capitalize">{model.task_type.replace(/_/g, ' ')}</p>
                    <p className="text-[11px] text-[#737373]">{model.description}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      value={model.model}
                      onChange={(e) => {
                        const updated = [...models];
                        updated[idx] = { ...updated[idx], model: e.target.value };
                        setModels(updated);
                      }}
                      className="w-full sm:w-72 bg-[#09090B] border border-white/[0.04] rounded-xl px-3 py-2 text-[#E5E5E5] text-[11px] font-mono focus:outline-none focus:border-[#22D3EE]/30"
                    />
                    <button
                      onClick={() => testModel(model.task_type, model.model)}
                      disabled={testingModel === model.task_type}
                      title="Test this model"
                      className="p-2 rounded-lg bg-white/[0.03] border border-white/[0.04] text-[#737373] hover:text-[#22D3EE] hover:border-[#22D3EE]/20 transition-colors disabled:opacity-30 shrink-0"
                    >
                      {testingModel === model.task_type ? (
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <TestTube className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                  {modelTestResult && modelTestResult.task === model.task_type && (
                    <div className={cn(
                      'w-full mt-2 px-3 py-2 rounded-lg text-[11px] font-mono',
                      modelTestResult.success
                        ? 'bg-[#22C55E]/10 border border-[#22C55E]/20 text-[#22C55E]'
                        : 'bg-[#EF4444]/10 border border-[#EF4444]/20 text-[#EF4444]'
                    )}>
                      {modelTestResult.success && <span className="text-[#737373]">Latency: {modelTestResult.latency_ms}ms -- </span>}
                      {modelTestResult.response.slice(0, 120)}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </SectionCard>
        </div>
      )}

      {/* Notifications Tab */}
      {tab === 'notifications' && (
        <div className="space-y-4">
          <SectionCard
            title="Telegram Notifications"
            description="Receive real-time alerts via Telegram bot"
            headerRight={
              <StatusDot
                connected={telegramConnected}
                label={telegramConnected ? 'Connected' : 'Not configured'}
              />
            }
          >
            <div className="p-4 sm:p-6 space-y-4">
              <Toggle
                enabled={telegramEnabled}
                onChange={() => setTelegramEnabled(!telegramEnabled)}
                label="Enable Telegram notifications"
                description="Send incident alerts and scan results to your Telegram chat"
              />

              {telegramEnabled && (
                <>
                  <div>
                    <label className="text-[10px] font-medium text-[#525252] uppercase tracking-wider block mb-1.5">Bot Token</label>
                    <div className="relative">
                      <input
                        type={showBotToken ? 'text' : 'password'}
                        value={telegramBotToken}
                        onChange={(e) => setTelegramBotToken(e.target.value)}
                        placeholder="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
                        className="w-full bg-[#09090B] border border-white/[0.04] rounded-xl px-4 py-2.5 text-sm text-[#E5E5E5] placeholder:text-[#525252] focus:outline-none focus:border-[#22D3EE]/30 font-mono pr-12"
                      />
                      <button
                        onClick={() => setShowBotToken(!showBotToken)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 p-1 text-[#737373] hover:text-[#E5E5E5] transition-colors"
                        aria-label={showBotToken ? 'Hide bot token' : 'Show bot token'}
                      >
                        {showBotToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  <div>
                    <label className="text-[10px] font-medium text-[#525252] uppercase tracking-wider block mb-1.5">Chat ID</label>
                    <input
                      type="text"
                      value={telegramChatId}
                      onChange={(e) => setTelegramChatId(e.target.value)}
                      placeholder="-1001234567890"
                      className="w-full bg-[#09090B] border border-white/[0.04] rounded-xl px-4 py-2.5 text-sm text-[#E5E5E5] placeholder:text-[#525252] focus:outline-none focus:border-[#22D3EE]/30 font-mono"
                    />
                  </div>

                  <div className="flex items-center gap-3">
                    <button
                      onClick={testTelegram}
                      disabled={testingTelegram || !telegramBotToken || !telegramChatId}
                      className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white/[0.04] border border-white/[0.04] text-[13px] text-[#737373] hover:text-[#22D3EE] hover:border-[#22D3EE]/20 transition-all disabled:opacity-30"
                    >
                      {testingTelegram ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                      Send Test Message
                    </button>
                    {telegramTestResult && (
                      <span className={cn(
                        'text-[12px]',
                        telegramTestResult.success ? 'text-[#22C55E]' : 'text-[#EF4444]'
                      )}>
                        {telegramTestResult.message}
                      </span>
                    )}
                  </div>

                  <div className="bg-white/[0.02] border border-white/[0.04] rounded-xl p-3">
                    <p className="text-[11px] text-[#737373] leading-relaxed">
                      <span className="text-[#E5E5E5] font-medium">Setup:</span> Create a bot via{' '}
                      <span className="text-[#22D3EE]">@BotFather</span> on Telegram, get the token, then send a message to the bot and use{' '}
                      <span className="text-[#22D3EE] font-mono text-[10px]">https://api.telegram.org/bot&lt;TOKEN&gt;/getUpdates</span>{' '}
                      to find your chat_id.
                    </p>
                  </div>
                </>
              )}
            </div>
          </SectionCard>

          <SectionCard
            title="Webhook Integration"
            description="Send alerts to Discord, Slack, or custom endpoints"
            headerRight={
              <StatusDot
                connected={!!webhookUrl}
                label={webhookUrl ? 'Configured' : 'Not configured'}
              />
            }
          >
            <div className="p-4 sm:p-6 space-y-4">
              <div>
                <label className="text-[10px] font-medium text-[#525252] uppercase tracking-wider block mb-1.5">Webhook URL</label>
                <input
                  type="url"
                  value={webhookUrl}
                  onChange={(e) => setWebhookUrl(e.target.value)}
                  placeholder="https://hooks.slack.com/services/..."
                  className="w-full bg-[#09090B] border border-white/[0.04] rounded-xl px-4 py-2.5 text-sm text-[#E5E5E5] placeholder:text-[#525252] focus:outline-none focus:border-[#22D3EE]/30 font-mono"
                />
              </div>

              <div>
                <label className="text-[10px] font-medium text-[#525252] uppercase tracking-wider block mb-1.5">Format</label>
                <div className="relative">
                  <select
                    value={webhookFormat}
                    onChange={(e) => setWebhookFormat(e.target.value)}
                    className="w-full sm:w-64 bg-[#09090B] border border-white/[0.04] rounded-xl px-4 py-2.5 text-sm text-[#E5E5E5] focus:outline-none focus:border-[#22D3EE]/30 appearance-none cursor-pointer"
                  >
                    {WEBHOOK_FORMATS.map((f) => (
                      <option key={f.value} value={f.value}>{f.label}</option>
                    ))}
                  </select>
                  <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#737373] pointer-events-none" />
                </div>
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={testWebhook}
                  disabled={testingWebhook || !webhookUrl}
                  className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white/[0.04] border border-white/[0.04] text-[13px] text-[#737373] hover:text-[#22D3EE] hover:border-[#22D3EE]/20 transition-all disabled:opacity-30"
                >
                  {testingWebhook ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Globe className="w-4 h-4" />}
                  Send Test
                </button>
                {webhookTestResult && (
                  <span className={cn(
                    'text-[12px]',
                    webhookTestResult.success ? 'text-[#22C55E]' : 'text-[#EF4444]'
                  )}>
                    {webhookTestResult.message}
                  </span>
                )}
              </div>
            </div>
          </SectionCard>

          <SectionCard title="Email Notifications">
            <div className="p-4 sm:p-6 space-y-4">
              <Toggle
                enabled={notifications.email_enabled}
                onChange={() => setNotifications({ ...notifications, email_enabled: !notifications.email_enabled })}
                label="Enable email notifications"
              />
              {notifications.email_enabled && (
                <div>
                  <label className="text-[10px] font-medium text-[#525252] uppercase tracking-wider block mb-1.5">Email Recipients (comma-separated)</label>
                  <input
                    type="text"
                    value={emailRecipients}
                    onChange={(e) => setEmailRecipients(e.target.value)}
                    placeholder="soc@example.com, admin@example.com"
                    className="w-full bg-[#09090B] border border-white/[0.04] rounded-xl px-4 py-2.5 text-sm text-[#E5E5E5] placeholder:text-[#525252] focus:outline-none focus:border-[#22D3EE]/30"
                  />
                </div>
              )}
            </div>
          </SectionCard>

          <SectionCard
            title="Notification Rules"
            description="Choose which events trigger notifications across all channels"
            headerRight={<SaveButton onClick={saveNotifications} />}
          >
            <div className="p-4 sm:p-6">
              {[
                { key: 'notify_on_critical' as const, label: 'Critical severity incidents', description: 'CVSS 9.0+ or active exploitation detected', icon: Shield },
                { key: 'notify_on_high' as const, label: 'High severity incidents', description: 'CVSS 7.0+ threats requiring attention', icon: BellRing },
                { key: 'notify_on_actions' as const, label: 'Autonomous actions executed', description: 'When AEGIS takes automated response actions', icon: Zap },
                { key: 'notify_on_scan_completed' as const, label: 'Scan completed', description: 'When a scheduled or manual scan finishes', icon: Radar01Icon },
              ].map((item, index) => (
                <div key={item.key} className={cn(index < 3 && 'border-b border-white/[0.02]')}>
                  <div className="flex items-center gap-3 py-3">
                    <div className="w-7 h-7 rounded-lg bg-white/[0.03] flex items-center justify-center shrink-0">
                      <item.icon className="w-3.5 h-3.5 text-[#737373]" size={14} />
                    </div>
                    <Toggle
                      enabled={!!notifications[item.key]}
                      onChange={() => setNotifications({ ...notifications, [item.key]: !notifications[item.key] })}
                      label={item.label}
                      description={item.description}
                    />
                  </div>
                </div>
              ))}
            </div>
          </SectionCard>

        </div>
      )}

      {/* Scanning Tab */}
      {tab === 'scanning' && (
        <div className="space-y-4">
          <SectionCard
            title="Scan Configuration"
            description="Configure automated scan intervals and behavior"
            headerRight={<SaveButton onClick={saveScanIntervals} />}
          >
            <div className="p-4 sm:p-6 space-y-6">
              <IntervalSlider
                label="Full Scan Interval"
                value={scanIntervals.full_scan_minutes}
                min={30}
                max={1440}
                step={30}
                onChange={(v) => setScanIntervals({ ...scanIntervals, full_scan_minutes: v })}
              />

              <IntervalSlider
                label="Quick Scan Interval"
                value={scanIntervals.quick_scan_minutes}
                min={10}
                max={120}
                step={5}
                onChange={(v) => setScanIntervals({ ...scanIntervals, quick_scan_minutes: v })}
              />

              <IntervalSlider
                label="Discovery Interval"
                value={scanIntervals.discovery_minutes}
                min={30}
                max={720}
                step={30}
                onChange={(v) => setScanIntervals({ ...scanIntervals, discovery_minutes: v })}
              />

              <div className="border-t border-white/[0.04] pt-4">
                <Toggle
                  enabled={scanIntervals.adaptive_scanning}
                  onChange={() => setScanIntervals({ ...scanIntervals, adaptive_scanning: !scanIntervals.adaptive_scanning })}
                  label="Adaptive Scanning"
                  description="Automatically increase scan frequency when threats are detected and decrease during quiet periods"
                />
              </div>

              {scanIntervals.adaptive_scanning && (
                <div className="bg-[#22D3EE]/5 border border-[#22D3EE]/10 rounded-xl p-3">
                  <p className="text-[11px] text-[#737373] leading-relaxed">
                    <span className="text-[#22D3EE] font-medium">Adaptive mode:</span> Scan intervals will automatically adjust based on threat activity. During active incidents, intervals may decrease to as low as 50% of configured values. During quiet periods, intervals may increase up to 200%.
                  </p>
                </div>
              )}
            </div>
          </SectionCard>
        </div>
      )}

      {/* API Keys Tab */}
      {tab === 'apikeys' && (
        <SectionCard
          title="API Key Management"
          description="Your API key is used to authenticate with the AEGIS platform"
        >
          <div className="p-4 sm:p-6 space-y-4">
            <div>
              <label className="text-[10px] font-medium text-[#525252] uppercase tracking-wider block mb-1.5">Current API Key</label>
              <div className="flex items-center gap-2">
                <div className="flex-1 relative">
                  <input
                    type={showApiKey ? 'text' : 'password'}
                    value={client.api_key}
                    readOnly
                    className="w-full bg-[#09090B] border border-white/[0.04] rounded-xl px-4 py-2.5 text-sm text-[#E5E5E5] font-mono pr-12"
                  />
                  <button
                    onClick={() => setShowApiKey(!showApiKey)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 p-1 text-[#737373] hover:text-[#E5E5E5] transition-colors"
                    aria-label={showApiKey ? 'Hide API key' : 'Show API key'}
                  >
                    {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                <button
                  onClick={copyApiKey}
                  className="flex items-center gap-1.5 px-3 py-2.5 bg-white/[0.04] hover:bg-white/[0.06] border border-white/[0.04] rounded-xl text-[#737373] hover:text-[#E5E5E5] transition-colors text-[13px]"
                >
                  {copied ? <Check className="w-4 h-4 text-[#22C55E]" /> : <Copy className="w-4 h-4" />}
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>

            <div className="pt-4 border-t border-white/[0.04]">
              <div className="bg-[#EF4444]/5 border border-[#EF4444]/20 rounded-xl p-4">
                <h4 className="text-[13px] font-medium text-[#EF4444] mb-1">Danger Zone</h4>
                <p className="text-[11px] text-[#737373] mb-3">Regenerating your API key will invalidate the current key and disconnect all active sessions.</p>
                <button className="text-[11px] font-medium text-[#EF4444] border border-white/[0.04] hover:bg-[#EF4444]/10 px-3 py-2 rounded-xl transition-colors">
                  Regenerate API Key
                </button>
              </div>
            </div>
          </div>
        </SectionCard>
      )}

      {tab === 'guide' && (
        <SectionCard title="AEGIS Feature Guide" description="Everything AEGIS can do for you. Click a module to navigate.">
          <div className="mb-4 p-4 rounded-xl border border-white/[0.04] bg-white/[0.02] flex items-center justify-between">
            <div>
              <p className="text-[13px] font-medium text-[#E5E5E5]">Interactive Feature Tour</p>
              <p className="text-[11px] text-[#737373] mt-0.5">Walk through all AEGIS modules step by step</p>
            </div>
            <button
              onClick={() => {
                localStorage.removeItem('aegis_guide_seen');
                window.location.href = '/dashboard';
              }}
              className="flex items-center gap-2 text-[12px] font-medium px-4 py-2 rounded-xl bg-[#22D3EE]/10 text-[#22D3EE] border border-[#22D3EE]/20 hover:bg-[#22D3EE]/20 transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Restart Feature Guide
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              { icon: Activity, name: 'Dashboard', desc: 'Real-time SOC view with live attack feed, threat map, events/sec, top attackers, log stream, node heartbeats \u2014 all WebSocket-powered.', href: '/dashboard', color: '#22D3EE', free: true },
              { icon: Globe, name: 'Surface (ASM)', desc: 'Attack surface management. AI-powered asset discovery via nmap, vulnerability scanning with Nuclei, SBOM analysis, risk scoring, and scheduled scans.', href: '/dashboard/surface', color: '#34D399', free: true },
              { icon: Zap, name: 'Response (SOAR)', desc: 'Autonomous incident response. 18\u03BCs fast path, 10 playbooks, AI triage with MITRE ATT&CK mapping. All actions auto-approved by default \u2014 override per guardrail.', href: '/dashboard/response', color: '#F87171', free: true },
              { icon: Bug, name: 'Phantom (Deception)', desc: 'SSH + HTTP honeypots with breadcrumb traps. Attacker steals fake credentials \u2192 tries on real API \u2192 CRITICAL alert + auto-block.', href: '/dashboard/phantom', color: '#F97316', free: true },
              { icon: Shield, name: 'Threats (TIP)', desc: '5 threat feeds, STIX 2.1 export, Intel Cloud hub for sharing IOCs across AEGIS instances. Campaign tracking detects coordinated multi-phase attacks.', href: '/dashboard/threats', color: '#FBBF24', free: true },
              { icon: Fingerprint, name: 'EDR/XDR Core', desc: 'Endpoint detection and response. ETW (Windows) + eBPF (Linux) telemetry, process tree reconstruction, 6 MITRE attack chain detection rules.', href: '/dashboard/edr', color: '#A78BFA', free: true },
              { icon: Flame, name: 'Ransomware Protection', desc: 'Canary files + entropy detection + process kill in <500ms. Auto-rollback via VSS (Windows) or Btrfs/LVM snapshots (Linux).', href: '/dashboard/response', color: '#EF4444', free: true },
              { icon: Radar, name: 'Antivirus Engine', desc: 'YARA + ClamAV signature scanning, hash reputation cache, encrypted quarantine. On-access + daily scheduled scans. Auto-updates from YARA-Forge.', href: '/dashboard/antivirus', color: '#06B6D4', free: true },
              { icon: Shield, name: 'Configurable Firewall', desc: 'YAML rule engine with rate limiting, CIDR matching, UA regex. 6 default templates. Hot reload in <1s. Test rules with synthetic events.', href: '/dashboard/firewall', color: '#10B981', free: true },
              { icon: Sparkles, name: 'Quantum Analytics', desc: 'Renyi entropy for C2 beacon detection, Grover calculator for post-quantum crypto assessment, adversarial ML poisoning detection.', href: '/dashboard/quantum', color: '#A78BFA', free: false },
              { icon: Bot, name: 'Honey-AI Deception', desc: 'Deploy 50+ fake services with AI-generated content. 4 industry themes (fintech, healthcare, ecommerce, devops). Breadcrumb UUID tracking.', href: '/dashboard/deception', color: '#F97316', free: false },
              { icon: Shield, name: 'Counter-Attack AI', desc: 'Analyze attackers with uncensored AI model. Recon, intel lookup, deception, abuse reporting, tarpit. Fully autonomous.', href: '/dashboard/response', color: '#EF4444', free: true },
            ].map((m) => (
              <button
                key={m.name}
                onClick={() => window.location.href = m.href}
                className="flex items-start gap-3 p-4 rounded-xl border border-white/[0.04] hover:border-white/[0.08] bg-white/[0.02] hover:bg-white/[0.03] transition-all text-left group"
              >
                <div
                  className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
                  style={{ background: `${m.color}10`, border: `1px solid ${m.color}20` }}
                >
                  <m.icon className="w-4 h-4" style={{ color: m.color }} />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[13px] font-medium text-[#E5E5E5] group-hover:text-[#22D3EE] transition-colors">{m.name}</span>
                    {!m.free && <span className="text-[9px] font-bold text-[#F97316] bg-[#F97316]/10 px-1.5 py-0.5 rounded">ENTERPRISE</span>}
                  </div>
                  <p className="text-[11px] text-[#737373] leading-relaxed">{m.desc}</p>
                </div>
                <ExternalLink className="w-3.5 h-3.5 text-[#525252] group-hover:text-[#737373] shrink-0 mt-1 transition-colors" />
              </button>
            ))}
          </div>
        </SectionCard>
      )}
    </div>
  );
}
