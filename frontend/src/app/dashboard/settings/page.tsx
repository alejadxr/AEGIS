'use client';

import { useState, useEffect, useRef } from 'react';
import { Settings01Icon, Radar01Icon, Bug01Icon } from 'hugeicons-react';
import {
  Key, Bell, Cpu, Save, RefreshCw, Eye, EyeOff, Copy, Check,
  Sparkles, ArrowUp, Shield, BellRing, Send, Globe,
  Zap, ChevronDown, TestTube, BookOpen, ExternalLink,
  Activity, Bug, Fingerprint, Flame, Radar, Bot,
  Share2, Wifi, Server, Database,
} from 'lucide-react';
import { LoadingState } from '@/components/shared/LoadingState';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';
import { MODEL_ROUTING_DEFAULTS } from '@/lib/constants';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';

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
        j % 2 === 1 ? <strong key={j} className="text-foreground font-semibold">{part}</strong> : part
      );
    }

    if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
      elements.push(
        <div key={i} className="flex gap-2 pl-1">
          <span className="text-[var(--brand)] mt-0.5 shrink-0">&#8226;</span>
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
        <span className="text-[13px] text-foreground block">{label}</span>
        {description && <span className="text-[11px] text-muted-foreground/60 block mt-0.5">{description}</span>}
      </div>
      <button
        onClick={onChange}
        aria-label={`Toggle ${label}`}
        className={cn(
          'relative w-11 h-6 rounded-full transition-colors duration-200 shrink-0',
          enabled ? 'bg-[var(--brand)]' : 'bg-white/[0.06]'
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
        connected ? 'bg-[var(--success)]' : 'bg-muted-foreground/40'
      )} />
      <span className={cn('text-[11px]', connected ? 'text-[var(--success)]' : 'text-muted-foreground')}>
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
    <Card className="rounded-xl overflow-hidden">
      <div className="px-4 sm:px-6 py-4 border-b border-border flex items-center justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-[13px] font-medium text-foreground uppercase tracking-wider">{title}</h3>
          {description && <p className="hidden sm:block text-[11px] text-muted-foreground mt-0.5">{description}</p>}
        </div>
        {headerRight}
      </div>
      {children}
    </Card>
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
        <label className="text-[13px] text-foreground">{label}</label>
        <span className="text-[13px] font-mono text-[var(--brand)]">{formatMinutes(value)}</span>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full h-1.5 bg-white/[0.04] rounded-full appearance-none cursor-pointer accent-[var(--brand)] [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-4 [&::-webkit-slider-thumb]:h-4 [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-[var(--brand)] [&::-webkit-slider-thumb]:cursor-pointer"
      />
      <div className="flex justify-between text-[10px] text-muted-foreground/60">
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
  const [saveError, setSaveError] = useState<string | null>(null);
  const [tab, setTab] = useState<string>('client');
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

  const [intelSharingEnabled, setIntelSharingEnabled] = useState(false);

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
          if (settings?.intel_sharing_enabled) {
            setIntelSharingEnabled(settings.intel_sharing_enabled as boolean);
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
    setSaveError(null);
    setSaveSuccess(msg);
    setTimeout(() => setSaveSuccess(null), 3000);
  };

  const flashSaveError = (msg: string) => {
    setSaveSuccess(null);
    setSaveError(msg);
    setTimeout(() => setSaveError(null), 5000);
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
    } catch (e) {
      flashSaveError(`Failed to save name: ${e instanceof Error ? e.message : 'Check connection'}`);
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
    } catch (e) {
      setNotifications(updated);
      flashSaveError(`Failed to save notifications: ${e instanceof Error ? e.message : 'Check connection'}`);
    } finally {
      setSaving(false);
    }
  };

  const saveModels = async () => {
    setSaving(true);
    try {
      await api.settings.updateModels(models.map((m) => ({ task_type: m.task_type, model: m.model })));
      flashSaveSuccess('Model routing saved');
    } catch (e) {
      flashSaveError(`Failed to save models: ${e instanceof Error ? e.message : 'Check connection'}`);
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
    } catch (e) {
      flashSaveError(`Failed to switch provider: ${e instanceof Error ? e.message : 'Check connection'}`);
    } finally {
      setSaving(false);
    }
  };

  const toggleIntelSharing = async () => {
    setSaving(true);
    const newValue = !intelSharingEnabled;
    try {
      await api.settings.updateIntelSharing({ enabled: newValue });
      setIntelSharingEnabled(newValue);
      flashSaveSuccess(newValue ? 'Threat sharing enabled' : 'Threat sharing disabled');
    } catch (e) {
      flashSaveError(`Failed: ${e instanceof Error ? e.message : 'Check connection'}`);
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
    } catch (e) {
      flashSaveError(`Failed to save intervals: ${e instanceof Error ? e.message : 'Check connection'}`);
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
    <Button
      variant="outline"
      onClick={onClick}
      disabled={saving}
      className="gap-2 text-[13px] shrink-0"
    >
      {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
      <span className="hidden sm:inline">{label || 'Save Changes'}</span>
      <span className="sm:hidden">Save</span>
    </Button>
  );

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-[22px] sm:text-[28px] font-bold text-foreground tracking-tight">Settings</h1>
        <p className="hidden sm:block text-sm text-muted-foreground mt-1">Platform configuration, AI model routing, notifications, and scan management</p>
      </div>

      {/* Save success toast */}
      {saveSuccess && (
        <div className="fixed top-4 right-4 z-50 flex items-center gap-2 bg-[var(--success)]/10 border border-[var(--success)]/20 text-[var(--success)] text-[13px] font-medium px-4 py-2.5 rounded-xl animate-fade-in">
          <Check className="w-4 h-4" />
          {saveSuccess}
        </div>
      )}
      {/* Save error toast */}
      {saveError && (
        <div className="fixed top-4 right-4 z-50 flex items-center gap-2 bg-destructive/10 border border-destructive/20 text-destructive text-[13px] font-medium px-4 py-2.5 rounded-xl animate-fade-in">
          <Shield className="w-4 h-4" />
          {saveError}
        </div>
      )}

      {/* AI Configuration Assistant */}
      <Card className="rounded-xl overflow-hidden">
        <div className="px-4 sm:px-6 py-4 border-b border-border">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[var(--brand)]/10 flex items-center justify-center">
              <Sparkles className="w-4 h-4 text-[var(--brand)]" />
            </div>
            <div>
              <h3 className="text-[13px] font-medium text-foreground">AI Configuration Assistant</h3>
              <p className="text-[11px] text-muted-foreground">Configure AEGIS using natural language</p>
            </div>
          </div>

          <div className="flex flex-wrap gap-2 mt-4">
            {QUICK_ACTIONS.map((action) => (
              <button
                key={action.label}
                onClick={() => handleQuickAction(action.prompt)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-muted/30 border border-border text-[12px] text-muted-foreground hover:text-[var(--brand)] hover:border-[var(--brand)]/20 transition-all duration-200"
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
                <Sparkles className="w-5 h-5 text-muted-foreground/60" />
              </div>
              <p className="text-[13px] text-muted-foreground/60">Ask AEGIS to configure your security platform</p>
              <p className="text-[11px] text-muted-foreground/60 mt-1">Try clicking a quick action above to get started</p>
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
                    ? 'bg-[var(--brand)]/10 text-[var(--brand)] rounded-xl rounded-br-md px-4 py-2'
                    : 'bg-white/[0.02] text-muted-foreground rounded-xl rounded-bl-md px-4 py-3'
                )}
              >
                {msg.role === 'assistant' ? (
                  <div className="space-y-1">{formatAIContent(msg.content)}</div>
                ) : (
                  msg.content
                )}
                <p className={cn(
                  'text-[10px] mt-1.5',
                  msg.role === 'user' ? 'text-[var(--brand)]/40' : 'text-muted-foreground/60'
                )}>
                  {msg.timestamp}
                </p>
              </div>
            </div>
          ))}

          {chatLoading && (
            <div className="flex justify-start">
              <div className="bg-white/[0.02] rounded-xl rounded-bl-md px-4 py-3">
                <div className="flex items-center gap-2 text-[13px] text-muted-foreground">
                  <span>AEGIS is thinking</span>
                  <span className="inline-flex gap-0.5">
                    <span className="w-1 h-1 rounded-full bg-[var(--brand)] animate-bounce" style={{ animationDelay: '0ms' }} />
                    <span className="w-1 h-1 rounded-full bg-[var(--brand)] animate-bounce" style={{ animationDelay: '150ms' }} />
                    <span className="w-1 h-1 rounded-full bg-[var(--brand)] animate-bounce" style={{ animationDelay: '300ms' }} />
                  </span>
                </div>
              </div>
            </div>
          )}

          <div ref={chatEndRef} />
        </div>

        <div className="px-4 sm:px-6 py-4 border-t border-border">
          <div className="flex items-center gap-3">
            <Input
              ref={inputRef}
              type="text"
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              onKeyDown={handleChatKeyDown}
              placeholder="Tell AEGIS what to configure..."
              className="flex-1"
            />
            <Button
              onClick={() => sendChatMessage(chatInput)}
              disabled={!chatInput.trim() || chatLoading}
              size="icon"
              className="bg-[var(--brand)] hover:bg-[var(--brand)] disabled:opacity-30 shrink-0"
            >
              <ArrowUp className="w-4 h-4 text-[#09090B]" />
            </Button>
          </div>
        </div>
      </Card>

      {/* Tab Bar -- shadcn Tabs */}
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList variant="line" className="w-full justify-start overflow-x-auto">
          {[
            { id: 'client', label: 'Client', icon: Settings01Icon },
            { id: 'models', label: 'AI Models', icon: Cpu },
            { id: 'notifications', label: 'Notifications', icon: Bell },
            { id: 'scanning', label: 'Scanning', icon: Radar01Icon },
            { id: 'apikeys', label: 'API Keys', icon: Key },
            { id: 'sharing', label: 'Threat Sharing', icon: Share2 },
            { id: 'guide', label: 'Feature Guide', icon: BookOpen },
          ].map((t) => (
            <TabsTrigger key={t.id} value={t.id} className="gap-2 whitespace-nowrap">
              <t.icon className="w-4 h-4" size={16} />
              {t.label}
            </TabsTrigger>
          ))}
        </TabsList>

      {/* Client Tab */}
      <TabsContent value="client">
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
                <label className="text-[10px] font-medium text-muted-foreground/60 uppercase tracking-wider block mb-1.5">Organization Name</label>
                <input
                  type="text"
                  value={clientName}
                  onChange={(e) => setClientName(e.target.value)}
                  className="w-full bg-background border border-border rounded-xl px-4 py-2.5 text-sm text-foreground focus:outline-none focus:border-[var(--brand)]/30 transition-colors"
                />
              </div>
              <div>
                <label className="text-[10px] font-medium text-muted-foreground/60 uppercase tracking-wider block mb-1.5">Slug</label>
                <input
                  type="text"
                  value={client.slug}
                  readOnly
                  className="w-full bg-background border border-border rounded-xl px-4 py-2.5 text-sm text-foreground font-mono"
                />
              </div>
            </div>
            <div>
              <label className="text-[10px] font-medium text-muted-foreground/60 uppercase tracking-wider block mb-1.5">Client ID</label>
              <input
                type="text"
                value={client.id}
                readOnly
                className="w-full bg-background border border-border rounded-xl px-4 py-2.5 text-sm text-muted-foreground font-mono"
              />
            </div>
          </div>
        </SectionCard>
      </TabsContent>

      {/* AI Models Tab */}
      <TabsContent value="models">
        <div className="space-y-4">
          <SectionCard
            title="AI Provider"
            description="Select the AI provider for all model routing"
            headerRight={
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[var(--success)]/10 border border-[var(--success)]/20 text-[11px] font-medium text-[var(--success)]">
                  <span className="w-1.5 h-1.5 rounded-full bg-[var(--success)] animate-pulse" />
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
                        ? 'bg-[var(--brand)]/10 border-[var(--brand)]/20 text-[var(--brand)]'
                        : 'bg-white/[0.02] border-border text-muted-foreground hover:text-foreground hover:border-white/[0.08]'
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
                    <p className="text-[13px] font-medium text-foreground capitalize">{model.task_type.replace(/_/g, ' ')}</p>
                    <p className="text-[11px] text-muted-foreground">{model.description}</p>
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
                      className="w-full sm:w-72 bg-background border border-border rounded-xl px-3 py-2 text-foreground text-[11px] font-mono focus:outline-none focus:border-[var(--brand)]/30"
                    />
                    <button
                      onClick={() => testModel(model.task_type, model.model)}
                      disabled={testingModel === model.task_type}
                      title="Test this model"
                      className="p-2 rounded-lg bg-white/[0.03] border border-border text-muted-foreground hover:text-[var(--brand)] hover:border-[var(--brand)]/20 transition-colors disabled:opacity-30 shrink-0"
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
                        ? 'bg-[var(--success)]/10 border border-[var(--success)]/20 text-[var(--success)]'
                        : 'bg-[var(--danger)]/10 border border-[var(--danger)]/20 text-[var(--danger)]'
                    )}>
                      {modelTestResult.success && <span className="text-muted-foreground">Latency: {modelTestResult.latency_ms}ms -- </span>}
                      {modelTestResult.response.slice(0, 120)}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </SectionCard>
        </div>
      </TabsContent>

      {/* Notifications Tab */}
      <TabsContent value="notifications">
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
                    <label className="text-[10px] font-medium text-muted-foreground/60 uppercase tracking-wider block mb-1.5">Bot Token</label>
                    <div className="relative">
                      <input
                        type={showBotToken ? 'text' : 'password'}
                        value={telegramBotToken}
                        onChange={(e) => setTelegramBotToken(e.target.value)}
                        placeholder="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
                        className="w-full bg-background border border-border rounded-xl px-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:border-[var(--brand)]/30 font-mono pr-12"
                      />
                      <button
                        onClick={() => setShowBotToken(!showBotToken)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 p-1 text-muted-foreground hover:text-foreground transition-colors"
                        aria-label={showBotToken ? 'Hide bot token' : 'Show bot token'}
                      >
                        {showBotToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  <div>
                    <label className="text-[10px] font-medium text-muted-foreground/60 uppercase tracking-wider block mb-1.5">Chat ID</label>
                    <input
                      type="text"
                      value={telegramChatId}
                      onChange={(e) => setTelegramChatId(e.target.value)}
                      placeholder="-1001234567890"
                      className="w-full bg-background border border-border rounded-xl px-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:border-[var(--brand)]/30 font-mono"
                    />
                  </div>

                  <div className="flex items-center gap-3">
                    <button
                      onClick={testTelegram}
                      disabled={testingTelegram || !telegramBotToken || !telegramChatId}
                      className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white/[0.04] border border-border text-[13px] text-muted-foreground hover:text-[var(--brand)] hover:border-[var(--brand)]/20 transition-all disabled:opacity-30"
                    >
                      {testingTelegram ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
                      Send Test Message
                    </button>
                    {telegramTestResult && (
                      <span className={cn(
                        'text-[12px]',
                        telegramTestResult.success ? 'text-[var(--success)]' : 'text-[var(--danger)]'
                      )}>
                        {telegramTestResult.message}
                      </span>
                    )}
                  </div>

                  <div className="bg-white/[0.02] border border-border rounded-xl p-3">
                    <p className="text-[11px] text-muted-foreground leading-relaxed">
                      <span className="text-foreground font-medium">Setup:</span> Create a bot via{' '}
                      <span className="text-[var(--brand)]">@BotFather</span> on Telegram, get the token, then send a message to the bot and use{' '}
                      <span className="text-[var(--brand)] font-mono text-[10px]">https://api.telegram.org/bot&lt;TOKEN&gt;/getUpdates</span>{' '}
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
                <label className="text-[10px] font-medium text-muted-foreground/60 uppercase tracking-wider block mb-1.5">Webhook URL</label>
                <input
                  type="url"
                  value={webhookUrl}
                  onChange={(e) => setWebhookUrl(e.target.value)}
                  placeholder="https://hooks.slack.com/services/..."
                  className="w-full bg-background border border-border rounded-xl px-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:border-[var(--brand)]/30 font-mono"
                />
              </div>

              <div>
                <label className="text-[10px] font-medium text-muted-foreground/60 uppercase tracking-wider block mb-1.5">Format</label>
                <div className="relative">
                  <select
                    value={webhookFormat}
                    onChange={(e) => setWebhookFormat(e.target.value)}
                    className="w-full sm:w-64 bg-background border border-border rounded-xl px-4 py-2.5 text-sm text-foreground focus:outline-none focus:border-[var(--brand)]/30 appearance-none cursor-pointer"
                  >
                    {WEBHOOK_FORMATS.map((f) => (
                      <option key={f.value} value={f.value}>{f.label}</option>
                    ))}
                  </select>
                  <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
                </div>
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={testWebhook}
                  disabled={testingWebhook || !webhookUrl}
                  className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white/[0.04] border border-border text-[13px] text-muted-foreground hover:text-[var(--brand)] hover:border-[var(--brand)]/20 transition-all disabled:opacity-30"
                >
                  {testingWebhook ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Globe className="w-4 h-4" />}
                  Send Test
                </button>
                {webhookTestResult && (
                  <span className={cn(
                    'text-[12px]',
                    webhookTestResult.success ? 'text-[var(--success)]' : 'text-[var(--danger)]'
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
                  <label className="text-[10px] font-medium text-muted-foreground/60 uppercase tracking-wider block mb-1.5">Email Recipients (comma-separated)</label>
                  <input
                    type="text"
                    value={emailRecipients}
                    onChange={(e) => setEmailRecipients(e.target.value)}
                    placeholder="soc@example.com, admin@example.com"
                    className="w-full bg-background border border-border rounded-xl px-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:border-[var(--brand)]/30"
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
                      <item.icon className="w-3.5 h-3.5 text-muted-foreground" size={14} />
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
      </TabsContent>

      {/* Scanning Tab */}
      <TabsContent value="scanning">
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

              <div className="border-t border-border pt-4">
                <Toggle
                  enabled={scanIntervals.adaptive_scanning}
                  onChange={() => setScanIntervals({ ...scanIntervals, adaptive_scanning: !scanIntervals.adaptive_scanning })}
                  label="Adaptive Scanning"
                  description="Automatically increase scan frequency when threats are detected and decrease during quiet periods"
                />
              </div>

              {scanIntervals.adaptive_scanning && (
                <div className="bg-[var(--brand)]/5 border border-[var(--brand)]/10 rounded-xl p-3">
                  <p className="text-[11px] text-muted-foreground leading-relaxed">
                    <span className="text-[var(--brand)] font-medium">Adaptive mode:</span> Scan intervals will automatically adjust based on threat activity. During active incidents, intervals may decrease to as low as 50% of configured values. During quiet periods, intervals may increase up to 200%.
                  </p>
                </div>
              )}
            </div>
          </SectionCard>
        </div>
      </TabsContent>

      {/* API Keys Tab */}
      <TabsContent value="apikeys">
        <SectionCard
          title="API Key Management"
          description="Your API key is used to authenticate with the AEGIS platform"
        >
          <div className="p-4 sm:p-6 space-y-4">
            <div>
              <label className="text-[10px] font-medium text-muted-foreground/60 uppercase tracking-wider block mb-1.5">Current API Key</label>
              <div className="flex items-center gap-2">
                <div className="flex-1 relative">
                  <input
                    type={showApiKey ? 'text' : 'password'}
                    value={client.api_key}
                    readOnly
                    className="w-full bg-background border border-border rounded-xl px-4 py-2.5 text-sm text-foreground font-mono pr-12"
                  />
                  <button
                    onClick={() => setShowApiKey(!showApiKey)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 p-1 text-muted-foreground hover:text-foreground transition-colors"
                    aria-label={showApiKey ? 'Hide API key' : 'Show API key'}
                  >
                    {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                <button
                  onClick={copyApiKey}
                  className="flex items-center gap-1.5 px-3 py-2.5 bg-white/[0.04] hover:bg-white/[0.06] border border-border rounded-xl text-muted-foreground hover:text-foreground transition-colors text-[13px]"
                >
                  {copied ? <Check className="w-4 h-4 text-[var(--success)]" /> : <Copy className="w-4 h-4" />}
                  {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>

            <div className="pt-4 border-t border-border">
              <div className="bg-[var(--danger)]/5 border border-[var(--danger)]/20 rounded-xl p-4">
                <h4 className="text-[13px] font-medium text-[var(--danger)] mb-1">Danger Zone</h4>
                <p className="text-[11px] text-muted-foreground mb-3">Regenerating your API key will invalidate the current key and disconnect all active sessions.</p>
                <button className="text-[11px] font-medium text-[var(--danger)] border border-border hover:bg-[var(--danger)]/10 px-3 py-2 rounded-xl transition-colors">
                  Regenerate API Key
                </button>
              </div>
            </div>
          </div>
        </SectionCard>
      </TabsContent>

      {/* Threat Sharing Tab */}
      <TabsContent value="sharing">
        <div className="space-y-4">
          <SectionCard
            title="Threat Intelligence Sharing"
            description="Join the AEGIS threat sharing network"
            headerRight={
              <div className="flex items-center gap-3">
                <span className={cn(
                  'text-[11px] font-medium',
                  intelSharingEnabled ? 'text-[var(--success)]' : 'text-muted-foreground'
                )}>
                  {intelSharingEnabled ? 'Active' : 'Disabled'}
                </span>
                <button
                  onClick={toggleIntelSharing}
                  disabled={saving}
                  aria-label="Toggle threat intelligence sharing"
                  className={cn(
                    'relative w-11 h-6 rounded-full transition-colors duration-200 shrink-0',
                    intelSharingEnabled ? 'bg-[var(--brand)]' : 'bg-white/[0.06]'
                  )}
                >
                  <span
                    className={cn(
                      'absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform duration-200',
                      intelSharingEnabled && 'translate-x-5'
                    )}
                  />
                </button>
              </div>
            }
          >
            <div className="p-4 sm:p-6 space-y-4">
              <div className="grid grid-cols-3 gap-3">
                {[
                  { label: 'IOCs Shared', value: 0, icon: Share2 },
                  { label: 'IOCs Received', value: 0, icon: Database },
                  { label: 'Auto-Blocked', value: 0, icon: Shield },
                ].map((stat) => (
                  <div key={stat.label} className="flex flex-col items-center gap-2 p-4 rounded-xl bg-white/[0.02] border border-border">
                    <div className="w-8 h-8 rounded-lg bg-[var(--brand)]/10 flex items-center justify-center">
                      <stat.icon className="w-4 h-4 text-[var(--brand)]" />
                    </div>
                    <span className="text-xl font-semibold text-foreground">{stat.value}</span>
                    <span className="text-[11px] text-muted-foreground">{stat.label}</span>
                  </div>
                ))}
              </div>
              <p className="text-[11px] text-muted-foreground/60 leading-relaxed">
                When enabled, AEGIS will share validated IOCs with the threat sharing network and automatically
                receive indicators from other nodes. Incoming IOCs are validated before being applied.
                High-confidence threats are auto-blocked based on your guardrail settings.
              </p>
            </div>
          </SectionCard>

          <SectionCard
            title="Threat Sharing Hub"
            description="Share and receive threat intelligence across AEGIS instances in real-time"
            headerRight={
              <StatusDot connected={true} label="Hub Online" />
            }
          >
            <div className="p-4 sm:p-6 space-y-5">
              {/* Hub URL */}
              <div>
                <label className="text-[10px] font-medium text-muted-foreground/60 uppercase tracking-wider block mb-1.5">Hub API URL</label>
                <div className="flex items-center gap-2">
                  <div className="flex-1 relative">
                    <input
                      type="text"
                      value="https://api-aegis.somoswilab.com"
                      readOnly
                      className="w-full bg-background border border-border rounded-xl px-4 py-2.5 text-sm text-foreground font-mono"
                    />
                  </div>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText('https://api-aegis.somoswilab.com');
                      flashSaveSuccess('Hub URL copied');
                    }}
                    className="flex items-center gap-1.5 px-3 py-2.5 bg-white/[0.04] hover:bg-white/[0.06] border border-border rounded-xl text-muted-foreground hover:text-foreground transition-colors text-[13px]"
                  >
                    <Copy className="w-4 h-4" />
                    Copy
                  </button>
                </div>
              </div>

              {/* WebSocket URL */}
              <div>
                <label className="text-[10px] font-medium text-muted-foreground/60 uppercase tracking-wider block mb-1.5">WebSocket URL (Real-time)</label>
                <div className="flex items-center gap-2">
                  <div className="flex-1 relative">
                    <input
                      type="text"
                      value="wss://api-aegis.somoswilab.com/ws"
                      readOnly
                      className="w-full bg-background border border-border rounded-xl px-4 py-2.5 text-sm text-foreground font-mono"
                    />
                  </div>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText('wss://api-aegis.somoswilab.com/ws');
                      flashSaveSuccess('WebSocket URL copied');
                    }}
                    className="flex items-center gap-1.5 px-3 py-2.5 bg-white/[0.04] hover:bg-white/[0.06] border border-border rounded-xl text-muted-foreground hover:text-foreground transition-colors text-[13px]"
                  >
                    <Copy className="w-4 h-4" />
                    Copy
                  </button>
                </div>
              </div>

              {/* Endpoints grid */}
              <div>
                <label className="text-[10px] font-medium text-muted-foreground/60 uppercase tracking-wider block mb-3">Available Endpoints</label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {[
                    { method: 'GET', path: '/api/v1/threats/feed', desc: 'Download shared IOCs', icon: Database },
                    { method: 'POST', path: '/api/v1/threats/intel/share', desc: 'Submit new IOCs', icon: Share2 },
                    { method: 'GET', path: '/api/v1/threats/intel/search?q=', desc: 'Search threat intel', icon: Radar },
                    { method: 'POST', path: '/api/v1/threats/nodes/register', desc: 'Register a node', icon: Server },
                    { method: 'GET', path: '/api/v1/threats/nodes', desc: 'List connected nodes', icon: Wifi },
                    { method: 'GET', path: '/api/v1/threats/hub/info', desc: 'Hub capabilities', icon: Globe },
                  ].map((ep) => (
                    <div key={ep.path} className="flex items-start gap-3 p-3 rounded-xl bg-white/[0.02] border border-border">
                      <div className="w-7 h-7 rounded-lg bg-[var(--brand)]/10 flex items-center justify-center shrink-0 mt-0.5">
                        <ep.icon className="w-3.5 h-3.5 text-[var(--brand)]" />
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-1.5">
                          <span className={cn(
                            'text-[9px] font-bold px-1.5 py-0.5 rounded',
                            ep.method === 'GET' ? 'bg-[var(--success)]/10 text-[var(--success)]' : 'bg-[var(--brand-accent)]/10 text-[var(--brand-accent)]'
                          )}>
                            {ep.method}
                          </span>
                          <span className="text-[11px] font-mono text-muted-foreground truncate">{ep.path}</span>
                        </div>
                        <p className="text-[11px] text-muted-foreground/60 mt-0.5">{ep.desc}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </SectionCard>

          {/* WebSocket Topics */}
          <SectionCard
            title="Real-time Topics"
            description="Subscribe to these WebSocket topics for live threat intelligence"
          >
            <div className="p-4 sm:p-6">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                {[
                  { topic: 'threats.new', desc: 'New IOC shared by any node' },
                  { topic: 'threats.ioc', desc: 'IOC indicator updates' },
                  { topic: 'threats.blocked_ip', desc: 'IP blocked across the network' },
                  { topic: 'threats.pattern_update', desc: 'Attack pattern intelligence' },
                  { topic: 'nodes.status', desc: 'Node online/offline changes' },
                  { topic: 'incidents.new', desc: 'New incidents from any node' },
                ].map((t) => (
                  <div key={t.topic} className="flex items-center gap-2 px-3 py-2 rounded-xl bg-white/[0.02] border border-border">
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--brand)] shrink-0" />
                    <div className="min-w-0">
                      <span className="text-[11px] font-mono text-[var(--brand)] block">{t.topic}</span>
                      <span className="text-[10px] text-muted-foreground/60">{t.desc}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </SectionCard>

          {/* Connection Guide */}
          <SectionCard title="Connect a Remote Node">
            <div className="p-4 sm:p-6 space-y-4">
              <div className="bg-white/[0.02] border border-border rounded-xl p-4">
                <p className="text-[11px] text-muted-foreground leading-relaxed">
                  <span className="text-foreground font-medium">To connect a remote AEGIS instance:</span> Set the
                  <span className="text-[var(--brand)] font-mono text-[10px] mx-1">AEGIS_HUB_URL</span>
                  environment variable in the remote node{"'"}s <span className="font-mono text-[10px]">.env</span> file to
                  <span className="text-[var(--brand)] font-mono text-[10px] ml-1">https://api-aegis.somoswilab.com</span>.
                  The node will automatically register and begin sharing threat intelligence.
                </p>
              </div>

              <div>
                <label className="text-[10px] font-medium text-muted-foreground/60 uppercase tracking-wider block mb-1.5">Example .env configuration</label>
                <div className="bg-[#09090B] border border-border rounded-xl p-4 font-mono text-[11px] text-muted-foreground leading-relaxed">
                  <div><span className="text-muted-foreground/40"># Connect to the AEGIS threat sharing hub</span></div>
                  <div><span className="text-[var(--brand)]">AEGIS_HUB_URL</span>=https://api-aegis.somoswilab.com</div>
                  <div className="mt-2"><span className="text-muted-foreground/40"># MongoDB Atlas for shared intel storage</span></div>
                  <div><span className="text-[var(--brand)]">AEGIS_MONGODB_URI</span>=mongodb+srv://...</div>
                </div>
              </div>

              <div>
                <label className="text-[10px] font-medium text-muted-foreground/60 uppercase tracking-wider block mb-1.5">Register via cURL</label>
                <div className="bg-[#09090B] border border-border rounded-xl p-4 font-mono text-[11px] text-muted-foreground leading-relaxed overflow-x-auto">
                  <div>curl -X POST https://api-aegis.somoswilab.com/api/v1/threats/nodes/register \</div>
                  <div className="pl-4">-H &quot;Content-Type: application/json&quot; \</div>
                  <div className="pl-4">-d {"'{\"node_id\": \"my-node-01\", \"node_name\": \"Office AEGIS\"}'"};</div>
                </div>
              </div>
            </div>
          </SectionCard>
        </div>
      </TabsContent>

      <TabsContent value="guide">
        <SectionCard title="AEGIS Feature Guide" description="Everything AEGIS can do for you. Click a module to navigate.">
          <div className="mb-4 p-4 rounded-xl border border-border bg-muted/30 flex items-center justify-between">
            <div>
              <p className="text-[13px] font-medium text-foreground">Interactive Feature Tour</p>
              <p className="text-[11px] text-muted-foreground mt-0.5">Walk through all AEGIS modules step by step</p>
            </div>
            <button
              onClick={() => {
                localStorage.removeItem('aegis_guide_seen');
                window.location.href = '/dashboard';
              }}
              className="flex items-center gap-2 text-[12px] font-medium px-4 py-2 rounded-xl bg-[var(--brand)]/10 text-[var(--brand)] border border-[var(--brand)]/20 hover:bg-[var(--brand)]/20 transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Restart Feature Guide
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              { icon: Activity, name: 'Dashboard', desc: 'Real-time SOC view with live attack feed, threat map, events/sec, top attackers, log stream, node heartbeats \u2014 all WebSocket-powered.', href: '/dashboard', color: 'var(--brand)', free: true },
              { icon: Globe, name: 'Surface (ASM)', desc: 'Attack surface management. AI-powered asset discovery via nmap, vulnerability scanning with Nuclei, SBOM analysis, risk scoring, and scheduled scans.', href: '/dashboard/surface', color: '#34D399', free: true },
              { icon: Zap, name: 'Response (SOAR)', desc: 'Autonomous incident response. 18\u03BCs fast path, 10 playbooks, AI triage with MITRE ATT&CK mapping. All actions auto-approved by default \u2014 override per guardrail.', href: '/dashboard/response', color: '#F87171', free: true },
              { icon: Bug, name: 'Phantom (Deception)', desc: 'SSH + HTTP honeypots with breadcrumb traps. Attacker steals fake credentials \u2192 tries on real API \u2192 CRITICAL alert + auto-block.', href: '/dashboard/phantom', color: 'var(--brand-accent)', free: true },
              { icon: Shield, name: 'Threats (TIP)', desc: '5 threat feeds, STIX 2.1 export, Intel Cloud hub for sharing IOCs across AEGIS instances. Campaign tracking detects coordinated multi-phase attacks.', href: '/dashboard/threats', color: '#FBBF24', free: true },
              { icon: Fingerprint, name: 'EDR/XDR Core', desc: 'Endpoint detection and response. ETW (Windows) + eBPF (Linux) telemetry, process tree reconstruction, 6 MITRE attack chain detection rules.', href: '/dashboard/edr', color: '#A78BFA', free: true },
              { icon: Flame, name: 'Ransomware Protection', desc: 'Canary files + entropy detection + process kill in <500ms. Auto-rollback via VSS (Windows) or Btrfs/LVM snapshots (Linux).', href: '/dashboard/response', color: 'var(--danger)', free: true },
              { icon: Radar, name: 'Antivirus Engine', desc: 'YARA + ClamAV signature scanning, hash reputation cache, encrypted quarantine. On-access + daily scheduled scans. Auto-updates from YARA-Forge.', href: '/dashboard/antivirus', color: 'var(--brand)', free: true },
              { icon: Shield, name: 'Configurable Firewall', desc: 'YAML rule engine with rate limiting, CIDR matching, UA regex. 6 default templates. Hot reload in <1s. Test rules with synthetic events.', href: '/dashboard/firewall', color: '#10B981', free: true },
              { icon: Sparkles, name: 'Quantum Analytics', desc: 'Renyi entropy for C2 beacon detection, Grover calculator for post-quantum crypto assessment, adversarial ML poisoning detection.', href: '/dashboard/quantum', color: '#A78BFA', free: false },
              { icon: Bot, name: 'Honey-AI Deception', desc: 'Deploy 50+ fake services with AI-generated content. 4 industry themes (fintech, healthcare, ecommerce, devops). Breadcrumb UUID tracking.', href: '/dashboard/deception', color: 'var(--brand-accent)', free: false },
              { icon: Shield, name: 'Counter-Attack AI', desc: 'Analyze attackers with uncensored AI model. Recon, intel lookup, deception, abuse reporting, tarpit. Fully autonomous.', href: '/dashboard/response', color: 'var(--danger)', free: true },
            ].map((m) => (
              <button
                key={m.name}
                onClick={() => window.location.href = m.href}
                className="flex items-start gap-3 p-4 rounded-xl border border-border hover:border-white/[0.08] bg-white/[0.02] hover:bg-white/[0.03] transition-all text-left group"
              >
                <div
                  className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
                  style={{ background: `${m.color}10`, border: `1px solid ${m.color}20` }}
                >
                  <m.icon className="w-4 h-4" style={{ color: m.color }} />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[13px] font-medium text-foreground group-hover:text-[var(--brand)] transition-colors">{m.name}</span>
                    {!m.free && <span className="text-[9px] font-bold text-[var(--brand-accent)] bg-[var(--brand-accent)]/10 px-1.5 py-0.5 rounded">ENTERPRISE</span>}
                  </div>
                  <p className="text-[11px] text-muted-foreground leading-relaxed">{m.desc}</p>
                </div>
                <ExternalLink className="w-3.5 h-3.5 text-muted-foreground/60 group-hover:text-muted-foreground shrink-0 mt-1 transition-colors" />
              </button>
            ))}
          </div>
        </SectionCard>
      </TabsContent>
      </Tabs>
    </div>
  );
}
