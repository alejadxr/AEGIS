'use client';

import { useState, useEffect, useCallback } from 'react';
import { Activity01Icon } from 'hugeicons-react';
import { Plus, Trash2, Monitor, Download, Loader2, CheckCircle, AlertCircle, Server, Laptop } from 'lucide-react';
import { cn } from '@/lib/utils';
import { api, isRedirectingToLogin } from '@/lib/api';
import { Modal } from '@/components/shared/Modal';

// ─── Types ────────────────────────────────────────────────────────────────────

interface SystemInfo {
  name: string;
  ip: string;
  role: string;
  status: 'online' | 'offline' | 'degraded';
  cpu: number;
  mem: number;
  disk: number;
  uptime: string;
  services: string[];
  pm2_processes: PM2Process[];
}

interface PM2Process {
  name: string;
  status: 'online' | 'stopped' | 'errored';
  cpu: number;
  mem: string;
  uptime: string;
  restarts: number;
}

interface NodeInfo {
  id: string;
  hostname: string;
  os_info: string | null;
  ip_address: string | null;
  agent_version: string;
  status: string;
  last_heartbeat: string | null;
  tags: string[];
  asset_count: number;
  created_at: string | null;
  cpu: number;
  mem: number;
  disk: number;
  processes: number;
  node_type: string | null;
}

type NodeType = 'server' | 'workspace';

// ─── LED Bar Component ────────────────────────────────────────────────────────

const LED_COLORS = {
  cyan: { active: '#22D3EE', glow: 'rgba(34,211,238,0.6)', dim: 'rgba(34,211,238,0.1)' },
  pink: { active: '#D946EF', glow: 'rgba(217,70,239,0.6)', dim: 'rgba(217,70,239,0.1)' },
  green: { active: '#22C55E', glow: 'rgba(34,197,94,0.6)', dim: 'rgba(34,197,94,0.1)' },
  orange: { active: '#F97316', glow: 'rgba(249,115,22,0.6)', dim: 'rgba(249,115,22,0.1)' },
} as const;

type LEDColor = keyof typeof LED_COLORS;

function LEDBar({ value, color }: { value: number; color: LEDColor }) {
  const segments = 10;
  const activeSegments = Math.round((value / 100) * segments);
  const palette = LED_COLORS[color];

  return (
    <div className="flex gap-[2px]" role="meter" aria-valuenow={value} aria-valuemin={0} aria-valuemax={100}>
      {Array.from({ length: segments }, (_, i) => {
        const isActive = i < activeSegments;
        const isLast = i === activeSegments - 1 && isActive;
        const intensity = isActive ? Math.min(1, 0.5 + (i / Math.max(activeSegments, 1)) * 0.5) : 0;
        return (
          <div
            key={i}
            className={cn("h-4 flex-1 rounded-[2px] transition-all duration-300", isLast && "animate-pulse")}
            style={{
              backgroundColor: isActive ? palette.active : palette.dim,
              opacity: isActive ? intensity : 0.12,
              boxShadow: isLast
                ? `0 0 12px ${palette.glow}, 0 0 4px ${palette.active}`
                : isActive
                ? `0 0 4px ${palette.glow}`
                : 'none',
            }}
          />
        );
      })}
    </div>
  );
}

// ─── Server Card ──────────────────────────────────────────────────────────────

function ServerCard({ system }: { system: SystemInfo }) {
  const { name, ip, role, status, cpu, mem, disk, uptime, services } = system;

  return (
    <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-4 hover:border-white/[0.1] transition-colors group">
        {/* Header */}
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2.5">
            <span
              className={cn(
                'w-2 h-2 rounded-full shrink-0',
                status === 'online'
                  ? 'bg-[#22C55E] shadow-[0_0_6px_#22C55E]'
                  : status === 'degraded'
                  ? 'bg-[#F59E0B] shadow-[0_0_6px_#F59E0B]'
                  : 'bg-[#EF4444] shadow-[0_0_6px_#EF4444]'
              )}
            />
            <h3 className="font-mono text-[13px] font-semibold text-white tracking-tight">
              {name}
            </h3>
            <span className="text-[10px] font-mono text-zinc-600">
              {ip}
            </span>
          </div>
          <span className="text-[10px] text-zinc-600">{role}</span>
        </div>

        {/* LED Meter Bars */}
        <div className="grid grid-cols-2 gap-3">
          {/* CPU */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[10px] text-zinc-500 font-medium">CPU</span>
              <span className="text-[13px] font-bold font-mono text-white tabular-nums">
                {cpu}%
              </span>
            </div>
            <LEDBar value={cpu} color="cyan" />
          </div>
          {/* MEM */}
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[10px] text-zinc-500 font-medium">MEM</span>
              <span className="text-[13px] font-bold font-mono text-white tabular-nums">
                {mem}%
              </span>
            </div>
            <LEDBar value={mem} color="pink" />
          </div>
        </div>

        {/* Footer */}
        <div className="mt-3 pt-2 border-t border-white/[0.04] space-y-2">
          <div className="flex items-center justify-between text-[10px]">
            <div className="flex items-center gap-3">
              <span className="text-zinc-600">Disk: <span className="text-zinc-400 font-mono">{disk}%</span></span>
              <span className="text-zinc-600">Up: <span className="text-zinc-400 font-mono">{uptime}</span></span>
            </div>
            <span className="text-zinc-600">{services.length} services</span>
          </div>
          <div className="flex flex-wrap gap-1">
            {services.map((svc) => (
              <span key={svc} className="text-[9px] font-mono text-zinc-500 bg-white/[0.03] px-1.5 py-0.5 rounded">
                {svc}
              </span>
            ))}
          </div>
        </div>
    </div>
  );
}

// ─── PM2 Process Status Badge ─────────────────────────────────────────────────

function StatusBadge({ status }: { status: PM2Process['status'] }) {
  const config = {
    online: { bg: 'bg-[#22C55E]/10', text: 'text-[#22C55E]', dot: 'bg-[#22C55E]' },
    stopped: { bg: 'bg-[#71717A]/10', text: 'text-[#71717A]', dot: 'bg-[#71717A]' },
    errored: { bg: 'bg-[#EF4444]/10', text: 'text-[#EF4444]', dot: 'bg-[#EF4444]' },
  };
  const c = config[status] || config.stopped;

  return (
    <span className={cn('inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[10px] font-semibold uppercase tracking-wider', c.bg, c.text)}>
      <span className={cn('w-1.5 h-1.5 rounded-full', c.dot)} />
      {status}
    </span>
  );
}

// ─── Network Node ─────────────────────────────────────────────────────────────

function NetworkNode({ system }: { system: SystemInfo }) {
  return (
    <div className="flex items-center gap-3 px-4 py-3 bg-white/[0.03] border border-white/[0.06] rounded-xl hover:bg-white/[0.05] transition-colors">
      <span
        className={cn(
          'w-2.5 h-2.5 rounded-full shrink-0',
          system.status === 'online'
            ? 'bg-[#22C55E] shadow-[0_0_6px_#22C55E]'
            : 'bg-[#EF4444] shadow-[0_0_6px_#EF4444]'
        )}
      />
      <div className="flex-1 min-w-0">
        <p className="text-[13px] font-medium text-white truncate">{system.name}</p>
        <p className="text-[11px] font-mono text-zinc-500">{system.ip}</p>
      </div>
      <span className="text-[11px] text-zinc-600 font-mono shrink-0">
        {system.status === 'online' ? 'Connected' : 'Offline'}
      </span>
    </div>
  );
}

// ─── Node Card ────────────────────────────────────────────────────────────────

function formatHeartbeat(iso: string | null): string {
  if (!iso) return 'Never';
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function getOsLabel(os: string | null): string {
  if (!os) return 'Unknown';
  const lower = os.toLowerCase();
  if (lower.includes('windows')) return 'Windows';
  if (lower.includes('mac') || lower.includes('darwin')) return 'macOS';
  if (lower.includes('linux')) return 'Linux';
  return os.split(' ')[0];
}

function NodeTypeBadge({ type }: { type: string | null }) {
  const isServer = type === 'server';
  return (
    <span className={cn(
      'inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase tracking-wider',
      isServer
        ? 'bg-[#22D3EE]/10 text-[#22D3EE]'
        : 'bg-[#A78BFA]/10 text-[#A78BFA]'
    )}>
      {isServer ? <Server className="w-2.5 h-2.5" /> : <Laptop className="w-2.5 h-2.5" />}
      {isServer ? 'Server' : 'Workspace'}
    </span>
  );
}

function NodeCard({ node, onRemove, onSelect }: { node: NodeInfo; onRemove: (id: string) => void; onSelect: (node: NodeInfo) => void }) {
  const isOnline = node.status === 'online';
  const isStale = node.status === 'stale';
  const hasMetrics = node.cpu > 0 || node.mem > 0;

  return (
    <div
      className="bg-[#18181B] border border-white/[0.06] rounded-xl p-4 hover:border-white/[0.1] transition-colors cursor-pointer group relative"
      onClick={() => onSelect(node)}
      role="button"
      tabIndex={0}
      aria-label={`Node ${node.hostname}`}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') onSelect(node); }}
    >
      <button
        onClick={(e) => { e.stopPropagation(); onRemove(node.id); }}
        className="absolute top-2 right-2 p-1.5 rounded-lg text-zinc-600 hover:text-red-400 hover:bg-red-400/10 transition-colors opacity-0 group-hover:opacity-100"
        aria-label={`Remove node ${node.hostname}`}
      >
        <Trash2 className="w-3.5 h-3.5" />
      </button>

      <div className="flex items-center gap-2.5 mb-2">
        <span
          className={cn(
            'w-2 h-2 rounded-full shrink-0',
            isOnline
              ? 'bg-[#22C55E] shadow-[0_0_6px_#22C55E]'
              : isStale
              ? 'bg-[#F59E0B] shadow-[0_0_6px_#F59E0B]'
              : 'bg-[#EF4444] shadow-[0_0_6px_#EF4444]'
          )}
        />
        <h4 className="text-[13px] font-semibold text-white truncate flex-1">{node.hostname}</h4>
        <NodeTypeBadge type={node.node_type} />
      </div>

      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-zinc-500">OS</span>
          <span className="text-zinc-400 font-mono">{getOsLabel(node.os_info)}</span>
        </div>
        {node.ip_address && (
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-zinc-500">IP</span>
            <span className="text-zinc-400 font-mono">{node.ip_address}</span>
          </div>
        )}
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-zinc-500">Status</span>
          <span className={cn(
            'font-medium capitalize',
            isOnline ? 'text-[#22C55E]' : isStale ? 'text-[#F59E0B]' : 'text-[#EF4444]'
          )}>
            {node.status}
          </span>
        </div>
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-zinc-500">Heartbeat</span>
          <span className="text-zinc-400 font-mono">{formatHeartbeat(node.last_heartbeat)}</span>
        </div>
      </div>

      {/* LED Meter Bars for CPU & MEM */}
      {hasMetrics && (
        <div className="mt-3 pt-2 border-t border-white/[0.04] grid grid-cols-2 gap-3">
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] text-zinc-500 font-medium">CPU</span>
              <span className="text-[12px] font-bold font-mono text-white tabular-nums">
                {Math.round(node.cpu)}%
              </span>
            </div>
            <LEDBar value={node.cpu} color="cyan" />
          </div>
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] text-zinc-500 font-medium">MEM</span>
              <span className="text-[12px] font-bold font-mono text-white tabular-nums">
                {Math.round(node.mem)}%
              </span>
            </div>
            <LEDBar value={node.mem} color="pink" />
          </div>
        </div>
      )}

      <div className={cn('pt-2 flex items-center justify-between', hasMetrics ? 'mt-2' : 'mt-3 border-t border-white/[0.04]')}>
        <span className="text-[9px] font-mono text-zinc-600">v{node.agent_version}</span>
        {node.disk > 0 && (
          <span className="text-[9px] font-mono text-zinc-600">
            Disk: <span className="text-zinc-500">{Math.round(node.disk)}%</span>
          </span>
        )}
      </div>
    </div>
  );
}

// ─── Add Node Card ────────────────────────────────────────────────────────────

function AddNodeCard({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="flex flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed border-white/[0.08] hover:border-[#22D3EE]/40 hover:bg-[#22D3EE]/[0.03] p-4 transition-colors min-h-[160px] cursor-pointer group"
      aria-label="Add new node"
    >
      <div className="w-10 h-10 rounded-xl bg-white/[0.04] group-hover:bg-[#22D3EE]/10 flex items-center justify-center transition-colors">
        <Plus className="w-5 h-5 text-zinc-500 group-hover:text-[#22D3EE] transition-colors" />
      </div>
      <span className="text-[12px] text-zinc-500 group-hover:text-zinc-400 font-medium transition-colors">
        Add Node
      </span>
    </button>
  );
}

// ─── Enrollment Modal ─────────────────────────────────────────────────────────

type EnrollStep = 'input' | 'loading' | 'success' | 'error';

function EnrollmentModal({ open, onClose, onEnrolled }: { open: boolean; onClose: () => void; onEnrolled: () => void }) {
  const [code, setCode] = useState('');
  const [nodeType, setNodeType] = useState<NodeType>('workspace');
  const [step, setStep] = useState<EnrollStep>('input');
  const [resultMessage, setResultMessage] = useState('');
  const [errorMessage, setErrorMessage] = useState('');

  const resetState = useCallback(() => {
    setCode('');
    setNodeType('workspace');
    setStep('input');
    setResultMessage('');
    setErrorMessage('');
  }, []);

  const handleClose = useCallback(() => {
    resetState();
    onClose();
  }, [resetState, onClose]);

  async function handleEnroll() {
    if (!code.trim()) return;
    setStep('loading');
    try {
      const result = await api.nodes.enroll(code.trim(), nodeType);
      setResultMessage(result.message);
      setStep('success');
      onEnrolled();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      try {
        const parsed = JSON.parse(msg);
        setErrorMessage(parsed.detail || msg);
      } catch {
        setErrorMessage(msg.includes('Invalid') || msg.includes('expired')
          ? msg
          : 'Invalid or expired code. Please check and try again.');
      }
      setStep('error');
    }
  }

  function formatCodeInput(value: string): string {
    const clean = value.toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (clean.length <= 2) return clean;
    const prefix = clean.slice(0, 2);
    const rest = clean.slice(2);
    if (rest.length <= 4) return `${prefix}-${rest}`;
    return `${prefix}-${rest.slice(0, 4)}-${rest.slice(4, 8)}`;
  }

  return (
    <Modal open={open} onClose={handleClose} title="Add a New Node" size="md">
      {step === 'input' && (
        <div className="space-y-6">
          <div className="space-y-4">
            <p className="text-[13px] text-zinc-400 leading-relaxed">
              Follow these steps to connect a new machine to your AEGIS network:
            </p>

            <div className="flex gap-3">
              <div className="w-6 h-6 rounded-full bg-[#22D3EE]/10 flex items-center justify-center shrink-0 mt-0.5">
                <span className="text-[11px] font-bold text-[#22D3EE]">1</span>
              </div>
              <div>
                <p className="text-[13px] text-white font-medium mb-2">
                  Download the AEGIS Node app on the target machine
                </p>
                <div className="flex flex-wrap gap-2">
                  {['Windows', 'macOS', 'Linux'].map((os) => (
                    <a
                      key={os}
                      href="#"
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.04] border border-white/[0.06] text-[11px] text-zinc-400 font-medium hover:bg-white/[0.08] hover:text-white transition-colors"
                    >
                      <Download className="w-3.5 h-3.5" />
                      {os}
                    </a>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex gap-3">
              <div className="w-6 h-6 rounded-full bg-[#22D3EE]/10 flex items-center justify-center shrink-0 mt-0.5">
                <span className="text-[11px] font-bold text-[#22D3EE]">2</span>
              </div>
              <div>
                <p className="text-[13px] text-white font-medium">
                  Open the Node app -- it will display an enrollment code
                </p>
                <p className="text-[11px] text-zinc-500 mt-0.5">
                  The code looks like: <span className="font-mono text-zinc-400">C6-AB12-XY34</span>
                </p>
              </div>
            </div>

            <div className="flex gap-3">
              <div className="w-6 h-6 rounded-full bg-[#22D3EE]/10 flex items-center justify-center shrink-0 mt-0.5">
                <span className="text-[11px] font-bold text-[#22D3EE]">3</span>
              </div>
              <div>
                <p className="text-[13px] text-white font-medium mb-2">
                  Select node type
                </p>
                <div className="flex rounded-xl bg-white/[0.04] border border-white/[0.06] p-1 mb-4">
                  {([['server', 'Server', 'Full monitoring: CPU, MEM, Disk, processes, services'] as const, ['workspace', 'Workspace', 'Light monitoring: CPU, MEM, basic info'] as const]).map(([value, label, desc]) => (
                    <button
                      key={value}
                      onClick={() => setNodeType(value)}
                      className={cn(
                        'flex-1 flex items-center gap-2 px-3 py-2 rounded-lg text-[12px] font-medium transition-all',
                        nodeType === value
                          ? 'bg-[#22D3EE]/10 text-[#22D3EE] border border-[#22D3EE]/20'
                          : 'text-zinc-500 hover:text-zinc-300 border border-transparent'
                      )}
                      type="button"
                    >
                      {value === 'server' ? <Server className="w-4 h-4 shrink-0" /> : <Laptop className="w-4 h-4 shrink-0" />}
                      <div className="text-left">
                        <span className="block">{label}</span>
                        <span className="block text-[9px] text-zinc-600 font-normal">{desc}</span>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex gap-3">
              <div className="w-6 h-6 rounded-full bg-[#22D3EE]/10 flex items-center justify-center shrink-0 mt-0.5">
                <span className="text-[11px] font-bold text-[#22D3EE]">4</span>
              </div>
              <div>
                <p className="text-[13px] text-white font-medium mb-3">
                  Paste the enrollment code below
                </p>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={code}
                    onChange={(e) => setCode(formatCodeInput(e.target.value))}
                    placeholder="C6-____-____"
                    maxLength={12}
                    className="flex-1 px-4 py-2.5 rounded-xl c6-input text-[15px] font-mono tracking-wider text-center placeholder:text-zinc-600 focus:outline-none focus:ring-2 focus:ring-[#22D3EE]/40"
                    aria-label="Enrollment code"
                    onKeyDown={(e) => { if (e.key === 'Enter') handleEnroll(); }}
                    autoFocus
                  />
                  <button
                    onClick={handleEnroll}
                    disabled={code.length < 12}
                    className={cn(
                      'px-5 py-2.5 rounded-xl text-[13px] font-semibold transition-colors',
                      code.length >= 12
                        ? 'bg-[#22D3EE] text-black hover:bg-[#22D3EE]/90'
                        : 'bg-white/[0.06] text-zinc-600 cursor-not-allowed'
                    )}
                  >
                    Enroll
                  </button>
                </div>
              </div>
            </div>
          </div>
          <p className="text-[11px] text-zinc-600 text-center">
            The node will automatically connect and start monitoring after enrollment.
            Codes expire after 15 minutes.
          </p>
        </div>
      )}

      {step === 'loading' && (
        <div className="flex flex-col items-center justify-center py-12">
          <Loader2 className="w-8 h-8 text-[#22D3EE] animate-spin mb-4" />
          <p className="text-[13px] text-zinc-400">Enrolling node...</p>
        </div>
      )}

      {step === 'success' && (
        <div className="flex flex-col items-center justify-center py-8 space-y-4">
          <div className="w-12 h-12 rounded-full bg-[#22C55E]/10 flex items-center justify-center">
            <CheckCircle className="w-6 h-6 text-[#22C55E]" />
          </div>
          <div className="text-center">
            <p className="text-[15px] font-semibold text-white mb-1">Node Enrolled Successfully</p>
            <p className="text-[13px] text-zinc-400 max-w-sm">{resultMessage}</p>
          </div>
          <button
            onClick={handleClose}
            className="px-5 py-2 rounded-xl bg-white/[0.06] text-[13px] text-zinc-300 font-medium hover:bg-white/[0.1] transition-colors"
          >
            Done
          </button>
        </div>
      )}

      {step === 'error' && (
        <div className="flex flex-col items-center justify-center py-8 space-y-4">
          <div className="w-12 h-12 rounded-full bg-[#EF4444]/10 flex items-center justify-center">
            <AlertCircle className="w-6 h-6 text-[#EF4444]" />
          </div>
          <div className="text-center">
            <p className="text-[15px] font-semibold text-white mb-1">Enrollment Failed</p>
            <p className="text-[13px] text-zinc-400 max-w-sm">{errorMessage}</p>
          </div>
          <button
            onClick={() => { setStep('input'); setErrorMessage(''); }}
            className="px-5 py-2 rounded-xl bg-white/[0.06] text-[13px] text-zinc-300 font-medium hover:bg-white/[0.1] transition-colors"
          >
            Try Again
          </button>
        </div>
      )}
    </Modal>
  );
}

// ─── Node Detail Modal ────────────────────────────────────────────────────────

function InfoItem({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="p-3 rounded-xl bg-white/[0.03] border border-white/[0.04]">
      <p className="text-[10px] text-zinc-500 font-medium uppercase tracking-wider mb-1">{label}</p>
      <p className={cn('text-[13px] text-white truncate', mono && 'font-mono text-[12px]')}>{value}</p>
    </div>
  );
}

function NodeDetailModal({ node, open, onClose }: { node: NodeInfo | null; open: boolean; onClose: () => void }) {
  if (!node) return null;
  const isOnline = node.status === 'online';
  const isStale = node.status === 'stale';

  return (
    <Modal open={open} onClose={onClose} title={`Node: ${node.hostname}`} size="md">
      <div className="space-y-4">
        <div className="flex items-center gap-3 p-3 rounded-xl bg-white/[0.03] border border-white/[0.06]">
          <span
            className={cn(
              'w-3 h-3 rounded-full shrink-0',
              isOnline
                ? 'bg-[#22C55E] shadow-[0_0_8px_#22C55E]'
                : isStale
                ? 'bg-[#F59E0B] shadow-[0_0_8px_#F59E0B]'
                : 'bg-[#EF4444] shadow-[0_0_8px_#EF4444]'
            )}
          />
          <div>
            <p className="text-[14px] font-semibold text-white">{node.hostname}</p>
            <p className={cn(
              'text-[11px] font-medium capitalize',
              isOnline ? 'text-[#22C55E]' : isStale ? 'text-[#F59E0B]' : 'text-[#EF4444]'
            )}>
              {node.status}
            </p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <InfoItem label="Agent ID" value={node.id} mono />
          <InfoItem label="IP Address" value={node.ip_address || 'N/A'} mono />
          <InfoItem label="Operating System" value={node.os_info || 'Unknown'} />
          <InfoItem label="Agent Version" value={`v${node.agent_version}`} mono />
          <InfoItem label="Last Heartbeat" value={node.last_heartbeat ? new Date(node.last_heartbeat).toLocaleString() : 'Never'} />
          <InfoItem label="Enrolled" value={node.created_at ? new Date(node.created_at).toLocaleDateString() : 'Unknown'} />
        </div>

        {node.tags.length > 0 && (
          <div>
            <p className="text-[10px] text-zinc-500 font-medium uppercase tracking-wider mb-2">Tags</p>
            <div className="flex flex-wrap gap-1.5">
              {node.tags.map((tag) => (
                <span key={tag} className="text-[10px] font-mono text-zinc-400 bg-white/[0.04] border border-white/[0.06] px-2 py-0.5 rounded-md">
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}

// ─── Confirm Remove Modal ─────────────────────────────────────────────────────

function ConfirmRemoveModal({ open, onClose, onConfirm, hostname }: { open: boolean; onClose: () => void; onConfirm: () => void; hostname: string }) {
  return (
    <Modal open={open} onClose={onClose} title="Remove Node" size="sm">
      <div className="space-y-4">
        <p className="text-[13px] text-zinc-400">
          Are you sure you want to remove <span className="text-white font-semibold">{hostname}</span> from
          your network? The node will stop reporting and must be re-enrolled to reconnect.
        </p>
        <div className="flex gap-2 justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl bg-white/[0.06] text-[13px] text-zinc-300 font-medium hover:bg-white/[0.1] transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="px-4 py-2 rounded-xl bg-[#EF4444]/10 text-[13px] text-[#EF4444] font-semibold hover:bg-[#EF4444]/20 transition-colors"
          >
            Remove Node
          </button>
        </div>
      </div>
    </Modal>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function InfraPage() {
  const [systems, setSystems] = useState<SystemInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());

  // Node state
  const [nodes, setNodes] = useState<NodeInfo[]>([]);
  const [nodesLoading, setNodesLoading] = useState(true);
  const [enrollModalOpen, setEnrollModalOpen] = useState(false);
  const [selectedNode, setSelectedNode] = useState<NodeInfo | null>(null);
  const [detailModalOpen, setDetailModalOpen] = useState(false);
  const [removeTarget, setRemoveTarget] = useState<NodeInfo | null>(null);
  const [removeModalOpen, setRemoveModalOpen] = useState(false);

  const fetchNodes = useCallback(async () => {
    try {
      const data = await api.nodes.list();
      setNodes(data);
    } catch {
      setNodes([]);
    } finally {
      setNodesLoading(false);
    }
  }, []);

  const fetchData = useCallback(async () => {
    try {
      const data = await api.infra.systems();
      const mapped: SystemInfo[] = data.systems.map((s) => ({
        ...s,
        status: (s.status as SystemInfo['status']) || 'offline',
        pm2_processes: (s.pm2_processes || []).map((p) => ({
          ...p,
          status: (p.status as PM2Process['status']) || 'stopped',
        })),
      }));
      setSystems(mapped);
      setError(null);
      setLastUpdated(new Date());
    } catch (err) {
      console.error('Failed to fetch infra data:', err);
      setError('Could not connect to server');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    fetchNodes();
    const interval = setInterval(() => {
      // Stop polling if we are being redirected to login (token expired)
      if (isRedirectingToLogin()) {
        clearInterval(interval);
        return;
      }
      fetchData();
      fetchNodes();
    }, 30_000);
    return () => clearInterval(interval);
  }, [fetchData, fetchNodes]);

  async function handleRemoveNode() {
    if (!removeTarget) return;
    try {
      await api.nodes.remove(removeTarget.id);
      setNodes((prev) => prev.filter((n) => n.id !== removeTarget.id));
    } catch {
      // silently fail
    }
    setRemoveModalOpen(false);
    setRemoveTarget(null);
  }

  // Collect all PM2 processes from all systems
  const allProcesses: PM2Process[] = systems.flatMap((s) => s.pm2_processes || []);
  const hasAdminPm2 = allProcesses.length > 0;

  // Server-type nodes with real metrics become ServerCards too
  const serverNodes: SystemInfo[] = nodes
    .filter((n) => n.node_type === 'server' && (n.cpu > 0 || n.mem > 0))
    .map((n) => ({
      name: n.hostname,
      ip: n.ip_address || '',
      role: 'Node Agent (Server)',
      status: (n.status === 'online' ? 'online' : n.status === 'stale' ? 'degraded' : 'offline') as SystemInfo['status'],
      cpu: n.cpu,
      mem: n.mem,
      disk: n.disk,
      uptime: formatHeartbeat(n.last_heartbeat),
      services: [],
      pm2_processes: [],
    }));

  const coreSystemCards = systems.filter(s => s.role !== 'Node Agent');
  const allServerCards = [...coreSystemCards, ...serverNodes];

  // Network mesh: combine tailscale systems + enrolled nodes
  const enrolledNetworkNodes: SystemInfo[] = nodes.map((n) => ({
    name: n.hostname,
    ip: n.ip_address || '',
    role: n.node_type === 'server' ? 'Server Node' : 'Workspace Node',
    status: (n.status === 'online' ? 'online' : 'offline') as SystemInfo['status'],
    cpu: n.cpu,
    mem: n.mem,
    disk: n.disk,
    uptime: '',
    services: [],
    pm2_processes: [],
  }));

  const onlineNodes = nodes.filter((n) => n.status === 'online').length;
  const onlineCount = systems.filter((s) => s.status === 'online').length;

  // Include nodes with metrics in average calculations
  const allMetricSources = [...systems, ...nodes.filter(n => n.cpu > 0 || n.mem > 0)];
  const totalCpu = allMetricSources.length > 0
    ? Math.round(allMetricSources.reduce((a, s) => a + s.cpu, 0) / allMetricSources.length)
    : 0;
  const totalMem = allMetricSources.length > 0
    ? Math.round(allMetricSources.reduce((a, s) => a + s.mem, 0) / allMetricSources.length)
    : 0;

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center space-y-3">
          <div className="w-8 h-8 border-2 border-[#22D3EE]/30 border-t-[#22D3EE] rounded-full animate-spin mx-auto" />
          <p className="text-sm text-zinc-500">Loading infrastructure metrics...</p>
        </div>
      </div>
    );
  }

  if (error && systems.length === 0) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center space-y-3">
          <div className="w-10 h-10 rounded-xl bg-[#EF4444]/10 flex items-center justify-center mx-auto">
            <span className="text-[#EF4444] text-lg">!</span>
          </div>
          <p className="text-sm text-zinc-400">{error}</p>
          <button
            onClick={() => { setLoading(true); fetchData(); }}
            className="text-xs text-[#22D3EE] hover:underline"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-[22px] sm:text-[28px] font-bold text-white tracking-tight">
            Infrastructure
          </h1>
          <p className="text-sm text-zinc-500 mt-1">
            Real-time system monitoring across all nodes
          </p>
        </div>
        <div className="flex items-center gap-2 mt-1">
          {error ? (
            <span className="w-1.5 h-1.5 bg-[#F59E0B] rounded-full animate-pulse" />
          ) : (
            <span className="w-1.5 h-1.5 bg-[#22C55E] rounded-full animate-pulse" />
          )}
          <span className="text-[11px] text-zinc-500 font-mono tabular-nums">
            {lastUpdated.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}
          </span>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-4 flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#22C55E]/10 flex items-center justify-center">
            <span className="text-[#22C55E] font-mono font-bold text-sm">{onlineCount}</span>
          </div>
          <div>
            <p className="text-[11px] text-zinc-500 font-medium uppercase tracking-wider">Systems</p>
            <p className="text-[15px] font-semibold text-white">{onlineCount}/{systems.length}</p>
          </div>
        </div>
        <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-4 flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#22D3EE]/10 flex items-center justify-center">
            <Monitor size={18} className="text-[#22D3EE]" />
          </div>
          <div>
            <p className="text-[11px] text-zinc-500 font-medium uppercase tracking-wider">Nodes</p>
            <p className="text-[15px] font-semibold text-white">{onlineNodes}/{nodes.length}</p>
          </div>
        </div>
        <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-4 flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#22D3EE]/10 flex items-center justify-center">
            <Activity01Icon size={18} className="text-[#22D3EE]" />
          </div>
          <div>
            <p className="text-[11px] text-zinc-500 font-medium uppercase tracking-wider">Avg CPU</p>
            <p className="text-[15px] font-semibold font-mono text-white tabular-nums">{totalCpu}%</p>
          </div>
        </div>
        <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-4 flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#D946EF]/10 flex items-center justify-center">
            <span className="text-[#D946EF] font-mono font-bold text-xs">RAM</span>
          </div>
          <div>
            <p className="text-[11px] text-zinc-500 font-medium uppercase tracking-wider">Avg Memory</p>
            <p className="text-[15px] font-semibold font-mono text-white tabular-nums">{totalMem}%</p>
          </div>
        </div>
      </div>

      {/* ─── Nodes Section ─────────────────────────────────────────────── */}
      <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl overflow-hidden">
        <div className="flex items-center justify-between px-4 sm:px-6 py-4 border-b border-white/[0.06]">
          <div className="flex items-center gap-2.5">
            <Monitor size={16} className="text-zinc-500" />
            <span className="text-[14px] font-semibold text-white">Nodes</span>
            <span className="text-[11px] text-zinc-600 font-mono">
              {nodes.length} enrolled
            </span>
          </div>
          <button
            onClick={() => setEnrollModalOpen(true)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#22D3EE]/10 text-[11px] text-[#22D3EE] font-semibold hover:bg-[#22D3EE]/20 transition-colors"
            aria-label="Add node"
          >
            <Plus className="w-3.5 h-3.5" />
            Add Node
          </button>
        </div>

        <div className="p-4 sm:p-6">
          {nodesLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="w-6 h-6 text-[#22D3EE] animate-spin" />
            </div>
          ) : nodes.length === 0 ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
              <AddNodeCard onClick={() => setEnrollModalOpen(true)} />
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3 stagger-children">
              {nodes.map((node) => (
                <NodeCard
                  key={node.id}
                  node={node}
                  onRemove={(id) => {
                    const target = nodes.find((n) => n.id === id);
                    if (target) {
                      setRemoveTarget(target);
                      setRemoveModalOpen(true);
                    }
                  }}
                  onSelect={(n) => {
                    setSelectedNode(n);
                    setDetailModalOpen(true);
                  }}
                />
              ))}
              <AddNodeCard onClick={() => setEnrollModalOpen(true)} />
            </div>
          )}
        </div>
      </div>

      {/* Server Cards Grid */}
      {allServerCards.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 stagger-children">
          {allServerCards.map((system) => (
            <ServerCard key={system.ip + system.name} system={system} />
          ))}
        </div>
      )}

      {/* PM2 Processes Section — only show when admin tenant has PM2 data */}
      {hasAdminPm2 && (
        <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl overflow-hidden">
          <div className="flex items-center justify-between px-4 sm:px-6 py-4 border-b border-white/[0.06]">
            <div className="flex items-center gap-2.5">
              <Activity01Icon size={16} className="text-zinc-500" />
              <span className="text-[14px] font-semibold text-white">
                PM2 Processes
              </span>
              <span className="text-[11px] text-zinc-600 font-mono">Mac Pro</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 bg-[#22C55E] rounded-full animate-pulse" />
              <span className="text-[11px] text-zinc-500 font-medium">
                {allProcesses.filter((p) => p.status === 'online').length} running
              </span>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-white/[0.04]">
                  <th className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest px-4 sm:px-6 py-3">Name</th>
                  <th className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest px-4 py-3">Status</th>
                  <th className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest px-4 py-3 hidden sm:table-cell">CPU</th>
                  <th className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest px-4 py-3 hidden sm:table-cell">Memory</th>
                  <th className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest px-4 py-3 hidden md:table-cell">Uptime</th>
                  <th className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest px-4 py-3 hidden md:table-cell">Restarts</th>
                </tr>
              </thead>
              <tbody>
                {allProcesses.map((proc) => (
                  <tr
                    key={proc.name}
                    className="border-b border-white/[0.03] hover:bg-white/[0.02] transition-colors"
                  >
                    <td className="px-4 sm:px-6 py-3">
                      <span className="text-[13px] font-mono font-medium text-white">{proc.name}</span>
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={proc.status} />
                    </td>
                    <td className="px-4 py-3 hidden sm:table-cell">
                      <span className="text-[13px] font-mono text-zinc-400 tabular-nums">{proc.cpu}%</span>
                    </td>
                    <td className="px-4 py-3 hidden sm:table-cell">
                      <span className="text-[13px] font-mono text-zinc-400">{proc.mem}</span>
                    </td>
                    <td className="px-4 py-3 hidden md:table-cell">
                      <span className="text-[12px] font-mono text-zinc-500">{proc.uptime}</span>
                    </td>
                    <td className="px-4 py-3 hidden md:table-cell">
                      <span className={cn(
                        'text-[12px] font-mono tabular-nums',
                        proc.restarts > 0 ? 'text-[#F59E0B]' : 'text-zinc-600'
                      )}>
                        {proc.restarts}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Network Mesh — enrolled nodes + core systems */}
      {(() => {
        const meshNodes = [
          ...systems.filter(s => s.ip && s.ip.startsWith('100.')),
          ...enrolledNetworkNodes.filter(n => n.ip),
        ];
        // Deduplicate by IP
        const seen = new Set<string>();
        const uniqueNodes = meshNodes.filter(n => {
          if (seen.has(n.ip)) return false;
          seen.add(n.ip);
          return true;
        });
        if (uniqueNodes.length === 0) return null;
        return (
          <div className="bg-[#18181B] border border-white/[0.06] rounded-2xl overflow-hidden">
            <div className="px-4 sm:px-6 py-4 border-b border-white/[0.06]">
              <div className="flex items-center gap-2.5">
                <span className="text-[14px] font-semibold text-white">Network Mesh</span>
                <span className="text-[11px] text-zinc-600 font-mono">
                  {uniqueNodes.filter(n => n.status === 'online').length}/{uniqueNodes.length} online
                </span>
              </div>
              <p className="text-[12px] text-zinc-500 mt-0.5">
                Connected infrastructure and enrolled nodes
              </p>
            </div>
            <div className="p-4 sm:p-6 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {uniqueNodes.map((sys) => (
                <NetworkNode key={sys.ip + sys.name} system={sys} />
              ))}
            </div>
          </div>
        );
      })()}

      {/* Modals */}
      <EnrollmentModal
        open={enrollModalOpen}
        onClose={() => setEnrollModalOpen(false)}
        onEnrolled={fetchNodes}
      />
      <NodeDetailModal
        node={selectedNode}
        open={detailModalOpen}
        onClose={() => { setDetailModalOpen(false); setSelectedNode(null); }}
      />
      <ConfirmRemoveModal
        open={removeModalOpen}
        onClose={() => { setRemoveModalOpen(false); setRemoveTarget(null); }}
        onConfirm={handleRemoveNode}
        hostname={removeTarget?.hostname || ''}
      />
    </div>
  );
}
