'use client';

import { useEffect, useState } from 'react';
import { subscribeTopic } from '@/lib/ws';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';

interface NodeStatus {
  id: string;
  hostname: string;
  status: 'online' | 'offline' | 'degraded' | string;
  last_heartbeat?: string | null;
}

const STATUS_COLOR: Record<string, string> = {
  online:   'bg-[var(--success)] shadow-[0_0_6px_color-mix(in_oklab,var(--success)_60%,transparent)]',
  active:   'bg-[var(--success)] shadow-[0_0_6px_color-mix(in_oklab,var(--success)_60%,transparent)]',
  offline:  'bg-[var(--danger)] shadow-[0_0_6px_color-mix(in_oklab,var(--danger)_50%,transparent)]',
  degraded: 'bg-[var(--warning)] shadow-[0_0_6px_color-mix(in_oklab,var(--warning)_50%,transparent)]',
  warning:  'bg-[var(--warning)] shadow-[0_0_6px_color-mix(in_oklab,var(--warning)_50%,transparent)]',
};

function statusDot(s: string) {
  return STATUS_COLOR[s?.toLowerCase()] ?? 'bg-muted-foreground/40';
}

export function NodeHeartbeatGrid() {
  const [nodes, setNodes] = useState<NodeStatus[]>([]);

  useEffect(() => {
    api.nodes.list().then((list) => {
      setNodes(
        list.map((n) => ({
          id: n.id,
          hostname: n.hostname,
          status: n.status,
          last_heartbeat: n.last_heartbeat,
        }))
      );
    }).catch(() => {});

    const off = subscribeTopic('nodes.status', (data) => {
      if (!data || typeof data !== 'object') return;
      const r = data as Record<string, unknown>;
      const id = String(r.id ?? r.node_id ?? '');
      if (!id) return;
      const hostname = String(r.hostname ?? id);
      const status = String(r.status ?? 'online');
      const last_heartbeat = r.last_heartbeat ? String(r.last_heartbeat) : new Date().toISOString();
      setNodes((prev) => {
        const idx = prev.findIndex((n) => n.id === id);
        if (idx < 0) {
          return [...prev, { id, hostname, status, last_heartbeat }];
        }
        const next = [...prev];
        next[idx] = { ...next[idx], hostname, status, last_heartbeat };
        return next;
      });
    });

    return () => {
      off();
    };
  }, []);

  const online = nodes.filter((n) => n.status === 'online' || n.status === 'active').length;

  return (
    <div className="aegis-card overflow-hidden flex flex-col h-full">
      <div className="aegis-section-header shrink-0">
        <span className="text-[13px] font-semibold text-foreground tracking-tight">Node Heartbeats</span>
        <span className="text-[11px] font-mono tabular-nums">
          <span className="text-[var(--success)]">{online}</span>
          <span className="text-muted-foreground/60"> / {nodes.length}</span>
        </span>
      </div>
      <div className="flex-1 overflow-y-auto p-3">
        {nodes.length === 0 ? (
          <p className="text-muted-foreground/60 text-[12px] font-mono text-center py-6">No nodes enrolled</p>
        ) : (
          <div className="grid grid-cols-6 gap-2">
            {nodes.map((n) => (
              <div
                key={n.id}
                title={`${n.hostname} — ${n.status}`}
                className="flex flex-col items-center gap-1 p-1.5 rounded-lg bg-muted/30 border border-border hover:border-border/80 transition-colors"
              >
                <span className={cn('w-2 h-2 rounded-full', statusDot(n.status))} />
                <span className="text-[9px] text-muted-foreground font-mono truncate max-w-full">
                  {n.hostname.slice(0, 8)}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
