'use client';

import { useEffect, useState, useRef } from 'react';
import { subscribeTopic } from '@/lib/ws';

interface LogLine {
  id: string;
  ts: string;
  level: string;
  source?: string;
  message: string;
}

const MAX_LINES = 200;

const LEVEL_COLOR: Record<string, string> = {
  critical: 'text-[#EF4444]',
  error: 'text-[#EF4444]',
  high: 'text-[#F97316]',
  warn: 'text-[#F59E0B]',
  warning: 'text-[#F59E0B]',
  info: 'text-[#22D3EE]',
  debug: 'text-zinc-500',
};

function shortTime(ts?: string): string {
  const d = ts ? new Date(ts) : new Date();
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
}

function normalize(raw: unknown): LogLine | null {
  if (!raw) return null;
  if (typeof raw === 'string') {
    return {
      id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
      ts: new Date().toISOString(),
      level: 'info',
      message: raw,
    };
  }
  if (typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
    ts: String(r.timestamp ?? r.ts ?? new Date().toISOString()),
    level: String(r.level ?? r.severity ?? 'info').toLowerCase(),
    source: r.source ? String(r.source) : r.module ? String(r.module) : undefined,
    message: String(r.message ?? r.line ?? r.text ?? JSON.stringify(r)),
  };
}

export function RawLogStream() {
  const [lines, setLines] = useState<LogLine[]>([]);
  const [autoScroll, setAutoScroll] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const off1 = subscribeTopic('logs.stream', (data) => {
      const line = normalize(data);
      if (!line) return;
      setLines((prev) => [...prev.slice(-(MAX_LINES - 1)), line]);
    });
    const off2 = subscribeTopic('log_line', (data) => {
      const line = normalize(data);
      if (!line) return;
      setLines((prev) => [...prev.slice(-(MAX_LINES - 1)), line]);
    });
    return () => {
      off1();
      off2();
    };
  }, []);

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [lines, autoScroll]);

  return (
    <div className="bg-[#0E0E10] border border-white/[0.06] rounded-2xl overflow-hidden flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.06] shrink-0 bg-[#18181B]">
        <div className="flex items-center gap-2.5">
          <span className="w-1.5 h-1.5 rounded-full bg-[#22C55E] animate-pulse" />
          <span className="text-[13px] font-semibold text-white tracking-tight">Raw Log Stream</span>
        </div>
        <label className="flex items-center gap-1.5 cursor-pointer">
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
            className="w-3 h-3 accent-[#22D3EE] cursor-pointer"
          />
          <span className="text-[10px] text-zinc-500 font-mono uppercase tracking-wide">auto-scroll</span>
        </label>
      </div>
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto font-mono text-[11px] leading-[1.45] p-3 space-y-0.5"
      >
        {lines.length === 0 ? (
          <p className="text-zinc-700 italic">Waiting for log events…</p>
        ) : (
          lines.map((line) => {
            const color = LEVEL_COLOR[line.level] ?? 'text-zinc-400';
            return (
              <div key={line.id} className="flex items-start gap-2">
                <span className="text-zinc-700 tabular-nums shrink-0">{shortTime(line.ts)}</span>
                <span className={`${color} font-semibold uppercase shrink-0 w-12`}>{line.level}</span>
                {line.source && (
                  <span className="text-zinc-600 shrink-0">[{line.source}]</span>
                )}
                <span className="text-zinc-300 break-all">{line.message}</span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
