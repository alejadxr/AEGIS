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
  critical: 'text-[#FF6B6B] font-bold',
  error: 'text-[#FF6B6B] font-bold',
  high: 'text-[#FF9F43] font-bold',
  warn: 'text-[#FECA57] font-bold',
  warning: 'text-[#FECA57] font-bold',
  info: 'text-[#48DBFB] font-semibold',
  debug: 'text-muted-foreground/70',
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
    <div className="bg-card border border-border rounded-2xl overflow-hidden flex flex-col h-full">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border shrink-0">
        <div className="flex items-center gap-2.5">
          <span className="w-1.5 h-1.5 rounded-full bg-[#22C55E] animate-pulse" />
          <span className="text-[13px] font-semibold text-foreground tracking-tight">Raw Log Stream</span>
        </div>
        <label className="flex items-center gap-1.5 cursor-pointer">
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
            className="w-3 h-3 accent-primary cursor-pointer"
          />
          <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wide">auto-scroll</span>
        </label>
      </div>
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto font-mono text-[12px] leading-[1.5] p-3 space-y-0.5 bg-background/90"
      >
        {lines.length === 0 ? (
          <p className="text-muted-foreground/40 italic">Waiting for log events…</p>
        ) : (
          lines.map((line) => {
            const color = LEVEL_COLOR[line.level] ?? 'text-muted-foreground';
            return (
              <div key={line.id} className="flex items-start gap-2">
                <span className="text-muted-foreground/40 tabular-nums shrink-0">{shortTime(line.ts)}</span>
                <span className={`${color} uppercase shrink-0 w-14`}>{line.level}</span>
                {line.source && (
                  <span className="text-muted-foreground/60 shrink-0">[{line.source}]</span>
                )}
                <span className="text-foreground break-all">{line.message}</span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
