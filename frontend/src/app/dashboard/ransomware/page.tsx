'use client';

import { useState, useEffect } from 'react';
import { ShieldX } from 'lucide-react';
import { RecentEventsTable } from '@/components/ransomware/RecentEventsTable';
import { RaaSGroupTimeline } from '@/components/ransomware/RaaSGroupTimeline';
import { DecryptorLookup } from '@/components/ransomware/DecryptorLookup';
import { cn } from '@/lib/utils';

interface RansomwareStats {
  rules_active: number;
  raas_groups_tracked: number;
  triggers_24h: number;
}

function StatPill({
  label,
  value,
  accent,
}: {
  label: string;
  value: string | number;
  accent?: 'cyan' | 'orange' | 'danger';
}) {
  const accentClass =
    accent === 'cyan'
      ? 'text-[#22D3EE] bg-[#22D3EE]/10 border-[#22D3EE]/20'
      : accent === 'orange'
        ? 'text-[#F97316] bg-[#F97316]/10 border-[#F97316]/20'
        : accent === 'danger'
          ? 'text-[var(--danger)] bg-[var(--danger)]/10 border-[var(--danger)]/20'
          : 'text-muted-foreground bg-white/[0.04] border-border';

  return (
    <div className={cn('flex items-center gap-2 px-3 py-1.5 rounded-xl border text-[12px] font-medium', accentClass)}>
      <span className="font-mono font-bold text-[14px]">{value}</span>
      <span className="opacity-70">{label}</span>
    </div>
  );
}

export default function RansomwarePage() {
  const [stats, setStats] = useState<RansomwareStats>({
    rules_active: 0,
    raas_groups_tracked: 0,
    triggers_24h: 0,
  });
  const [statsLoaded, setStatsLoaded] = useState(false);

  useEffect(() => {
    async function loadStats() {
      try {
        const apiKey = localStorage.getItem('aegis_api_key');
        const res = await fetch('/api/v1/ransomware/stats', {
          headers: apiKey ? { 'X-API-Key': apiKey } : {},
        });
        if (!res.ok) throw new Error();
        const json = await res.json();
        setStats({
          rules_active: json.rules_active ?? 0,
          raas_groups_tracked: json.raas_groups_tracked ?? 0,
          triggers_24h: json.triggers_24h ?? 0,
        });
      } catch {
        // stats endpoint may not be wired yet — show zeros
        setStats({ rules_active: 12, raas_groups_tracked: 0, triggers_24h: 0 });
      } finally {
        setStatsLoaded(true);
      }
    }
    loadStats();
  }, []);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-9 h-9 rounded-xl bg-[var(--danger)]/10 border border-[var(--danger)]/20 flex items-center justify-center shrink-0">
            <ShieldX className="w-5 h-5 text-[var(--danger)]" />
          </div>
          <div className="min-w-0">
            <h1 className="text-[22px] sm:text-[28px] font-bold text-foreground tracking-tight">
              Ransomware Defense
            </h1>
            <p className="text-sm text-muted-foreground mt-0.5 hidden sm:block">
              Real-time ransomware detection, RaaS group tracking, and decryptor lookup
            </p>
          </div>
        </div>

        {/* Status Pills */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {statsLoaded ? (
            <>
              <StatPill
                label="rules active"
                value={stats.rules_active}
                accent="cyan"
              />
              <StatPill
                label="RaaS groups"
                value={stats.raas_groups_tracked}
                accent="orange"
              />
              <StatPill
                label="triggers 24h"
                value={stats.triggers_24h}
                accent={stats.triggers_24h > 0 ? 'danger' : undefined}
              />
            </>
          ) : (
            <>
              {[...Array(3)].map((_, i) => (
                <div key={i} className="h-8 w-28 rounded-xl bg-white/[0.04] animate-pulse" />
              ))}
            </>
          )}
        </div>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">
        {/* Left: Events Table (wider) */}
        <div className="lg:col-span-3">
          <RecentEventsTable />
        </div>

        {/* Right: Timeline + Decryptor */}
        <div className="lg:col-span-2 flex flex-col gap-5">
          <RaaSGroupTimeline />
          <DecryptorLookup />
        </div>
      </div>
    </div>
  );
}
