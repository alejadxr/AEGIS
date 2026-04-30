'use client';

import { useState, useEffect } from 'react';
import { Search01Icon } from 'hugeicons-react';
import { Plus, Download, Filter, Globe, Hash, Link, Mail, Monitor } from 'lucide-react';
import { DataTable } from '@/components/shared/DataTable';
import { Modal } from '@/components/shared/Modal';
import { LoadingState } from '@/components/shared/LoadingState';
import { api } from '@/lib/api';
import { cn, formatDate } from '@/lib/utils';
import { IOC_TYPES } from '@/lib/constants';

interface IOCRow {
  id: string;
  ioc_type: string;
  ioc_value: string;
  threat_type: string;
  confidence: number;
  source: string;
  tags: string[];
  first_seen: string;
  last_seen: string;
  [key: string]: unknown;
}

const DEMO_IOCS: IOCRow[] = [
  { id: '1', ioc_type: 'ip', ioc_value: '45.33.32.156', threat_type: 'Brute Force', confidence: 0.95, source: 'honeypot', tags: ['ssh', 'bruteforce', 'russia'], first_seen: new Date(Date.now() - 2592000000).toISOString(), last_seen: new Date(Date.now() - 300000).toISOString() },
  { id: '2', ioc_type: 'ip', ioc_value: '185.220.101.34', threat_type: 'Web Scanner', confidence: 0.88, source: 'honeypot', tags: ['http', 'scanner', 'tor-exit'], first_seen: new Date(Date.now() - 604800000).toISOString(), last_seen: new Date(Date.now() - 900000).toISOString() },
  { id: '3', ioc_type: 'domain', ioc_value: 'evil-c2.darknet.to', threat_type: 'C2 Infrastructure', confidence: 0.97, source: 'internal', tags: ['c2', 'cobalt-strike', 'apt'], first_seen: new Date(Date.now() - 172800000).toISOString(), last_seen: new Date(Date.now() - 3600000).toISOString() },
  { id: '4', ioc_type: 'hash', ioc_value: 'a1b2c3d4e5f6789012345678abcdef01', threat_type: 'Malware', confidence: 0.99, source: 'internal', tags: ['cobalt-strike', 'beacon', 'windows'], first_seen: new Date(Date.now() - 86400000).toISOString(), last_seen: new Date(Date.now() - 86400000).toISOString() },
  { id: '5', ioc_type: 'url', ioc_value: 'http://198.51.100.42/update.bin', threat_type: 'Malware Delivery', confidence: 0.92, source: 'internal', tags: ['malware', 'dropper'], first_seen: new Date(Date.now() - 172800000).toISOString(), last_seen: new Date(Date.now() - 86400000).toISOString() },
  { id: '6', ioc_type: 'ip', ioc_value: '198.51.100.23', threat_type: 'APT Activity', confidence: 0.93, source: 'honeypot', tags: ['apt', 'metasploit', 'china'], first_seen: new Date(Date.now() - 5184000000).toISOString(), last_seen: new Date(Date.now() - 1800000).toISOString() },
  { id: '7', ioc_type: 'domain', ioc_value: 'phish-portal.example.xyz', threat_type: 'Phishing', confidence: 0.85, source: 'community', tags: ['phishing', 'credential-harvest'], first_seen: new Date(Date.now() - 259200000).toISOString(), last_seen: new Date(Date.now() - 172800000).toISOString() },
  { id: '8', ioc_type: 'email', ioc_value: 'admin@phish-portal.example.xyz', threat_type: 'Phishing', confidence: 0.82, source: 'community', tags: ['phishing', 'sender'], first_seen: new Date(Date.now() - 259200000).toISOString(), last_seen: new Date(Date.now() - 172800000).toISOString() },
  { id: '9', ioc_type: 'ip', ioc_value: '203.0.113.42', threat_type: 'SQL Injection', confidence: 0.78, source: 'honeypot', tags: ['sqli', 'scanner', 'brazil'], first_seen: new Date(Date.now() - 172800000).toISOString(), last_seen: new Date(Date.now() - 3600000).toISOString() },
  { id: '10', ioc_type: 'hash', ioc_value: 'ff0011223344556677889900aabbccdd', threat_type: 'Ransomware', confidence: 0.96, source: 'community', tags: ['ransomware', 'lockbit', 'windows'], first_seen: new Date(Date.now() - 432000000).toISOString(), last_seen: new Date(Date.now() - 259200000).toISOString() },
];

const typeIcons: Record<string, typeof Monitor> = {
  ip: Monitor,
  domain: Globe,
  hash: Hash,
  url: Link,
  email: Mail,
};

const typeColors: Record<string, string> = {
  ip: 'text-[var(--brand)] bg-[var(--brand)]/10',
  domain: 'text-[var(--chart-5)] bg-[var(--chart-5)]/10',
  hash: 'text-[var(--warning)] bg-[var(--warning)]/10',
  url: 'text-[var(--info)] bg-[var(--info)]/10',
  email: 'text-[var(--success)] bg-[var(--success)]/10',
};

export default function ThreatsPage() {
  const [iocs, setIocs] = useState<IOCRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [showAddModal, setShowAddModal] = useState(false);
  const [newIOC, setNewIOC] = useState({ ioc_type: 'ip', ioc_value: '', threat_type: '', source: 'manual', tags: '' });

  useEffect(() => {
    async function load() {
      try {
        const data = await api.threats.intel();
        setIocs(data as IOCRow[]);
      } catch {
        setIocs(DEMO_IOCS);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const handleSearch = async () => {
    if (!searchQuery.trim()) return;
    try {
      const results = await api.threats.search(searchQuery);
      setIocs(results as IOCRow[]);
    } catch {
      setIocs(DEMO_IOCS.filter((i) =>
        i.ioc_value.includes(searchQuery) || i.threat_type.toLowerCase().includes(searchQuery.toLowerCase())
      ));
    }
  };

  const handleAdd = async () => {
    if (!newIOC.ioc_value.trim()) return;
    try {
      await api.threats.addIOC({
        ...newIOC,
        tags: newIOC.tags.split(',').map((t) => t.trim()).filter(Boolean),
      });
    } catch {
      // Demo mode
    }
    setShowAddModal(false);
    setNewIOC({ ioc_type: 'ip', ioc_value: '', threat_type: '', source: 'manual', tags: '' });
  };

  const filtered = typeFilter === 'all' ? iocs : iocs.filter((i) => i.ioc_type === typeFilter);

  const columns = [
    {
      key: 'ioc_type', label: 'Type', sortable: true,
      render: (row: IOCRow) => {
        const Icon = typeIcons[row.ioc_type] || Monitor;
        return (
          <div className="flex items-center gap-2">
            <div className={cn('w-7 h-7 rounded-lg flex items-center justify-center', typeColors[row.ioc_type]?.split(' ')[1] || 'bg-zinc-500/10')}>
              <Icon className={cn('w-3.5 h-3.5', typeColors[row.ioc_type]?.split(' ')[0] || 'text-muted-foreground')} />
            </div>
            <span className={cn('text-[10px] font-semibold uppercase tracking-wider', typeColors[row.ioc_type]?.split(' ')[0] || 'text-muted-foreground')}>
              {row.ioc_type}
            </span>
          </div>
        );
      },
    },
    {
      key: 'ioc_value', label: 'Value', sortable: true,
      render: (row: IOCRow) => <span className="font-mono text-[13px] text-foreground">{row.ioc_value}</span>,
    },
    { key: 'threat_type', label: 'Threat Type', sortable: true, render: (row: IOCRow) => <span className="text-[13px] text-foreground/80">{row.threat_type}</span> },
    {
      key: 'confidence', label: 'Confidence', sortable: true,
      render: (row: IOCRow) => {
        const pct = Math.round(row.confidence * 100);
        return (
          <div className="flex items-center gap-2">
            <div className="w-16 h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
              <div
                className={cn(
                  'h-full rounded-full',
                  pct >= 90 ? 'bg-[var(--success)]' : pct >= 70 ? 'bg-[var(--warning)]' : 'bg-[var(--danger)]'
                )}
                style={{ width: `${pct}%` }}
              />
            </div>
            <span className="text-[11px] font-mono text-muted-foreground">{pct}%</span>
          </div>
        );
      },
    },
    {
      key: 'source', label: 'Source', sortable: true,
      render: (row: IOCRow) => <span className="capitalize text-muted-foreground text-[13px]">{row.source}</span>,
    },
    {
      key: 'tags', label: 'Tags',
      render: (row: IOCRow) => (
        <div className="flex flex-wrap gap-1">
          {(row.tags as string[]).slice(0, 3).map((tag) => (
            <span key={tag} className="text-[10px] bg-white/[0.05] border border-border px-1.5 py-0.5 rounded-md text-muted-foreground">{tag}</span>
          ))}
          {(row.tags as string[]).length > 3 && (
            <span className="text-[10px] text-muted-foreground/60">+{(row.tags as string[]).length - 3}</span>
          )}
        </div>
      ),
    },
    {
      key: 'last_seen', label: 'Last Seen', sortable: true,
      render: (row: IOCRow) => <span className="text-muted-foreground text-[11px] font-mono">{formatDate(row.last_seen as string)}</span>,
    },
  ];

  if (loading) return <LoadingState message="Loading threat intelligence data..." />;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-[22px] sm:text-[28px] font-bold text-foreground tracking-tight">Threat Intelligence</h1>
          <p className="text-sm text-muted-foreground mt-1 hidden sm:block">IOC management, threat feed, and intelligence sharing</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-1.5 bg-white/[0.05] hover:bg-white/[0.08] text-foreground/80 border border-border font-medium px-3 sm:px-4 py-2.5 rounded-xl transition-colors text-[13px]"
          >
            <Plus className="w-4 h-4" />
            <span className="hidden sm:inline">Add IOC</span>
          </button>
          <button className="flex items-center gap-1.5 bg-[var(--brand)] hover:bg-[var(--brand)] text-[#09090B] font-semibold px-3 sm:px-4 py-2.5 rounded-xl transition-colors text-[13px]">
            <Download className="w-4 h-4" />
            <span className="hidden sm:inline">Export</span>
          </button>
        </div>
      </div>

      {/* Search Bar */}
      <div className="flex items-center gap-2 sm:gap-3">
        <div className="relative flex-1">
          <Search01Icon size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-muted-foreground/60" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            placeholder="Search IOCs..."
            className="w-full bg-card border border-border rounded-xl pl-10 pr-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:border-[var(--brand)]/30 transition-colors"
          />
        </div>
        <button
          onClick={handleSearch}
          className="bg-white/[0.05] hover:bg-white/[0.08] border border-border px-3 sm:px-4 py-2.5 rounded-xl transition-colors text-[13px] text-foreground/80 shrink-0"
        >
          Search
        </button>
      </div>

      {/* Type Filters */}
      <div className="flex items-center gap-1.5 sm:gap-2 flex-wrap">
        <Filter className="w-4 h-4 text-muted-foreground/60 shrink-0" />
        <button
          onClick={() => setTypeFilter('all')}
          className={cn(
            'px-2 sm:px-3 py-1.5 rounded-lg text-[11px] font-medium transition-colors',
            typeFilter === 'all' ? 'bg-[var(--brand)]/10 text-[var(--brand)]' : 'text-muted-foreground hover:text-foreground'
          )}
        >
          All ({iocs.length})
        </button>
        {IOC_TYPES.map((t) => {
          const count = iocs.filter((i) => i.ioc_type === t.value).length;
          return (
            <button
              key={t.value}
              onClick={() => setTypeFilter(t.value)}
              className={cn(
                'px-2 sm:px-3 py-1.5 rounded-lg text-[11px] font-medium transition-colors',
                typeFilter === t.value ? 'bg-[var(--brand)]/10 text-[var(--brand)]' : 'text-muted-foreground hover:text-foreground'
              )}
            >
              {t.label} ({count})
            </button>
          );
        })}
      </div>

      {/* IOC Table */}
      <DataTable<IOCRow>
        columns={columns}
        data={filtered}
        emptyMessage="No IOCs match the current filters. Add indicators manually or they will be automatically generated from honeypot interactions."
      />

      {/* Add IOC Modal */}
      <Modal open={showAddModal} onClose={() => setShowAddModal(false)} title="Add Indicator of Compromise">
        <div className="space-y-4">
          <div>
            <label className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block mb-1.5">IOC Type</label>
            <select
              value={newIOC.ioc_type}
              onChange={(e) => setNewIOC({ ...newIOC, ioc_type: e.target.value })}
              className="w-full bg-[#09090B] border border-border rounded-xl px-4 py-2.5 text-sm text-foreground focus:outline-none focus:border-[var(--brand)]/30"
            >
              {IOC_TYPES.map((t) => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block mb-1.5">Value</label>
            <input
              type="text"
              value={newIOC.ioc_value}
              onChange={(e) => setNewIOC({ ...newIOC, ioc_value: e.target.value })}
              placeholder="e.g., 192.168.1.1 or evil.com"
              className="w-full bg-[#09090B] border border-border rounded-xl px-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:border-[var(--brand)]/30 font-mono"
            />
          </div>
          <div>
            <label className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block mb-1.5">Threat Type</label>
            <input
              type="text"
              value={newIOC.threat_type}
              onChange={(e) => setNewIOC({ ...newIOC, threat_type: e.target.value })}
              placeholder="e.g., C2 Infrastructure, Malware, Phishing"
              className="w-full bg-[#09090B] border border-border rounded-xl px-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:border-[var(--brand)]/30"
            />
          </div>
          <div>
            <label className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block mb-1.5">Tags (comma-separated)</label>
            <input
              type="text"
              value={newIOC.tags}
              onChange={(e) => setNewIOC({ ...newIOC, tags: e.target.value })}
              placeholder="apt, cobalt-strike, windows"
              className="w-full bg-[#09090B] border border-border rounded-xl px-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:border-[var(--brand)]/30"
            />
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button onClick={() => setShowAddModal(false)} className="px-4 py-2 text-[13px] text-muted-foreground hover:text-foreground transition-colors rounded-xl">
              Cancel
            </button>
            <button onClick={handleAdd} className="flex items-center gap-2 bg-[var(--brand)] hover:bg-[var(--brand)] text-[#09090B] font-semibold px-4 py-2 rounded-xl transition-colors text-[13px]">
              <Plus className="w-4 h-4" />
              Add IOC
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
