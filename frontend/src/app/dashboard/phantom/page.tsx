'use client';

import { useState, useEffect } from 'react';
import { CommandLineIcon, UserIcon } from 'hugeicons-react';
import { Ghost, Plus, RotateCw, Trash2 } from 'lucide-react';
import { Card, CardHeader, CardContent, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';
import { StatusIndicator } from '@/components/shared/StatusIndicator';
import { Modal } from '@/components/shared/Modal';
import { LoadingState } from '@/components/shared/LoadingState';
import { DataTable } from '@/components/shared/DataTable';
import { api } from '@/lib/api';
import { cn, formatRelativeTime } from '@/lib/utils';
import { HONEYPOT_TYPES } from '@/lib/constants';

interface HoneypotItem {
  id: string;
  name: string;
  honeypot_type: string;
  status: string;
  ip_address: string | null;
  port: number | null;
  interactions_count: number;
  last_rotation: string | null;
  created_at: string;
}

interface InteractionItem {
  id: string;
  honeypot_id: string;
  source_ip: string;
  protocol: string;
  commands: string[];
  credentials_tried: Array<{ username: string; password: string }>;
  session_duration: number | null;
  timestamp: string;
}

interface AttackerItem {
  id: string;
  source_ip: string;
  known_ips: string[];
  tools_used: string[];
  techniques: string[];
  sophistication: string;
  geo_data: { country: string; city: string } | null;
  first_seen: string;
  last_seen: string;
  total_interactions: number;
  [key: string]: unknown;
}

const HEATMAP_HOURS = Array.from({ length: 24 }, (_, i) => i);
const HEATMAP_DAYS_PHANTOM = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

function buildInteractionHeatmap(interactions: InteractionItem[]): number[][] {
  const grid: number[][] = Array.from({ length: 7 }, () => new Array(24).fill(0));

  interactions.forEach((ix) => {
    const d = new Date(ix.timestamp);
    const rawDay = d.getDay();
    const dayIdx = rawDay === 0 ? 6 : rawDay - 1;
    const hourIdx = d.getHours();
    grid[dayIdx][hourIdx] += 1;
  });

  return grid;
}

function interactionHeatColor(value: number): string {
  if (value === 0) return 'bg-muted/20';
  if (value <= 1) return 'bg-[#22D3EE]/15';
  if (value <= 2) return 'bg-[#22D3EE]/25';
  if (value <= 3) return 'bg-[#22D3EE]/40';
  if (value <= 4) return 'bg-[#22D3EE]/55';
  if (value <= 5) return 'bg-[#22D3EE]/70';
  return 'bg-[#22D3EE]/85';
}

const typeIcons: Record<string, string> = {
  ssh: 'SSH',
  http: 'HTTP',
  smb: 'SMB',
  api: 'API',
  database: 'DB',
  smtp: 'SMTP',
};

const sophisticationColors: Record<string, string> = {
  script_kiddie: 'text-[#22C55E]',
  intermediate: 'text-[#F59E0B]',
  advanced: 'text-[#EF4444]',
  apt: 'text-[#A855F7]',
};

export default function PhantomPage() {
  const [honeypots, setHoneypots] = useState<HoneypotItem[]>([]);
  const [interactions, setInteractions] = useState<InteractionItem[]>([]);
  const [attackers, setAttackers] = useState<AttackerItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [showDeployModal, setShowDeployModal] = useState(false);
  const [newName, setNewName] = useState('');
  const [newType, setNewType] = useState('ssh');
  const [newPort, setNewPort] = useState(2222);
  const [tab, setTab] = useState<string>('grid');

  useEffect(() => {
    async function load() {
      try {
        const [h, i, a] = await Promise.allSettled([
          api.phantom.honeypots(),
          api.phantom.interactions(),
          api.phantom.attackers(),
        ]);
        setHoneypots(h.status === 'fulfilled' ? h.value : []);
        setInteractions(i.status === 'fulfilled' ? i.value : []);
        setAttackers(a.status === 'fulfilled' ? a.value as AttackerItem[] : []);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const handleDeploy = async () => {
    if (!newName.trim()) return;
    try {
      await api.phantom.deployHoneypot({ name: newName, honeypot_type: newType, port: newPort });
    } catch {
      // best effort
    }
    setShowDeployModal(false);
    setNewName('');
  };

  const handleRotate = async (id: string) => {
    try {
      await api.phantom.rotateHoneypot(id);
    } catch {
      // best effort
    }
    setHoneypots(honeypots.map((h) => h.id === id ? { ...h, status: 'rotating' } : h));
  };

  const attackerColumns = [
    { key: 'source_ip', label: 'Source IP', sortable: true, render: (row: AttackerItem) => <span className="font-mono text-[#22D3EE] text-[13px]">{row.source_ip}</span> },
    {
      key: 'sophistication', label: 'Level', sortable: true,
      render: (row: AttackerItem) => (
        <span className={cn('capitalize font-medium text-[13px]', sophisticationColors[row.sophistication] || 'text-muted-foreground')}>
          {row.sophistication.replace(/_/g, ' ')}
        </span>
      ),
    },
    { key: 'tools_used', label: 'Tools', render: (row: AttackerItem) => <span className="text-[11px] text-muted-foreground font-mono">{(row.tools_used as string[]).join(', ')}</span> },
    {
      key: 'geo_data', label: 'Origin',
      render: (row: AttackerItem) => {
        const geo = row.geo_data as { country: string; city: string } | null;
        return <span className="text-muted-foreground text-[13px]">{geo ? `${geo.city}, ${geo.country}` : 'Unknown'}</span>;
      },
    },
    { key: 'total_interactions', label: 'Interactions', sortable: true, render: (row: AttackerItem) => <span className="font-mono text-foreground text-[13px]">{row.total_interactions}</span> },
    { key: 'last_seen', label: 'Last Seen', sortable: true, render: (row: AttackerItem) => <span className="text-muted-foreground text-[11px] font-mono">{formatRelativeTime(row.last_seen as string)}</span> },
  ];

  if (loading) return <LoadingState message="Loading Phantom deception network..." />;

  const interactionHeatmap = buildInteractionHeatmap(interactions);
  const hasInteractions = interactions.length > 0;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-[22px] sm:text-[28px] font-bold text-foreground tracking-tight">Phantom Network</h1>
          <p className="text-sm text-muted-foreground mt-1 hidden sm:block">Honeypot orchestration, attacker profiling, and deception intelligence</p>
        </div>
        <Button
          variant="outline"
          onClick={() => setShowDeployModal(true)}
          className="shrink-0"
        >
          <Plus className="w-4 h-4" />
          <span className="hidden sm:inline">Deploy Honeypot</span>
          <span className="sm:hidden">Deploy</span>
        </Button>
      </div>

      {/* Interaction Activity Heatmap */}
      <Card className="overflow-hidden rounded-xl py-0">
        <CardHeader className="border-b border-border px-4 sm:px-6 py-4">
          <CardTitle className="text-[13px] font-medium uppercase tracking-wider">Interaction Activity</CardTitle>
          <CardDescription className="text-[11px] mt-0.5 hidden sm:block">Honeypot interaction density by hour and day of week</CardDescription>
        </CardHeader>
        <CardContent className="p-4 sm:p-6 overflow-x-auto">
          {!hasInteractions ? (
            <div className="h-32 flex items-center justify-center">
              <p className="text-muted-foreground/50 text-[13px]">No interaction data yet</p>
            </div>
          ) : (
            <>
              <div className="flex mb-1.5">
                <div className="w-10 shrink-0" />
                {HEATMAP_HOURS.map((h) => (
                  <div key={h} className="flex-1 min-w-[18px] text-center text-[9px] text-muted-foreground/50 font-mono">
                    {h % 6 === 0 ? `${String(h).padStart(2, '0')}` : ''}
                  </div>
                ))}
              </div>
              {HEATMAP_DAYS_PHANTOM.map((day, dayIdx) => (
                <div key={day} className="flex items-center mb-[3px]">
                  <div className="w-10 shrink-0 text-[10px] text-muted-foreground/50 font-medium">{day}</div>
                  {interactionHeatmap[dayIdx].map((value, hourIdx) => (
                    <div key={hourIdx} className="flex-1 min-w-[18px] px-[1px]">
                      <div
                        className={cn('h-[18px] rounded-[3px]', interactionHeatColor(value))}
                        title={`${day} ${String(hourIdx).padStart(2, '0')}:00 - ${value} interactions`}
                      />
                    </div>
                  ))}
                </div>
              ))}
              <div className="flex items-center gap-1.5 mt-3 justify-end">
                <span className="text-[9px] text-muted-foreground/50">Less</span>
                {[0, 1, 3, 5, 7].map((v) => (
                  <div key={v} className={cn('w-3 h-3 rounded-[2px]', interactionHeatColor(v))} />
                ))}
                <span className="text-[9px] text-muted-foreground/50">More</span>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Tab Section */}
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList variant="line" className="overflow-x-auto">
          {[
            { id: 'grid', label: 'Honeypots', icon: Ghost, count: honeypots.length },
            { id: 'interactions', label: 'Interactions', icon: CommandLineIcon, count: interactions.length },
            { id: 'attackers', label: 'Profiles', icon: UserIcon, count: attackers.length },
          ].map((t) => (
            <TabsTrigger key={t.id} value={t.id}>
              <t.icon className="w-4 h-4" size={16} />
              {t.label}
              <Badge variant="secondary" className="text-[10px] sm:text-[11px] px-1 sm:px-1.5 py-0.5 h-auto">{t.count}</Badge>
            </TabsTrigger>
          ))}
        </TabsList>

        {/* Honeypot Grid */}
        <TabsContent value="grid">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {honeypots.length === 0 ? (
              <Card className="col-span-full rounded-xl p-12 text-center">
                <Ghost className="w-12 h-12 text-muted-foreground/50 mx-auto mb-3 opacity-50" />
                <p className="text-muted-foreground text-[13px]">No honeypots deployed. Deploy your first decoy to start gathering threat intelligence.</p>
              </Card>
            ) : (
              honeypots.map((hp) => (
                <Card key={hp.id} className="rounded-xl p-4 py-4 hover:border-border/80 transition-all duration-200">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-[#22D3EE]/10 flex items-center justify-center">
                        <span className="text-[11px] font-bold text-[#22D3EE] font-mono">{typeIcons[hp.honeypot_type] || '?'}</span>
                      </div>
                      <div>
                        <p className="text-[13px] font-medium text-foreground">{hp.name}</p>
                        <p className="text-[11px] text-muted-foreground font-mono">{hp.ip_address}:{hp.port}</p>
                      </div>
                    </div>
                    <StatusIndicator status={hp.status} />
                  </div>

                  <div className="grid grid-cols-2 gap-3 mb-4">
                    <div className="bg-background border border-border rounded-lg p-2.5">
                      <p className="text-[10px] text-muted-foreground/50 uppercase tracking-wider font-medium">Interactions</p>
                      <p className="text-lg font-bold text-foreground font-mono mt-0.5">{hp.interactions_count}</p>
                    </div>
                    <div className="bg-background border border-border rounded-lg p-2.5">
                      <p className="text-[10px] text-muted-foreground/50 uppercase tracking-wider font-medium">Last Rotation</p>
                      <p className="text-[11px] text-muted-foreground mt-1.5">{hp.last_rotation ? formatRelativeTime(hp.last_rotation) : 'Never'}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleRotate(hp.id)}
                      disabled={hp.status === 'rotating'}
                      className="flex-1 text-[11px]"
                    >
                      <RotateCw className={cn('w-3 h-3', hp.status === 'rotating' && 'animate-spin')} />
                      Rotate
                    </Button>
                    <Button variant="outline" size="icon-sm" className="text-muted-foreground hover:text-[#EF4444]">
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  </div>
                </Card>
              ))
            )}
          </div>
        </TabsContent>

        {/* Interactions Feed */}
        <TabsContent value="interactions">
          <div className="space-y-3">
            {interactions.length === 0 ? (
              <Card className="rounded-xl p-12 text-center">
                <CommandLineIcon size={48} className="text-muted-foreground/50 mx-auto mb-3 opacity-50" />
                <p className="text-muted-foreground text-[13px]">No interactions captured yet. Deploy honeypots and wait for attackers.</p>
              </Card>
            ) : (
              interactions.map((ix) => (
                <Card key={ix.id} className="rounded-xl p-4 py-4 hover:border-border/80 transition-colors">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <Badge variant="outline" className="text-[10px] font-bold text-[#22D3EE] bg-[#22D3EE]/10 border-[#22D3EE]/20 font-mono uppercase tracking-wider">{ix.protocol}</Badge>
                      <span className="font-mono text-[#22D3EE] text-[13px]">{ix.source_ip}</span>
                    </div>
                    <div className="flex items-center gap-3 text-[11px] text-muted-foreground/50 font-mono">
                      {ix.session_duration && <span>{ix.session_duration}s</span>}
                      <span>{formatRelativeTime(ix.timestamp)}</span>
                    </div>
                  </div>
                  {ix.commands.length > 0 && (
                    <div className="bg-background border border-border rounded-lg p-3 mb-2">
                      <p className="text-[10px] text-muted-foreground/50 mb-1.5 font-medium uppercase tracking-wider">Commands Executed</p>
                      <div className="font-mono text-[11px] text-[#22C55E] space-y-0.5">
                        {ix.commands.map((cmd, i) => (
                          <p key={i}><span className="text-muted-foreground/50">$</span> {cmd}</p>
                        ))}
                      </div>
                    </div>
                  )}
                  {ix.credentials_tried.length > 0 && (
                    <div className="bg-background border border-border rounded-lg p-3">
                      <p className="text-[10px] text-muted-foreground/50 mb-1.5 font-medium uppercase tracking-wider">Credentials Attempted</p>
                      <div className="font-mono text-[11px] text-[#F59E0B] space-y-0.5">
                        {ix.credentials_tried.map((cred, i) => (
                          <p key={i}>{cred.username}:{cred.password}</p>
                        ))}
                      </div>
                    </div>
                  )}
                </Card>
              ))
            )}
          </div>
        </TabsContent>

        {/* Attacker Profiles */}
        <TabsContent value="attackers">
          <DataTable<AttackerItem>
            columns={attackerColumns}
            data={attackers}
            emptyMessage="No attacker profiles generated yet. Honeypot interactions will automatically generate profiles."
          />
        </TabsContent>
      </Tabs>

      {/* Deploy Modal */}
      <Modal open={showDeployModal} onClose={() => setShowDeployModal(false)} title="Deploy New Honeypot">
        <div className="space-y-4">
          <div>
            <label className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block mb-1.5">Name</label>
            <Input
              type="text"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="ssh-trap-02"
              className="font-mono"
            />
          </div>
          <div>
            <label className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block mb-1.5">Type</label>
            <select
              value={newType}
              onChange={(e) => {
                setNewType(e.target.value);
                const hp = HONEYPOT_TYPES.find((t) => t.value === e.target.value);
                if (hp) setNewPort(hp.defaultPort);
              }}
              className="w-full bg-card border border-border rounded-xl px-4 py-2.5 text-sm text-foreground focus:outline-none focus:border-ring"
            >
              {HONEYPOT_TYPES.map((t) => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider block mb-1.5">Port</label>
            <Input
              type="number"
              value={newPort}
              onChange={(e) => setNewPort(Number(e.target.value))}
              className="font-mono"
            />
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <Button variant="ghost" onClick={() => setShowDeployModal(false)}>
              Cancel
            </Button>
            <Button onClick={handleDeploy} className="bg-[#22D3EE] hover:bg-[#06B6D4] text-[#09090B]">
              <Ghost className="w-4 h-4" />
              Deploy
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
