'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Plus, Power, Trash2, Pencil, Beaker, FileText } from 'lucide-react';
import { api } from '@/lib/api';
import { cn, formatDate } from '@/lib/utils';
import { LoadingState } from '@/components/shared/LoadingState';
import { Modal } from '@/components/shared/Modal';
import { RuleEditor, RuleFormValues } from '@/components/firewall/RuleEditor';
import { RuleTester } from '@/components/firewall/RuleTester';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

interface FirewallRule {
  id: string;
  client_id: string;
  name: string;
  enabled: boolean;
  yaml_def: string;
  priority: number;
  hits: number;
  last_hit_at: string | null;
  created_at: string;
  updated_at: string;
}

interface FirewallTemplate {
  id: string;
  name: string;
  description: string;
  yaml_def: string;
}

const DEMO_RULES: FirewallRule[] = [
  {
    id: 'demo-1',
    client_id: 'demo',
    name: 'Block SSH brute force (demo)',
    enabled: true,
    priority: 100,
    yaml_def:
      'name: Block SSH brute force\nenabled: true\npriority: 100\nmatch:\n  - port: 22\n  - protocol: tcp\n  - rate_limit: { count: 5, window_seconds: 60 }\naction: block_ip\nduration_seconds: 3600\n',
    hits: 42,
    last_hit_at: new Date(Date.now() - 600000).toISOString(),
    created_at: new Date(Date.now() - 86400000).toISOString(),
    updated_at: new Date(Date.now() - 3600000).toISOString(),
  },
];

export default function FirewallPage() {
  const [rules, setRules] = useState<FirewallRule[]>([]);
  const [templates, setTemplates] = useState<FirewallTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [isDemo, setIsDemo] = useState(false);

  const [editorOpen, setEditorOpen] = useState(false);
  const [editing, setEditing] = useState<FirewallRule | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const [testerOpen, setTesterOpen] = useState(false);
  const [testerRule, setTesterRule] = useState<FirewallRule | null>(null);

  const [templatesOpen, setTemplatesOpen] = useState(false);

  const loadRules = useCallback(async () => {
    try {
      const data = await api.firewall.list();
      setRules(data);
      setIsDemo(false);
    } catch {
      setRules(DEMO_RULES);
      setIsDemo(true);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadTemplates = useCallback(async () => {
    try {
      const data = await api.firewall.templates();
      setTemplates(data);
    } catch {
      setTemplates([]);
    }
  }, []);

  useEffect(() => {
    loadRules();
    loadTemplates();
  }, [loadRules, loadTemplates]);

  const handleCreate = () => {
    setEditing(null);
    setEditorOpen(true);
  };

  const handleEdit = (rule: FirewallRule) => {
    setEditing(rule);
    setEditorOpen(true);
  };

  const handleSubmit = async (values: RuleFormValues) => {
    setSubmitting(true);
    try {
      if (editing) {
        await api.firewall.update(editing.id, values);
      } else {
        await api.firewall.create(values);
      }
      setEditorOpen(false);
      setEditing(null);
      await loadRules();
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Failed to save rule');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (rule: FirewallRule) => {
    if (!confirm(`Delete rule "${rule.name}"?`)) return;
    try {
      await api.firewall.delete(rule.id);
      await loadRules();
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Failed to delete rule');
    }
  };

  const handleToggle = async (rule: FirewallRule) => {
    try {
      await api.firewall.update(rule.id, { enabled: !rule.enabled });
      await loadRules();
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Failed to toggle rule');
    }
  };

  const handleTest = (rule: FirewallRule) => {
    setTesterRule(rule);
    setTesterOpen(true);
  };

  const handleCloneTemplate = async (tpl: FirewallTemplate) => {
    try {
      await api.firewall.create({
        name: tpl.name,
        enabled: true,
        priority: 100,
        yaml_def: tpl.yaml_def,
      });
      setTemplatesOpen(false);
      await loadRules();
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Failed to clone template');
    }
  };

  const sorted = useMemo(
    () => [...rules].sort((a, b) => b.priority - a.priority),
    [rules]
  );

  if (loading) return <LoadingState message="Loading firewall rules..." />;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-[22px] sm:text-[28px] font-bold text-foreground tracking-tight">
            Configurable Firewall
          </h1>
          <p className="text-sm text-muted-foreground mt-1 hidden sm:block">
            Rule engine with YAML DSL — block, allow, alert or quarantine based on live traffic
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Button variant="outline" onClick={() => setTemplatesOpen(true)} className="gap-1.5 text-[13px]">
            <FileText className="w-4 h-4" />
            <span className="hidden sm:inline">Templates</span>
          </Button>
          <Button variant="outline" onClick={handleCreate} className="gap-1.5 text-[13px]">
            <Plus className="w-4 h-4" />
            <span className="hidden sm:inline">New rule</span>
          </Button>
        </div>
      </div>

      {isDemo && (
        <div className="bg-[#F97316]/[0.06] border border-[#F97316]/20 text-[#F97316] rounded-xl px-4 py-3 text-[13px]">
          Running in demo mode — the backend did not respond, so a sample rule is shown. Rules you create will not persist until the API is reachable.
        </div>
      )}

      {/* Summary tiles */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatTile label="Total rules" value={rules.length} />
        <StatTile label="Enabled" value={rules.filter((r) => r.enabled).length} accent="#22C55E" />
        <StatTile label="Total hits" value={rules.reduce((acc, r) => acc + r.hits, 0)} accent="#22D3EE" />
        <StatTile label="Templates" value={templates.length} accent="#A855F7" />
      </div>

      {/* Rules list */}
      <Card className="rounded-xl">
        <div className="hidden md:grid grid-cols-[1fr_80px_80px_80px_160px_140px] gap-3 px-4 py-3 border-b border-border text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
          <div>Name</div>
          <div className="text-center">Enabled</div>
          <div className="text-center">Priority</div>
          <div className="text-center">Hits</div>
          <div>Updated</div>
          <div className="text-right">Actions</div>
        </div>

        {sorted.length === 0 && (
          <div className="px-4 py-10 text-center text-[13px] text-muted-foreground">
            No firewall rules yet. Start from a template or create one from scratch.
          </div>
        )}

        {sorted.map((rule) => (
          <div
            key={rule.id}
            className="grid grid-cols-1 md:grid-cols-[1fr_80px_80px_80px_160px_140px] gap-3 px-4 py-3 border-b border-border/30 last:border-b-0 hover:bg-muted/30 transition-colors items-center"
          >
            <div className="min-w-0">
              <div className="text-[13px] font-medium text-foreground truncate">{rule.name}</div>
              <div className="text-[11px] text-muted-foreground/60 font-mono truncate">
                action: {extractAction(rule.yaml_def) || '\u2014'}
              </div>
            </div>
            <div className="text-center">
              <button
                onClick={() => handleToggle(rule)}
                className={cn(
                  'w-11 h-6 rounded-full transition-colors relative',
                  rule.enabled ? 'bg-[#22C55E]/30' : 'bg-muted'
                )}
                aria-label={rule.enabled ? 'Disable rule' : 'Enable rule'}
              >
                <span
                  className={cn(
                    'absolute top-0.5 w-5 h-5 rounded-full transition-all',
                    rule.enabled ? 'left-[22px] bg-[#22C55E]' : 'left-0.5 bg-muted-foreground'
                  )}
                />
              </button>
            </div>
            <div className="text-center font-mono text-[12px] text-foreground">
              {rule.priority}
            </div>
            <div className="text-center font-mono text-[12px] text-foreground">
              {rule.hits}
            </div>
            <div className="text-[11px] text-muted-foreground font-mono">
              {formatDate(rule.updated_at)}
            </div>
            <div className="flex justify-end gap-1">
              <Button variant="ghost" size="icon-xs" onClick={() => handleTest(rule)} title="Test rule" className="text-muted-foreground hover:text-[#22D3EE]">
                <Beaker className="w-4 h-4" />
              </Button>
              <Button variant="ghost" size="icon-xs" onClick={() => handleEdit(rule)} title="Edit" className="text-muted-foreground hover:text-foreground">
                <Pencil className="w-4 h-4" />
              </Button>
              <Button variant="ghost" size="icon-xs" onClick={() => handleToggle(rule)} title={rule.enabled ? 'Disable' : 'Enable'} className="text-muted-foreground hover:text-[#F97316]">
                <Power className="w-4 h-4" />
              </Button>
              <Button variant="ghost" size="icon-xs" onClick={() => handleDelete(rule)} title="Delete" className="text-muted-foreground hover:text-[#EF4444]">
                <Trash2 className="w-4 h-4" />
              </Button>
            </div>
          </div>
        ))}
      </Card>

      {/* Editor modal */}
      <Modal
        open={editorOpen}
        onClose={() => {
          setEditorOpen(false);
          setEditing(null);
        }}
        title={editing ? 'Edit firewall rule' : 'New firewall rule'}
        size="lg"
      >
        <RuleEditor
          initial={
            editing
              ? {
                  name: editing.name,
                  enabled: editing.enabled,
                  priority: editing.priority,
                  yaml_def: editing.yaml_def,
                }
              : undefined
          }
          onSubmit={handleSubmit}
          onCancel={() => {
            setEditorOpen(false);
            setEditing(null);
          }}
          submitting={submitting}
        />
      </Modal>

      {/* Tester modal */}
      <Modal
        open={testerOpen}
        onClose={() => {
          setTesterOpen(false);
          setTesterRule(null);
        }}
        title={testerRule ? `Test: ${testerRule.name}` : 'Test rule'}
        size="lg"
      >
        {testerRule && (
          <RuleTester ruleId={testerRule.id} yamlDef={testerRule.yaml_def} />
        )}
      </Modal>

      {/* Templates modal */}
      <Modal
        open={templatesOpen}
        onClose={() => setTemplatesOpen(false)}
        title="Rule templates"
        size="lg"
      >
        <div className="space-y-3">
          {templates.length === 0 && (
            <p className="text-[13px] text-muted-foreground">No templates available.</p>
          )}
          {templates.map((tpl) => (
            <Card key={tpl.id} className="rounded-xl hover:ring-[#22D3EE]/20 hover:ring-1 transition-all">
              <CardContent className="p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <h3 className="text-[13px] font-medium text-foreground">{tpl.name}</h3>
                    <p className="text-[11px] text-muted-foreground mt-1">{tpl.description}</p>
                  </div>
                  <Button
                    onClick={() => handleCloneTemplate(tpl)}
                    size="sm"
                    className="bg-[#22D3EE] hover:bg-[#06B6D4] text-[#09090B] font-semibold"
                  >
                    Use
                  </Button>
                </div>
                <pre className="mt-3 bg-black/40 border border-border rounded-lg p-3 text-[11px] text-muted-foreground font-mono overflow-x-auto">
                  {tpl.yaml_def}
                </pre>
              </CardContent>
            </Card>
          ))}
        </div>
      </Modal>
    </div>
  );
}

function StatTile({
  label,
  value,
  accent = '#E5E5E5',
}: {
  label: string;
  value: number;
  accent?: string;
}) {
  return (
    <Card className="rounded-xl px-4 py-4">
      <div className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
        {label}
      </div>
      <div
        className="mt-1 text-2xl font-semibold font-mono"
        style={{ color: accent }}
      >
        {value}
      </div>
    </Card>
  );
}

function extractAction(yaml: string): string | null {
  const m = yaml.match(/^action:\s*(\S+)/m);
  return m ? m[1] : null;
}
