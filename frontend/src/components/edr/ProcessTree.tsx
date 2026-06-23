'use client';

/**
 * Collapsible process tree viewer for the EDR module.
 *
 * Deliberately avoids pulling in D3 directly — the backend already returns
 * the tree pre-built, and our dataset is small (O(hundreds)), so a plain
 * recursive React tree is cheaper and lighter on the bundle than d3-hierarchy.
 */

import { useState } from 'react';
import { ChevronDown, ChevronRight, Terminal, User } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface ProcessTreeNode {
  pid: number;
  ppid?: number | null;
  name?: string | null;
  path?: string | null;
  command_line?: string | null;
  user?: string | null;
  started_at?: string | null;
  event_kind?: string | null;
  children?: ProcessTreeNode[];
  truncated?: boolean;
}

interface Props {
  anchor: ProcessTreeNode;
  ancestors: ProcessTreeNode[];  // closest parent first
  descendants: ProcessTreeNode;  // the anchor, with nested .children
}

export function ProcessTree({ anchor, ancestors, descendants }: Props) {
  return (
    <div className="font-mono text-xs">
      {ancestors.length > 0 && (
        <div className="mb-3 pb-3 border-b border-white/[0.04]">
          <h3 className="text-[10px] uppercase tracking-wider text-zinc-500 mb-2">
            Ancestors
          </h3>
          <div className="pl-4 border-l border-zinc-700/60 space-y-1">
            {[...ancestors].reverse().map((a) => (
              <NodeRow
                key={`anc-${a.pid}`}
                node={a}
                highlighted={false}
              />
            ))}
          </div>
        </div>
      )}

      <h3 className="text-[10px] uppercase tracking-wider text-zinc-500 mb-2">
        Descendants (rooted at pid {anchor.pid})
      </h3>
      <TreeNode node={descendants} depth={0} highlightedPid={anchor.pid} />
    </div>
  );
}

function TreeNode({
  node,
  depth,
  highlightedPid,
}: {
  node: ProcessTreeNode;
  depth: number;
  highlightedPid: number;
}) {
  const [open, setOpen] = useState(depth < 3);
  const hasChildren = (node.children?.length ?? 0) > 0;
  const highlighted = node.pid === highlightedPid;

  return (
    <div>
      <div className="flex items-start">
        {hasChildren ? (
          <button
            onClick={() => setOpen((v) => !v)}
            className="p-0.5 text-zinc-500 hover:text-zinc-300 mr-1"
          >
            {open ? (
              <ChevronDown className="w-3 h-3" />
            ) : (
              <ChevronRight className="w-3 h-3" />
            )}
          </button>
        ) : (
          <span className="w-4 mr-1" />
        )}
        <NodeRow node={node} highlighted={highlighted} />
      </div>
      {hasChildren && open && (
        <div
          className="ml-4 pl-3 border-l border-zinc-700/60"
          style={{ marginLeft: `${Math.min(depth * 0.5, 3)}rem` }}
        >
          {node.children!.map((c) => (
            <TreeNode
              key={c.pid}
              node={c}
              depth={depth + 1}
              highlightedPid={highlightedPid}
            />
          ))}
          {node.truncated && (
            <div className="text-zinc-600 italic pl-2">... truncated ...</div>
          )}
        </div>
      )}
    </div>
  );
}

function NodeRow({
  node,
  highlighted,
}: {
  node: ProcessTreeNode;
  highlighted: boolean;
}) {
  const name = node.name ?? '<unknown>';
  return (
    <div
      className={cn(
        'flex flex-wrap items-center gap-2 px-2 py-1 rounded',
        highlighted
          ? 'bg-cyan-500/10 border border-cyan-500/40 text-cyan-100'
          : 'border border-transparent hover:bg-white/[0.02] text-zinc-300',
      )}
    >
      <Terminal className="w-3 h-3 text-zinc-500 shrink-0" />
      <span className="text-zinc-100 truncate">{name}</span>
      <span className="text-zinc-500">pid={node.pid}</span>
      {node.ppid != null && (
        <span className="text-zinc-600">ppid={node.ppid}</span>
      )}
      {node.user && (
        <span className="text-zinc-500 flex items-center gap-1">
          <User className="w-3 h-3" />
          {node.user}
        </span>
      )}
      {node.command_line && (
        <span
          className="text-zinc-600 truncate max-w-xl"
          title={node.command_line}
        >
          {node.command_line}
        </span>
      )}
    </div>
  );
}
