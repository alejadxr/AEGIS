'use client';

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { RefreshCw } from 'lucide-react';
import { LoadingState } from '@/components/shared/LoadingState';
import { api } from '@/lib/api';
import { cn } from '@/lib/utils';

/* ──────────────────────────────────────────
   Types
   ────────────────────────────────────────── */

interface Asset {
  id: string;
  hostname: string;
  ip_address: string;
  asset_type: string;
  ports: number[];
  technologies: string[];
  status: string;
  risk_score: number;
  last_scan_at: string | null;
}

interface GraphNode {
  id: string;
  label: string;
  subtitle: string;
  risk: number;
  type: 'internet' | 'external' | 'internal' | 'database' | 'api';
  asset?: Asset;
  x: number;
  y: number;
  vx: number;
  vy: number;
}

interface GraphEdge {
  source: string;
  target: string;
  risk: number;
}

/* ──────────────────────────────────────────
   Risk helpers
   ────────────────────────────────────────── */

function riskColor(score: number): string {
  if (score >= 9) return '#EF4444'; // critical red
  if (score >= 7) return '#F97316'; // high orange
  if (score >= 4) return '#EAB308'; // medium yellow
  return '#22C55E'; // low green
}

function riskLabel(score: number): string {
  if (score >= 9) return 'Critical';
  if (score >= 7) return 'High';
  if (score >= 4) return 'Medium';
  return 'Low';
}

function riskGlow(score: number): string {
  if (score >= 9) return 'drop-shadow(0 0 8px rgba(239,68,68,0.5))';
  if (score >= 7) return 'drop-shadow(0 0 6px rgba(249,115,22,0.4))';
  if (score >= 4) return 'drop-shadow(0 0 4px rgba(234,179,8,0.3))';
  return 'drop-shadow(0 0 4px rgba(34,197,94,0.3))';
}

function nodeRadius(score: number): number {
  if (score >= 9) return 28;
  if (score >= 7) return 24;
  if (score >= 4) return 20;
  return 16;
}

const EXTERNAL_PORTS = new Set([80, 443, 3000, 3001, 3002, 3003, 3006, 3007, 8080, 8888]);
const DB_PORTS = new Set([5432, 3306, 27017, 6379, 11211]);
const API_PORTS = new Set([8000, 8080, 8443, 9000, 11434]);

function classifyNode(asset: Asset): GraphNode['type'] {
  const hasExternalPort = asset.ports.some((p) => EXTERNAL_PORTS.has(p));
  const hasDBPort = asset.ports.some((p) => DB_PORTS.has(p));
  const hasAPIPort = asset.ports.some((p) => API_PORTS.has(p));

  if (hasDBPort) return 'database';
  if (hasAPIPort && !hasExternalPort) return 'api';
  if (hasExternalPort) return 'external';
  return 'internal';
}

/* ──────────────────────────────────────────
   Build graph from assets
   ────────────────────────────────────────── */

function buildGraph(assets: Asset[]): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  // Internet entry node
  nodes.push({
    id: 'internet',
    label: 'Internet',
    subtitle: 'Entry Point',
    risk: 0,
    type: 'internet',
    x: 0,
    y: 0,
    vx: 0,
    vy: 0,
  });

  // Create nodes for each asset
  for (const asset of assets) {
    const portsList = asset.ports.slice(0, 3).join(', ');
    const portsLabel = asset.ports.length > 3 ? `${portsList}...` : portsList;

    nodes.push({
      id: asset.id,
      label: asset.hostname || asset.ip_address,
      subtitle: portsLabel ? `Ports: ${portsLabel}` : asset.asset_type,
      risk: asset.risk_score,
      type: classifyNode(asset),
      asset,
      x: 0,
      y: 0,
      vx: 0,
      vy: 0,
    });
  }

  // Build edges: Internet -> external-facing services
  const externalNodes = nodes.filter((n) => n.type === 'external');
  const internalNodes = nodes.filter((n) => n.type === 'internal' || n.type === 'api');
  const dbNodes = nodes.filter((n) => n.type === 'database');

  for (const ext of externalNodes) {
    edges.push({ source: 'internet', target: ext.id, risk: ext.risk });
  }

  // External -> internal/api (same IP = connected, or if there are lateral movement paths)
  for (const ext of externalNodes) {
    for (const int of internalNodes) {
      if (ext.asset && int.asset && ext.asset.ip_address === int.asset.ip_address) {
        edges.push({ source: ext.id, target: int.id, risk: Math.max(ext.risk, int.risk) });
      }
    }
    // External -> databases (same IP)
    for (const db of dbNodes) {
      if (ext.asset && db.asset && ext.asset.ip_address === db.asset.ip_address) {
        edges.push({ source: ext.id, target: db.id, risk: Math.max(ext.risk, db.risk) });
      }
    }
  }

  // Internal/API -> databases (same IP)
  for (const int of internalNodes) {
    for (const db of dbNodes) {
      if (int.asset && db.asset && int.asset.ip_address === db.asset.ip_address) {
        edges.push({ source: int.id, target: db.id, risk: Math.max(int.risk, db.risk) });
      }
    }
  }

  // If no external nodes found, connect internet directly to all nodes
  if (externalNodes.length === 0) {
    for (const node of nodes) {
      if (node.id !== 'internet') {
        edges.push({ source: 'internet', target: node.id, risk: node.risk });
      }
    }
  }

  // Connect orphans (nodes with no edges) to internet
  const connected = new Set<string>();
  for (const e of edges) {
    connected.add(e.source);
    connected.add(e.target);
  }
  for (const node of nodes) {
    if (!connected.has(node.id) && node.id !== 'internet') {
      edges.push({ source: 'internet', target: node.id, risk: node.risk });
    }
  }

  return { nodes, edges };
}

/* ──────────────────────────────────────────
   Simple force-directed layout (runs N iterations)
   ────────────────────────────────────────── */

function layoutGraph(
  nodes: GraphNode[],
  edges: GraphEdge[],
  width: number,
  height: number
): GraphNode[] {
  const ITERATIONS = 120;
  const REPULSION = 8000;
  const ATTRACTION = 0.005;
  const DAMPING = 0.85;
  const IDEAL_LENGTH = 140;

  // Initialize positions in a spread-out pattern
  const centerX = width / 2;
  const centerY = height / 2;

  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i];
    if (node.id === 'internet') {
      node.x = centerX;
      node.y = 60;
    } else {
      const angle = (i / (nodes.length - 1)) * Math.PI * 1.5 - Math.PI * 0.25;
      const radius = 120 + Math.random() * 100;
      node.x = centerX + Math.cos(angle) * radius;
      node.y = centerY + Math.sin(angle) * radius * 0.7 + 40;
    }
    node.vx = 0;
    node.vy = 0;
  }

  const nodeMap = new Map(nodes.map((n) => [n.id, n]));

  for (let iter = 0; iter < ITERATIONS; iter++) {
    // Repulsion between all pairs
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
        const force = REPULSION / (dist * dist);
        dx = (dx / dist) * force;
        dy = (dy / dist) * force;
        a.vx -= dx;
        a.vy -= dy;
        b.vx += dx;
        b.vy += dy;
      }
    }

    // Attraction along edges
    for (const edge of edges) {
      const a = nodeMap.get(edge.source);
      const b = nodeMap.get(edge.target);
      if (!a || !b) continue;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const force = (dist - IDEAL_LENGTH) * ATTRACTION;
      const fx = (dx / Math.max(dist, 1)) * force;
      const fy = (dy / Math.max(dist, 1)) * force;
      a.vx += fx;
      a.vy += fy;
      b.vx -= fx;
      b.vy -= fy;
    }

    // Apply velocities with damping
    for (const node of nodes) {
      if (node.id === 'internet') continue; // Keep internet fixed at top
      node.vx *= DAMPING;
      node.vy *= DAMPING;
      node.x += node.vx;
      node.y += node.vy;
      // Clamp to bounds
      const r = 30;
      node.x = Math.max(r, Math.min(width - r, node.x));
      node.y = Math.max(r, Math.min(height - r, node.y));
    }
  }

  return nodes;
}

/* ──────────────────────────────────────────
   Node icon paths (SVG)
   ────────────────────────────────────────── */

function NodeIcon({ type, x, y }: { type: GraphNode['type']; x: number; y: number }) {
  const size = 10;
  const ox = x - size / 2;
  const oy = y - size / 2;

  switch (type) {
    case 'internet':
      return (
        <g transform={`translate(${ox}, ${oy})`}>
          <circle cx={5} cy={5} r={4} fill="none" stroke="currentColor" strokeWidth={1.2} />
          <ellipse cx={5} cy={5} rx={2} ry={4} fill="none" stroke="currentColor" strokeWidth={0.8} />
          <line x1={1} y1={5} x2={9} y2={5} stroke="currentColor" strokeWidth={0.8} />
        </g>
      );
    case 'database':
      return (
        <g transform={`translate(${ox}, ${oy})`}>
          <ellipse cx={5} cy={2.5} rx={4} ry={1.5} fill="none" stroke="currentColor" strokeWidth={1} />
          <path d="M1 2.5v5c0 .83 1.79 1.5 4 1.5s4-.67 4-1.5v-5" fill="none" stroke="currentColor" strokeWidth={1} />
          <path d="M1 5c0 .83 1.79 1.5 4 1.5s4-.67 4-1.5" fill="none" stroke="currentColor" strokeWidth={0.8} />
        </g>
      );
    case 'api':
      return (
        <g transform={`translate(${ox}, ${oy})`}>
          <rect x={1} y={1} width={8} height={8} rx={1.5} fill="none" stroke="currentColor" strokeWidth={1} />
          <path d="M3.5 4L5 5.5 6.5 4" fill="none" stroke="currentColor" strokeWidth={0.8} />
          <line x1={5} y1={3} x2={5} y2={5.5} stroke="currentColor" strokeWidth={0.8} />
        </g>
      );
    default: // external, internal
      return (
        <g transform={`translate(${ox}, ${oy})`}>
          <rect x={0.5} y={1} width={9} height={6} rx={1} fill="none" stroke="currentColor" strokeWidth={1} />
          <line x1={3} y1={8} x2={7} y2={8} stroke="currentColor" strokeWidth={1} />
          <line x1={5} y1={7} x2={5} y2={8} stroke="currentColor" strokeWidth={1} />
        </g>
      );
  }
}

/* ──────────────────────────────────────────
   Main Page Component
   ────────────────────────────────────────── */

export default function AttackPathPage() {
  const [loading, setLoading] = useState(true);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const fetchAssets = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.surface.assets();
      setAssets(data);
    } catch {
      setAssets([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAssets();
  }, [fetchAssets]);

  // Build and layout graph
  const { nodes, edges } = useMemo(() => {
    if (assets.length === 0) return { nodes: [], edges: [] };
    const graph = buildGraph(assets);
    const W = 800;
    const H = 560;
    layoutGraph(graph.nodes, graph.edges, W, H);
    return graph;
  }, [assets]);

  const nodeMap = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  // Stats
  const stats = useMemo(() => {
    const criticalPaths = edges.filter((e) => e.risk >= 9).length;
    const highPaths = edges.filter((e) => e.risk >= 7 && e.risk < 9).length;
    const entryPoints = edges.filter((e) => e.source === 'internet').length;
    const maxDepth = (() => {
      // BFS from internet
      const adj = new Map<string, string[]>();
      for (const e of edges) {
        if (!adj.has(e.source)) adj.set(e.source, []);
        adj.get(e.source)!.push(e.target);
      }
      const visited = new Set<string>();
      const queue: [string, number][] = [['internet', 0]];
      let max = 0;
      while (queue.length > 0) {
        const [node, depth] = queue.shift()!;
        if (visited.has(node)) continue;
        visited.add(node);
        max = Math.max(max, depth);
        for (const neighbor of adj.get(node) || []) {
          if (!visited.has(neighbor)) queue.push([neighbor, depth + 1]);
        }
      }
      return max;
    })();
    return { criticalPaths, highPaths, entryPoints, maxDepth };
  }, [edges]);

  const handleMouseMove = useCallback(
    (e: React.MouseEvent<SVGSVGElement>) => {
      if (!svgRef.current || !containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      setTooltipPos({ x: e.clientX - rect.left, y: e.clientY - rect.top });
    },
    []
  );

  if (loading) return <LoadingState message="Building attack graph..." />;

  const SVG_W = 800;
  const SVG_H = 560;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-[22px] sm:text-[28px] font-bold text-foreground tracking-tight">Attack Path</h1>
          <p className="hidden sm:block text-sm text-muted-foreground mt-1">
            Visualize potential lateral movement paths through your infrastructure
          </p>
        </div>
        <button
          onClick={fetchAssets}
          className="flex items-center gap-2 bg-white/[0.05] border border-border hover:border-[#22D3EE]/20 text-foreground/80 hover:text-[#22D3EE] px-4 py-2 rounded-xl transition-all text-[13px] font-medium shrink-0"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Entry Points', value: stats.entryPoints, color: '#22D3EE' },
          { label: 'Critical Paths', value: stats.criticalPaths, color: '#EF4444' },
          { label: 'High Risk Paths', value: stats.highPaths, color: '#F97316' },
          { label: 'Max Depth', value: stats.maxDepth, color: '#A855F7' },
        ].map((stat) => (
          <div key={stat.label} className="bg-card border border-border rounded-2xl p-4">
            <p className="text-[11px] text-muted-foreground font-medium uppercase tracking-wider">{stat.label}</p>
            <p className="text-[24px] font-bold mt-1" style={{ color: stat.color }}>
              {stat.value}
            </p>
          </div>
        ))}
      </div>

      {/* Graph Card */}
      <div
        ref={containerRef}
        className="bg-card border border-border rounded-2xl overflow-hidden relative"
      >
        {assets.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-muted-foreground">
            <p className="text-[14px] font-medium">No assets discovered yet</p>
            <p className="text-[12px] mt-1">Run a surface scan to populate the attack graph</p>
          </div>
        ) : (
          <>
            <svg
              ref={svgRef}
              viewBox={`0 0 ${SVG_W} ${SVG_H}`}
              className="w-full h-auto"
              style={{ minHeight: 400 }}
              onMouseMove={handleMouseMove}
            >
              <defs>
                {/* Animated dash pattern */}
                <style>
                  {`
                    @keyframes dashMove {
                      to { stroke-dashoffset: -20; }
                    }
                    .edge-line {
                      animation: dashMove 1.5s linear infinite;
                    }
                    .edge-line-critical {
                      animation: dashMove 0.8s linear infinite;
                    }
                  `}
                </style>

                {/* Glow filter */}
                <filter id="glow-critical">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
                <filter id="glow-high">
                  <feGaussianBlur stdDeviation="2" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>

                {/* Arrow marker */}
                <marker id="arrow" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto" fill="#52525B">
                  <path d="M0,0 L8,3 L0,6 Z" />
                </marker>
                <marker id="arrow-critical" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto" fill="#EF4444">
                  <path d="M0,0 L8,3 L0,6 Z" />
                </marker>
                <marker id="arrow-high" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto" fill="#F97316">
                  <path d="M0,0 L8,3 L0,6 Z" />
                </marker>
              </defs>

              {/* Background grid */}
              <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth="0.5" />
              </pattern>
              <rect width={SVG_W} height={SVG_H} fill="url(#grid)" />

              {/* Edges */}
              {edges.map((edge, i) => {
                const source = nodeMap.get(edge.source);
                const target = nodeMap.get(edge.target);
                if (!source || !target) return null;

                const isCritical = edge.risk >= 9;
                const isHigh = edge.risk >= 7;
                const color = riskColor(edge.risk);

                // Shorten line to stop at node radius
                const dx = target.x - source.x;
                const dy = target.y - source.y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                const targetR = nodeRadius(target.risk) + 4;
                const sourceR = nodeRadius(source.risk) + 4;
                const ratio1 = sourceR / Math.max(dist, 1);
                const ratio2 = targetR / Math.max(dist, 1);
                const x1 = source.x + dx * ratio1;
                const y1 = source.y + dy * ratio1;
                const x2 = target.x - dx * ratio2;
                const y2 = target.y - dy * ratio2;

                return (
                  <line
                    key={`edge-${i}`}
                    x1={x1}
                    y1={y1}
                    x2={x2}
                    y2={y2}
                    stroke={color}
                    strokeWidth={isCritical ? 2 : isHigh ? 1.5 : 1}
                    strokeOpacity={isCritical ? 0.7 : isHigh ? 0.5 : 0.25}
                    strokeDasharray="6 4"
                    className={isCritical ? 'edge-line-critical' : 'edge-line'}
                    markerEnd={isCritical ? 'url(#arrow-critical)' : isHigh ? 'url(#arrow-high)' : 'url(#arrow)'}
                    filter={isCritical ? 'url(#glow-critical)' : undefined}
                  />
                );
              })}

              {/* Nodes */}
              {nodes.map((node) => {
                const r = node.id === 'internet' ? 22 : nodeRadius(node.risk);
                const color = node.id === 'internet' ? '#22D3EE' : riskColor(node.risk);
                const isHovered = hoveredNode?.id === node.id;

                return (
                  <g
                    key={node.id}
                    onMouseEnter={() => setHoveredNode(node)}
                    onMouseLeave={() => setHoveredNode(null)}
                    className="cursor-pointer"
                    style={{ filter: isHovered ? riskGlow(node.risk) : undefined }}
                  >
                    {/* Outer ring */}
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={r + 3}
                      fill="none"
                      stroke={color}
                      strokeWidth={isHovered ? 1.5 : 0.5}
                      strokeOpacity={isHovered ? 0.6 : 0.15}
                    />
                    {/* Main circle */}
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={r}
                      fill={`${color}10`}
                      stroke={color}
                      strokeWidth={isHovered ? 2 : 1}
                      strokeOpacity={isHovered ? 1 : 0.6}
                    />
                    {/* Icon */}
                    <g style={{ color }}>
                      <NodeIcon type={node.type} x={node.x} y={node.y - 3} />
                    </g>
                    {/* Label */}
                    <text
                      x={node.x}
                      y={node.y + r + 14}
                      textAnchor="middle"
                      fill="#FAFAFA"
                      fontSize={11}
                      fontWeight={500}
                      fontFamily="var(--font-outfit), sans-serif"
                    >
                      {node.label.length > 18 ? node.label.slice(0, 16) + '...' : node.label}
                    </text>
                    {/* Risk badge */}
                    {node.id !== 'internet' && (
                      <text
                        x={node.x}
                        y={node.y + r + 26}
                        textAnchor="middle"
                        fill={color}
                        fontSize={9}
                        fontFamily="var(--font-azeret), monospace"
                        opacity={0.8}
                      >
                        {riskLabel(node.risk)} ({node.risk.toFixed(1)})
                      </text>
                    )}
                  </g>
                );
              })}
            </svg>

            {/* Hover tooltip */}
            {hoveredNode && hoveredNode.asset && (
              <div
                className="absolute z-50 pointer-events-none"
                style={{
                  left: Math.min(tooltipPos.x + 16, (containerRef.current?.clientWidth || 600) - 260),
                  top: tooltipPos.y - 10,
                }}
              >
                <div className="bg-[#09090B] border border-white/[0.08] rounded-xl p-3 shadow-2xl min-w-[220px]">
                  <p className="text-[13px] font-semibold text-foreground">{hoveredNode.asset.hostname}</p>
                  <p className="text-[11px] text-muted-foreground font-mono mt-0.5">{hoveredNode.asset.ip_address}</p>
                  <div className="mt-2 space-y-1">
                    <div className="flex justify-between text-[11px]">
                      <span className="text-muted-foreground">Type</span>
                      <span className="text-foreground/80">{hoveredNode.asset.asset_type}</span>
                    </div>
                    <div className="flex justify-between text-[11px]">
                      <span className="text-muted-foreground">Ports</span>
                      <span className="text-foreground/80 font-mono">{hoveredNode.asset.ports.join(', ') || 'None'}</span>
                    </div>
                    <div className="flex justify-between text-[11px]">
                      <span className="text-muted-foreground">Risk Score</span>
                      <span className="font-mono font-semibold" style={{ color: riskColor(hoveredNode.asset.risk_score) }}>
                        {hoveredNode.asset.risk_score.toFixed(1)}
                      </span>
                    </div>
                    <div className="flex justify-between text-[11px]">
                      <span className="text-muted-foreground">Status</span>
                      <span className={cn(
                        'text-[10px] font-medium px-1.5 py-0.5 rounded',
                        hoveredNode.asset.status === 'active'
                          ? 'bg-[#22C55E]/10 text-[#22C55E]'
                          : 'bg-zinc-800 text-muted-foreground'
                      )}>
                        {hoveredNode.asset.status}
                      </span>
                    </div>
                    {hoveredNode.asset.technologies.length > 0 && (
                      <div className="flex justify-between text-[11px]">
                        <span className="text-muted-foreground">Tech</span>
                        <span className="text-foreground/80 text-right max-w-[140px] truncate">
                          {hoveredNode.asset.technologies.join(', ')}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* Legend */}
            <div className="absolute bottom-4 left-4 flex items-center gap-4 bg-[#09090B]/80 backdrop-blur-sm border border-border rounded-xl px-4 py-2">
              {[
                { label: 'Low', color: '#22C55E' },
                { label: 'Medium', color: '#EAB308' },
                { label: 'High', color: '#F97316' },
                { label: 'Critical', color: '#EF4444' },
              ].map((item) => (
                <div key={item.label} className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-[10px] text-muted-foreground font-medium">{item.label}</span>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      {/* Asset Breakdown */}
      {assets.length > 0 && (
        <div className="bg-card border border-border rounded-2xl overflow-hidden">
          <div className="px-4 sm:px-6 py-4 border-b border-border">
            <h3 className="text-[14px] font-semibold text-foreground">Path Nodes</h3>
            <p className="text-[12px] text-muted-foreground mt-0.5">Assets ordered by risk exposure</p>
          </div>
          <div className="divide-y divide-white/[0.03]">
            {[...assets]
              .sort((a, b) => b.risk_score - a.risk_score)
              .slice(0, 10)
              .map((asset) => (
                <div key={asset.id} className="flex items-center justify-between px-4 sm:px-6 py-3 hover:bg-white/[0.02] transition-colors">
                  <div className="flex items-center gap-3 min-w-0">
                    <span
                      className="w-2 h-2 rounded-full shrink-0"
                      style={{ backgroundColor: riskColor(asset.risk_score) }}
                    />
                    <div className="min-w-0">
                      <p className="text-[13px] text-foreground font-medium truncate">{asset.hostname}</p>
                      <p className="text-[11px] text-muted-foreground font-mono">{asset.ip_address}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 shrink-0">
                    <span className="text-[11px] text-muted-foreground font-mono hidden sm:block">
                      {asset.ports.slice(0, 4).join(', ')}
                    </span>
                    <span
                      className="text-[12px] font-mono font-semibold min-w-[50px] text-right"
                      style={{ color: riskColor(asset.risk_score) }}
                    >
                      {asset.risk_score.toFixed(1)}
                    </span>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}
