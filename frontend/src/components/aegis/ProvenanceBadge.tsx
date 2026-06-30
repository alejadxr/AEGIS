'use client';

import * as React from 'react';
import { StatusBadge } from './StatusBadge';

/**
 * ProvenanceBadge — telemetry attribution tag.
 *
 * Use to show WHO/WHAT generated a detection or action: an algorithmic rule,
 * an AI agent, a honeypot interaction, or a legacy log line.
 *
 * Built on StatusBadge so all severity / status colors stay consistent.
 */
export type Provenance = 'algorithm' | 'agent' | 'honeypot' | 'legacy' | 'rule' | 'manual';

export interface ProvenanceBadgeProps {
  source: Provenance;
  /** Optional override label; defaults to the source name. */
  label?: string;
  size?: 'sm' | 'md';
}

const SOURCE_MAP: Record<Provenance, { variant: React.ComponentProps<typeof StatusBadge>['variant']; label: string }> = {
  algorithm: { variant: 'info', label: 'Algorithm' },
  agent: { variant: 'accent', label: 'Agent' },
  honeypot: { variant: 'warning', label: 'Honeypot' },
  legacy: { variant: 'muted', label: 'Legacy' },
  rule: { variant: 'info', label: 'Rule' },
  manual: { variant: 'muted', label: 'Manual' },
};

export function ProvenanceBadge({ source, label, size = 'sm' }: ProvenanceBadgeProps) {
  const cfg = SOURCE_MAP[source];
  return (
    <StatusBadge variant={cfg.variant} size={size} title={`Source: ${cfg.label}`}>
      {label ?? cfg.label}
    </StatusBadge>
  );
}
