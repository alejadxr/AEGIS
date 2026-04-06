import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { Severity, Sophistication } from './types';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function severityColor(severity: Severity): string {
  const map: Record<Severity, string> = {
    critical: 'text-danger',
    high: 'text-warning',
    medium: 'text-yellow-400',
    low: 'text-info',
    info: 'text-text-muted',
  };
  return map[severity] || 'text-text-muted';
}

export function severityBgColor(severity: Severity): string {
  const map: Record<Severity, string> = {
    critical: 'bg-danger/10 text-danger border-danger/30',
    high: 'bg-warning/10 text-warning border-warning/30',
    medium: 'bg-yellow-400/10 text-yellow-400 border-yellow-400/30',
    low: 'bg-info/10 text-info border-info/30',
    info: 'bg-text-muted/10 text-text-muted border-text-muted/30',
  };
  return map[severity] || 'bg-text-muted/10 text-text-muted border-text-muted/30';
}

export function sophisticationColor(level: Sophistication): string {
  const map: Record<Sophistication, string> = {
    script_kiddie: 'text-success',
    intermediate: 'text-warning',
    advanced: 'text-danger',
    apt: 'text-purple',
  };
  return map[level] || 'text-text-muted';
}

export function formatDate(date: string | null): string {
  if (!date) return 'N/A';
  return new Date(date).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: true,
  });
}

export function formatRelativeTime(date: string): string {
  const now = new Date();
  const then = new Date(date);
  const seconds = Math.floor((now.getTime() - then.getTime()) / 1000);

  if (seconds < 0) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return formatDate(date);
}

export function formatNumber(num: number): string {
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
  return num.toString();
}

export function riskScoreColor(score: number): string {
  if (score >= 9) return 'text-danger';
  if (score >= 7) return 'text-warning';
  if (score >= 4) return 'text-yellow-400';
  return 'text-success';
}

export function truncate(str: string, len: number): string {
  if (str.length <= len) return str;
  return str.slice(0, len) + '...';
}
