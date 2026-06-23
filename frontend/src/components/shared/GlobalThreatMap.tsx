'use client';

/**
 * GlobalThreatMap (v1.6.3+) — thin re-export of AsciiThreatMap.
 *
 * The previous SVG/react-simple-maps implementation was replaced with an
 * ASCII retro CRT-style map. This file is kept as a re-export so existing
 * dynamic imports (`@/components/shared/GlobalThreatMap`) keep working
 * without churn.
 */

export type { ThreatMapEntry, AsciiThreatMapProps as GlobalThreatMapProps } from './AsciiThreatMap';
export { AsciiThreatMap as GlobalThreatMap } from './AsciiThreatMap';
