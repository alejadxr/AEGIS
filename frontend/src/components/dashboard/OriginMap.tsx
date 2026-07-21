'use client';

import * as React from 'react';
import Link from 'next/link';
import { InformationCircleIcon } from 'hugeicons-react';
import { RotateCcw } from 'lucide-react';
import { Panel, EmptyState } from '@/components/aegis';
import { cn } from '@/lib/utils';
import { CC_TO_LATLON } from '@/lib/geo-centroids';
import { LAND_PATH, MAP_W, VIEW_Y, VIEW_H, projectLonLat } from '@/lib/geo/land-dots.generated';
import { resolveCountryName } from '@/lib/geo/country-names';

/**
 * OriginMap — the single most visible failure in the old build, rebuilt.
 *
 * Replaces GlobalThreatMap.tsx, ThreatMapCanvas.tsx and world-geometry.ts
 * entirely. The old map drew a sparse hand-drawn dot cloud with no ocean
 * reference, so land never resolved into recognisable continents. This
 * version rasterises real world-atlas landmass geometry at build time
 * (scripts/build-land-dots.mjs -> src/lib/geo/land-dots.generated.ts,
 * 4,783 dots, ONE <path> node) against a faint ocean lattice so land reads
 * by contrast, not by hoping sparse dots self-organise into continents.
 *
 * Two-region layout: a full-bleed dot-matrix world map answers WHERE, a
 * ranked, keyboard-operable country list answers HOW MUCH — every fact a
 * marker carries is also present as text, so the map is never the sole
 * carrier of information (WCAG: no info by hover/colour alone).
 *
 * Zero runtime dependency on d3-geo / topojson-client / world-atlas — those
 * only run inside the build script. The browser loads a static path string
 * and a plain lon/lat -> xy linear projection helper.
 *
 * The map is also operable: wheel/pinch to zoom, drag to pan, keyboard
 * (+/-/arrows/0), and bidirectional marker<->list selection. See the
 * "ZOOM / PAN TRANSFORM MODEL" section below for the mechanics.
 */

export interface OriginMapEntry {
  country: string;
  country_code: string;
  count: number;
  /**
   * Operator/ASN attribution, resolved server-side from the same GeoIP
   * lookup that produced `country`. All three fields are OPTIONAL — the
   * backend returns them as null until the GeoIP CSV warmup completes
   * after an API restart. Absent data means an absent line, never a
   * placeholder: see the per-change null rules below.
   */
  top_asn?: string | null;
  top_asn_owner?: string | null;
  distinct_operators?: number | null;
}

export interface OriginMapProps {
  /** From api.dashboard.threatMap(). ALREADY FP-filtered server-side — do not re-filter. */
  data: OriginMapEntry[];
  /**
   * The operator's own uplink ASN, e.g. 'AS6400' (from
   * process.env.NEXT_PUBLIC_AEGIS_HOME_ASN, read and passed through by the
   * page). When it case-insensitively matches a row's top_asn, that row is
   * marked 'YOUR UPLINK'. Configuration only — never inferred from data.
   */
  homeAsn?: string | null;
  loading?: boolean;
  error?: boolean;
  /**
   * Optional refetch hook for the error state's Retry action. If omitted,
   * Retry falls back to a full page reload — a real handler either way,
   * never a decorative button with no effect.
   */
  onRetry?: () => void;
}

type Tier = 'critical' | 'high' | 'medium' | 'low';

const SEV_VAR: Record<Tier, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
};

const TRANSITION = 'stroke-opacity 150ms cubic-bezier(0.22, 1, 0.36, 1), stroke-width 150ms cubic-bezier(0.22, 1, 0.36, 1)';

function tierFor(count: number, maxCount: number): Tier {
  const ratio = maxCount > 0 ? count / maxCount : 0;
  if (ratio >= 0.66) return 'critical';
  if (ratio >= 0.33) return 'high';
  if (ratio >= 0.12) return 'medium';
  return 'low';
}

function markerRadius(count: number, maxCount: number): number {
  const ratio = maxCount > 0 ? count / maxCount : 0;
  return Math.min(11, 3 + 7 * Math.sqrt(ratio));
}

// ---------------------------------------------------------------------------
// ASN attribution — the "your uplink vs. Starlink vs. Amazon" answer. Every
// helper here degrades to `null` (an omitted line) the instant top_asn_owner
// is missing; nothing is ever guessed or filled with a placeholder.
// ---------------------------------------------------------------------------

/** Rail-row / chip line 2: "{owner} · {asn}[ +N]". Raw db-ip strings — no
 * cleanup, may contain quotes or exceed 50 chars; callers must `truncate`. */
function formatAsnLine(entry: OriginMapEntry): string | null {
  if (!entry.top_asn_owner) return null;
  const asnPart = entry.top_asn ? ` · ${entry.top_asn}` : '';
  let line = `${entry.top_asn_owner}${asnPart}`;
  if (entry.distinct_operators != null && entry.distinct_operators > 1) {
    line += ` +${entry.distinct_operators - 1}`;
  }
  return line;
}

/** Map-marker annotation: same "{owner} · {asn}" pair, hard-truncated to
 * `max` chars with an ellipsis (SVG <text> has no CSS text-overflow). */
function truncateAsnForMarker(entry: OriginMapEntry, max = 32): string | null {
  if (!entry.top_asn_owner) return null;
  const asnPart = entry.top_asn ? ` · ${entry.top_asn}` : '';
  const full = `${entry.top_asn_owner}${asnPart}`;
  if (full.length <= max) return full;
  return `${full.slice(0, Math.max(0, max - 1)).trimEnd()}…`;
}

/** True when the row's top ASN is the operator's own uplink — configured
 * via `homeAsn`, never inferred. Case-insensitive, whitespace-tolerant. */
function isHomeUplink(entry: OriginMapEntry, homeAsn: string | null | undefined): boolean {
  const home = homeAsn?.trim();
  const rowAsn = entry.top_asn?.trim();
  if (!home || !rowAsn) return false;
  return home.toLowerCase() === rowAsn.toLowerCase();
}

/** Local, self-contained — does not depend on globals.css having a media
 * query for this. Disables the marker-ring hover transition only. */
function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = React.useState(false);
  React.useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setReduced(mq.matches);
    const handler = (e: MediaQueryListEvent) => setReduced(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, []);
  return reduced;
}

/** True below the 820px two-pane breakpoint this component uses elsewhere
 * (`min-[820px]:`). SSR-safe: defaults false, corrected post-mount — same
 * pattern as usePrefersReducedMotion above. */
function useIsNarrowViewport(): boolean {
  const [narrow, setNarrow] = React.useState(false);
  React.useEffect(() => {
    const mq = window.matchMedia('(max-width: 819px)');
    setNarrow(mq.matches);
    const handler = (e: MediaQueryListEvent) => setNarrow(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, []);
  return narrow;
}

/** '⌘' on Apple platforms, 'Ctrl' everywhere else. SSR-safe default. */
function useModifierKeyLabel(): string {
  const [label, setLabel] = React.useState('Ctrl');
  React.useEffect(() => {
    const nav = window.navigator as Navigator & { userAgentData?: { platform?: string } };
    const platform = nav.userAgentData?.platform || nav.platform || nav.userAgent || '';
    if (/mac/i.test(platform)) setLabel('⌘');
  }, []);
  return label;
}

// ---------------------------------------------------------------------------
// ZOOM / PAN TRANSFORM MODEL
//
// State is {k, tx, ty}: the group is rendered as
//   translate(tx, ty) scale(k)
// applied directly in the SVG's own viewBox coordinate space (never the
// viewBox itself, which stays fixed). k in [1, 8]. tx/ty are clamped after
// every change so land can never leave the frame; at k===1 the clamp
// collapses both to a single point, so pan is structurally impossible at
// rest.
// ---------------------------------------------------------------------------

const ZOOM_MIN = 1;
const ZOOM_MAX = 8;
const ZOOM_STEP = 1.6;
const MOBILE_INITIAL_K = 1.6;
const WHEEL_SENSITIVITY = 0.002;
const ARROW_PAN_STEP = 40;
const DOUBLE_TAP_MAX_MS = 300;
const DOUBLE_TAP_MAX_DIST = 24;
const HINT_DURATION_MS = 1600;
const HINT_MAX_SHOWS = 2;

/** Centre of the cropped viewBox — the pivot for button/keyboard zoom. */
const CENTER_POINT = { x: MAP_W / 2, y: VIEW_Y + VIEW_H / 2 };

interface ViewTransform {
  k: number;
  tx: number;
  ty: number;
  /** Whether THIS state change should animate (button/keyboard/double-tap
   * steps) or apply instantly (wheel/drag/pinch — continuous gestures). */
  smooth: boolean;
}

const IDENTITY_TRANSFORM: ViewTransform = { k: 1, tx: 0, ty: 0, smooth: false };

function clampK(k: number): number {
  return Math.min(ZOOM_MAX, Math.max(ZOOM_MIN, k));
}

/** Clamp tx/ty so the cropped viewBox frame always stays over land+ocean,
 * never past the edge of the projected world. */
function clampPan(k: number, tx: number, ty: number): { tx: number; ty: number } {
  const txMin = MAP_W * (1 - k);
  const tyMin = (VIEW_Y + VIEW_H) * (1 - k);
  const tyMax = VIEW_Y * (1 - k);
  return {
    tx: Math.min(0, Math.max(txMin, tx)),
    ty: Math.min(tyMax, Math.max(tyMin, ty)),
  };
}

/** Zoom so that SVG-space point `p` stays fixed on screen: t' = p - (k'/k)(p - t). */
function zoomAbout(prev: ViewTransform, p: { x: number; y: number }, newKRaw: number, smooth: boolean): ViewTransform {
  const k = clampK(newKRaw);
  const ratio = k / prev.k;
  const rawTx = p.x - ratio * (p.x - prev.tx);
  const rawTy = p.y - ratio * (p.y - prev.ty);
  const { tx, ty } = clampPan(k, rawTx, rawTy);
  return { k, tx, ty, smooth };
}

function panBy(prev: ViewTransform, dx: number, dy: number, smooth: boolean): ViewTransform {
  const { tx, ty } = clampPan(prev.k, prev.tx + dx, prev.ty + dy);
  return { ...prev, tx, ty, smooth };
}

/** Screen (client) coords -> this SVG's own user-space coords, via the
 * live CTM — never a hand-rolled offset (the SVG is letterboxed by
 * preserveAspectRatio, so naive bounding-box math drifts). */
function screenToSvgPoint(svg: SVGSVGElement, clientX: number, clientY: number): { x: number; y: number } {
  const ctm = svg.getScreenCTM();
  if (!ctm) return { x: 0, y: 0 };
  const pt = svg.createSVGPoint();
  pt.x = clientX;
  pt.y = clientY;
  const transformed = pt.matrixTransform(ctm.inverse());
  return { x: transformed.x, y: transformed.y };
}

/** Mobile-only initial view: centred on the top-5 markers' centroid at
 * MOBILE_INITIAL_K, so a 125px-tall phone viewport opens on the active
 * region instead of a postage-stamp world. Falls back to all markers, then
 * to identity, when there is nothing to centre on. */
function computeMobileInitialTransform(markers: Marker[], top5: Set<string>): ViewTransform {
  const top5Markers = markers.filter((m) => top5.has(m.code));
  const pool = top5Markers.length > 0 ? top5Markers : markers;
  if (pool.length === 0) return { ...IDENTITY_TRANSFORM };
  const cx = pool.reduce((sum, m) => sum + m.cx, 0) / pool.length;
  const cy = pool.reduce((sum, m) => sum + m.cy, 0) / pool.length;
  const k = MOBILE_INITIAL_K;
  const { tx, ty } = clampPan(k, CENTER_POINT.x - k * cx, CENTER_POINT.y - k * cy);
  return { k, tx, ty, smooth: false };
}

interface Marker {
  code: string;
  country: string;
  count: number;
  cx: number;
  cy: number;
  r: number;
  tier: Tier;
  isTop: boolean;
  /** Truncated "{owner} · {asn}" annotation for the on-map label, or null. */
  asnLabel: string | null;
  /** Full "{owner} · {asn}[ +N]" line for the <title> tooltip, or null. */
  asnLine: string | null;
}

const rowFocusRing =
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-1 focus-visible:ring-offset-card';

const zoomButtonClass =
  'flex items-center justify-center rounded-[8px] border border-[var(--border)] bg-[color-mix(in_oklab,var(--card)_92%,transparent)] backdrop-blur-[2px] text-foreground h-11 w-11 md:h-7 md:w-7 disabled:cursor-not-allowed';

export function OriginMap({ data, homeAsn, loading = false, error = false, onRetry }: OriginMapProps) {
  const reactId = React.useId();
  const oceanPatternId = `aegis-ocean-${reactId}`;
  const instructionsId = `aegis-map-instructions-${reactId}`;
  const prefersReducedMotion = usePrefersReducedMotion();
  const isNarrow = useIsNarrowViewport();
  const modifierLabel = useModifierKeyLabel();
  const [hoveredCode, setHoveredCode] = React.useState<string | null>(null);
  const [selectedCode, setSelectedCode] = React.useState<string | null>(null);
  const [transform, setTransform] = React.useState<ViewTransform>(IDENTITY_TRANSFORM);
  const [pointerCount, setPointerCount] = React.useState(0);
  const [hintVisible, setHintVisible] = React.useState(false);

  const svgRef = React.useRef<SVGSVGElement>(null);
  const mapDivRef = React.useRef<HTMLDivElement>(null);
  const pointersRef = React.useRef<Map<number, { x: number; y: number }>>(new Map());
  const lastTapRef = React.useRef<{ x: number; y: number; time: number } | null>(null);
  const hintTimeoutRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const hintCountRef = React.useRef(0);
  const mobileInitDoneRef = React.useRef(false);
  const desktopRowRefs = React.useRef<Map<string, HTMLButtonElement>>(new Map());
  const chipRefs = React.useRef<Map<string, HTMLButtonElement>>(new Map());

  const sorted = React.useMemo(() => [...data].sort((a, b) => b.count - a.count), [data]);
  const maxCount = React.useMemo(
    () => sorted.reduce((max, d) => Math.max(max, d.count), 1),
    [sorted],
  );
  const totalAttacks = React.useMemo(() => sorted.reduce((sum, d) => sum + d.count, 0), [sorted]);
  const top5Codes = React.useMemo(
    () => new Set(sorted.slice(0, 5).map((d) => d.country_code.toUpperCase())),
    [sorted],
  );
  const topCode = sorted[0]?.country_code?.toUpperCase() ?? null;

  const markers = React.useMemo<Marker[]>(() => {
    const out: Marker[] = [];
    for (const entry of sorted) {
      const code = entry.country_code?.toUpperCase();
      const latlon = code ? CC_TO_LATLON[code] : undefined;
      if (!latlon) continue;
      const [lon, lat] = latlon;
      const [cx, cy] = projectLonLat(lon, lat);
      out.push({
        code,
        country: resolveCountryName(code).name,
        count: entry.count,
        cx,
        cy,
        r: markerRadius(entry.count, maxCount),
        tier: tierFor(entry.count, maxCount),
        isTop: code === topCode,
        asnLabel: truncateAsnForMarker(entry),
        asnLine: formatAsnLine(entry),
      });
    }
    return out;
  }, [sorted, maxCount, topCode]);

  const unmappedCount = sorted.length - markers.length;

  const top3 = sorted.slice(0, 3);
  const ariaLabel = error
    ? 'World map of attack origins. Origin data unavailable.'
    : sorted.length === 0
      ? 'World map of attack origins. No external origins attributed.'
      : `World map of attack origins. Top sources: ${top3
          .map((d) => `${resolveCountryName(d.country_code).name} ${d.count}`)
          .join(', ')}.`;

  const handleRetry = React.useCallback(() => {
    if (onRetry) onRetry();
    else if (typeof window !== 'undefined') window.location.reload();
  }, [onRetry]);

  const showMarkers = !loading && !error && markers.length > 0;
  const showLegend = !loading && !error && sorted.length > 0;
  /** Gates all zoom/pan/keyboard affordances — there is nothing to zoom
   * toward while loading, on error, or with zero attributed sources. */
  const mapInteractive = !loading && !error && sorted.length > 0;

  // ── Mobile: on first real data, open on the top-5 centroid at 1.6x ──
  React.useEffect(() => {
    if (!isNarrow || mobileInitDoneRef.current || !mapInteractive) return;
    mobileInitDoneRef.current = true;
    setTransform(computeMobileInitialTransform(markers, top5Codes));
  }, [isNarrow, mapInteractive, markers, top5Codes]);

  // ── Discrete zoom/pan actions (button, keyboard, double-click/-tap) ──
  const zoomInStep = React.useCallback(() => {
    setTransform((prev) => zoomAbout(prev, CENTER_POINT, prev.k * ZOOM_STEP, true));
  }, []);
  const zoomOutStep = React.useCallback(() => {
    setTransform((prev) => zoomAbout(prev, CENTER_POINT, prev.k / ZOOM_STEP, true));
  }, []);
  const resetView = React.useCallback(() => {
    setTransform({ ...IDENTITY_TRANSFORM, smooth: true });
  }, []);
  const zoomAtClientPoint = React.useCallback((clientX: number, clientY: number) => {
    const svg = svgRef.current;
    if (!svg) return;
    const p = screenToSvgPoint(svg, clientX, clientY);
    setTransform((prev) => {
      if (prev.k >= ZOOM_MAX) return { ...IDENTITY_TRANSFORM, smooth: true };
      return zoomAbout(prev, p, prev.k * ZOOM_STEP, true);
    });
  }, []);

  // ── Wheel: Cmd/Ctrl+wheel zooms about the pointer; plain wheel scrolls
  // the page and shows a one-shot hint instead. Native listener because
  // React's onWheel is passive and cannot preventDefault. ──
  const triggerHint = React.useCallback(() => {
    if (hintCountRef.current >= HINT_MAX_SHOWS) return;
    hintCountRef.current += 1;
    setHintVisible(true);
    if (hintTimeoutRef.current) clearTimeout(hintTimeoutRef.current);
    hintTimeoutRef.current = setTimeout(() => setHintVisible(false), HINT_DURATION_MS);
  }, []);

  React.useEffect(() => {
    const el = mapDivRef.current;
    if (!el || !mapInteractive) return;
    const onWheel = (e: WheelEvent) => {
      if (!(e.ctrlKey || e.metaKey)) {
        triggerHint();
        return;
      }
      e.preventDefault();
      const svg = svgRef.current;
      if (!svg) return;
      const p = screenToSvgPoint(svg, e.clientX, e.clientY);
      const factor = Math.exp(-e.deltaY * WHEEL_SENSITIVITY);
      setTransform((prev) => zoomAbout(prev, p, prev.k * factor, false));
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, [mapInteractive, triggerHint]);

  React.useEffect(
    () => () => {
      if (hintTimeoutRef.current) clearTimeout(hintTimeoutRef.current);
    },
    [],
  );

  // ── Pointer pan (1 finger, k>1) + pinch (2 fingers) ──
  const handlePointerDown = (e: React.PointerEvent<SVGSVGElement>) => {
    if (!mapInteractive) return;
    e.currentTarget.setPointerCapture(e.pointerId);
    pointersRef.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
    setPointerCount(pointersRef.current.size);
  };

  const handlePointerMove = (e: React.PointerEvent<SVGSVGElement>) => {
    if (!mapInteractive) return;
    const pointers = pointersRef.current;
    const prevPoint = pointers.get(e.pointerId);
    if (!prevPoint) return;

    if (pointers.size === 1) {
      if (transform.k > 1) {
        e.preventDefault();
        const svg = svgRef.current;
        const ctm = svg?.getScreenCTM();
        const scale = ctm?.a || 1;
        const dx = (e.clientX - prevPoint.x) / scale;
        const dy = (e.clientY - prevPoint.y) / scale;
        setTransform((prev) => panBy(prev, dx, dy, false));
      }
      pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
    } else if (pointers.size === 2) {
      e.preventDefault();
      const otherId = Array.from(pointers.keys()).find((id) => id !== e.pointerId);
      const other = otherId != null ? pointers.get(otherId) : undefined;
      pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (other) {
        const prevDist = Math.hypot(prevPoint.x - other.x, prevPoint.y - other.y);
        const currDist = Math.hypot(e.clientX - other.x, e.clientY - other.y);
        const svg = svgRef.current;
        if (prevDist > 0 && svg) {
          const factor = currDist / prevDist;
          const midX = (e.clientX + other.x) / 2;
          const midY = (e.clientY + other.y) / 2;
          const p = screenToSvgPoint(svg, midX, midY);
          setTransform((prev) => zoomAbout(prev, p, prev.k * factor, false));
        }
      }
    }
  };

  const handlePointerUp = (e: React.PointerEvent<SVGSVGElement>) => {
    const wasSolo = pointersRef.current.size === 1 && pointersRef.current.has(e.pointerId);
    pointersRef.current.delete(e.pointerId);
    setPointerCount(pointersRef.current.size);
    if (e.currentTarget.hasPointerCapture(e.pointerId)) {
      e.currentTarget.releasePointerCapture(e.pointerId);
    }

    if (wasSolo && mapInteractive && e.pointerType === 'touch') {
      const now = performance.now();
      const last = lastTapRef.current;
      if (last && now - last.time < DOUBLE_TAP_MAX_MS && Math.hypot(e.clientX - last.x, e.clientY - last.y) < DOUBLE_TAP_MAX_DIST) {
        lastTapRef.current = null;
        zoomAtClientPoint(e.clientX, e.clientY);
      } else {
        lastTapRef.current = { x: e.clientX, y: e.clientY, time: now };
      }
    }
  };

  const handlePointerCancelOrLeave = (e: React.PointerEvent<SVGSVGElement>) => {
    pointersRef.current.delete(e.pointerId);
    setPointerCount(pointersRef.current.size);
  };

  const handleDoubleClick = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!mapInteractive) return;
    e.preventDefault();
    zoomAtClientPoint(e.clientX, e.clientY);
  };

  // ── Keyboard: +/-/arrows/0/Escape on the map region itself ──
  const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (!mapInteractive) return;
    switch (e.key) {
      case '+':
      case '=':
        e.preventDefault();
        zoomInStep();
        break;
      case '-':
      case '_':
        e.preventDefault();
        zoomOutStep();
        break;
      case 'ArrowUp':
        e.preventDefault();
        setTransform((prev) => panBy(prev, 0, ARROW_PAN_STEP / prev.k, true));
        break;
      case 'ArrowDown':
        e.preventDefault();
        setTransform((prev) => panBy(prev, 0, -ARROW_PAN_STEP / prev.k, true));
        break;
      case 'ArrowLeft':
        e.preventDefault();
        setTransform((prev) => panBy(prev, ARROW_PAN_STEP / prev.k, 0, true));
        break;
      case 'ArrowRight':
        e.preventDefault();
        setTransform((prev) => panBy(prev, -ARROW_PAN_STEP / prev.k, 0, true));
        break;
      case '0':
        e.preventDefault();
        resetView();
        break;
      case 'Escape':
        e.preventDefault();
        resetView();
        setSelectedCode(null);
        e.currentTarget.blur();
        break;
      default:
        break;
    }
  };

  // ── Marker <-> list selection sync ──
  const toggleSelected = (code: string) => {
    setSelectedCode((c) => (c === code ? null : code));
  };

  React.useEffect(() => {
    if (!selectedCode) return;
    const map = isNarrow ? chipRefs.current : desktopRowRefs.current;
    const el = map.get(selectedCode);
    if (el) el.scrollIntoView({ block: 'nearest', behavior: prefersReducedMotion ? 'auto' : 'smooth' });
  }, [selectedCode, isNarrow, prefersReducedMotion]);

  const cursorClass = !mapInteractive || transform.k <= 1
    ? ''
    : pointerCount === 1
      ? 'cursor-grabbing'
      : 'cursor-grab';

  const touchAction = !mapInteractive ? 'pan-y' : transform.k > 1 || pointerCount >= 2 ? 'none' : 'pan-y';

  return (
    <Panel
      as="section"
      variant="default"
      padding="none"
      aria-label="Threat origin map"
      className="col-span-12 flex flex-col min-[820px]:flex-row min-[820px]:h-[440px] overflow-hidden"
    >
      {/* ═══ LEFT — THE MAP ═══ */}
      <div
        ref={mapDivRef}
        className="relative flex-1 min-w-0 aspect-[1000/393] min-[820px]:aspect-auto min-[820px]:h-full p-5"
        style={{ touchAction }}
        tabIndex={mapInteractive ? 0 : undefined}
        role={mapInteractive ? 'application' : undefined}
        aria-roledescription={mapInteractive ? 'Interactive world map' : undefined}
        aria-label={mapInteractive ? ariaLabel : undefined}
        aria-describedby={mapInteractive ? instructionsId : undefined}
        onKeyDown={handleKeyDown}
      >
        <p id={instructionsId} className="sr-only">
          Use plus and minus to zoom, arrow keys to pan, zero to reset. Country totals are also listed in the panel beside the map.
        </p>
        <svg
          ref={svgRef}
          viewBox={`0 ${VIEW_Y} ${MAP_W} ${VIEW_H}`}
          preserveAspectRatio="xMidYMid meet"
          role="img"
          aria-label={ariaLabel}
          width="100%"
          height="100%"
          shapeRendering="geometricPrecision"
          className={cn('block w-full h-full', cursorClass)}
          onDoubleClick={handleDoubleClick}
          onPointerDown={handlePointerDown}
          onPointerMove={handlePointerMove}
          onPointerUp={handlePointerUp}
          onPointerCancel={handlePointerCancelOrLeave}
          onPointerLeave={handlePointerCancelOrLeave}
        >
          <defs>
            <pattern id={oceanPatternId} width="5" height="5" patternUnits="userSpaceOnUse">
              <circle cx="2.5" cy="2.5" r="1" fill="var(--map-ocean)" />
            </pattern>
          </defs>
          <rect x={0} y={VIEW_Y} width={MAP_W} height={VIEW_H} fill={`url(#${oceanPatternId})`} />
          <g
            transform={`translate(${transform.tx} ${transform.ty}) scale(${transform.k})`}
            style={
              !prefersReducedMotion && transform.smooth
                ? { transition: 'transform 180ms cubic-bezier(0.22, 1, 0.36, 1)' }
                : undefined
            }
          >
            <path d={LAND_PATH} fill="var(--map-land)" fillRule="nonzero" opacity={error ? 0.5 : 1} />
            {showMarkers &&
              markers.map((m) => {
                const k = transform.k;
                const isActive = hoveredCode === m.code || selectedCode === m.code;
                const showRing = m.isTop || isActive;
                const ringOpacity = isActive ? 0.55 : 0.28;
                const ringWidth = isActive ? 1.5 : 1;
                const showLabel = top5Codes.has(m.code) || k >= 2.5;
                const titleText = `${m.country} · ${m.count} events${m.asnLine ? ' · ' + m.asnLine : ''}`;
                return (
                  <g key={m.code}>
                    {/* Hit target FIRST in paint order — larger than the
                        visible marker so it stays tappable at every zoom. */}
                    <circle
                      cx={m.cx}
                      cy={m.cy}
                      r={Math.max(m.r, 11) / k}
                      fill="transparent"
                      onPointerEnter={() => setHoveredCode(m.code)}
                      onPointerLeave={() => setHoveredCode((c) => (c === m.code ? null : c))}
                      onClick={() => toggleSelected(m.code)}
                      style={{ cursor: mapInteractive ? 'pointer' : undefined }}
                    >
                      <title>{titleText}</title>
                    </circle>
                    {showRing && (
                      <circle
                        cx={m.cx}
                        cy={m.cy}
                        r={(m.r + 3.5) / k}
                        fill="none"
                        stroke={SEV_VAR[m.tier]}
                        strokeOpacity={ringOpacity}
                        strokeWidth={ringWidth / k}
                        style={prefersReducedMotion ? undefined : { transition: TRANSITION }}
                      />
                    )}
                    <circle
                      cx={m.cx}
                      cy={m.cy}
                      r={m.r / k}
                      fill={SEV_VAR[m.tier]}
                      fillOpacity={0.55}
                      stroke={SEV_VAR[m.tier]}
                      strokeWidth={1.25 / k}
                    />
                    {showLabel && (
                      <text
                        x={m.cx}
                        y={m.cy - (m.r + 4) / k}
                        textAnchor="middle"
                        fontSize={9 / k}
                        fontFamily="var(--font-mono)"
                        fill="var(--foreground)"
                        paintOrder="stroke"
                        stroke="var(--background)"
                        strokeWidth={2.5 / k}
                      >
                        {m.code}
                      </text>
                    )}
                    {/* Supplementary ASN annotation — purely additive, stacked
                        above the code label so it never overlaps the marker
                        itself. The rail row (below) already carries this same
                        string without hovering, so this satisfies the
                        no-hover-only-information rule even though it renders
                        unconditionally alongside the top-5 code label. */}
                    {showLabel && m.asnLabel && (
                      <text
                        x={m.cx}
                        y={m.cy - (m.r + 13) / k}
                        textAnchor="middle"
                        fontSize={7 / k}
                        fontFamily="var(--font-mono)"
                        fill="var(--muted-foreground)"
                        paintOrder="stroke"
                        stroke="var(--background)"
                        strokeWidth={2.5 / k}
                      >
                        {m.asnLabel}
                      </text>
                    )}
                  </g>
                );
              })}
          </g>
        </svg>

        {/* One-shot hint: plain wheel over the map lets the page scroll and
            explains how to zoom instead. At most twice per mount. */}
        {mapInteractive && (
          <div aria-hidden className="pointer-events-none absolute inset-0 z-[4] flex items-center justify-center">
            <span
              className={cn(
                'rounded-full bg-[color-mix(in_oklab,var(--background)_88%,transparent)] border border-[var(--border)] px-3 py-1.5 text-[12px] text-foreground',
                'pointer-events-none motion-safe:transition-opacity motion-safe:duration-[120ms]',
                hintVisible ? 'opacity-100' : 'opacity-0',
              )}
            >
              Hold {modifierLabel} to zoom
            </span>
          </div>
        )}

        {/* Overlay — top-left: identity + the ONE count on the page. */}
        <div className="pointer-events-none absolute top-5 left-5 z-[2] max-w-[70%]">
          <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
            Threat Origin
          </p>
          {loading ? (
            <div
              aria-hidden
              className="mt-1.5 h-3 w-[120px] rounded-sm bg-[color-mix(in_oklab,var(--foreground)_8%,transparent)]"
            />
          ) : error ? (
            <p className="mt-1.5 font-mono tabular-nums text-[12px] font-semibold text-danger">
              ORIGIN DATA UNAVAILABLE
            </p>
          ) : sorted.length === 0 ? (
            <p className="mt-1.5 font-mono tabular-nums text-[12px] text-muted-foreground">
              NO EXTERNAL ORIGINS ATTRIBUTED
            </p>
          ) : (
            <p className="mt-1.5 font-mono tabular-nums text-[12px] text-foreground">
              {sorted.length} COUNTRIES &middot; {totalAttacks} ATTACKS
              {unmappedCount > 0 ? ` · ${unmappedCount} UNMAPPED` : ''}
            </p>
          )}
        </div>

        {/* Overlay — bottom-left: magnitude/severity legend (hidden when nothing to key). */}
        {showLegend && (
          <div className="pointer-events-none absolute bottom-5 left-5 z-[2] flex items-center gap-3.5">
            {(['critical', 'high', 'medium', 'low'] as const).map((tier) => (
              <span key={tier} className="inline-flex items-center gap-1.5">
                <span
                  aria-hidden
                  className="h-1.5 w-1.5 shrink-0 rounded-full"
                  style={{ background: SEV_VAR[tier] }}
                />
                <span className="font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">
                  {tier}
                </span>
              </span>
            ))}
          </div>
        )}

        {/* Overlay — bottom-right (bottom-left on mobile, out of the zoom
            controls' way): honesty disclosure about server-side FP filtering. */}
        <div className="absolute z-[2] bottom-3 left-3 min-[820px]:bottom-5 min-[820px]:left-auto min-[820px]:right-5 flex items-center gap-1.5">
          <span className="font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground/80">
            Excludes known false positives
          </span>
          <span
            tabIndex={0}
            role="img"
            aria-label="Traffic from devices confirmed as operator-owned is filtered server-side before aggregation."
            title="Traffic from devices confirmed as operator-owned is filtered server-side before aggregation."
            className="inline-flex shrink-0 rounded-sm text-muted-foreground/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]"
          >
            <InformationCircleIcon size={12} strokeWidth={1.8} />
          </span>
        </div>

        {/* Zoom controls — always visible, never hover-revealed. */}
        {mapInteractive && (
          <div className="absolute z-[3] bottom-3 right-3 min-[820px]:bottom-5 min-[820px]:right-5 flex flex-col gap-1.5">
            <button
              type="button"
              onClick={zoomInStep}
              disabled={transform.k >= ZOOM_MAX}
              aria-disabled={transform.k >= ZOOM_MAX}
              aria-label="Zoom in"
              className={cn(zoomButtonClass, transform.k >= ZOOM_MAX && 'opacity-40', rowFocusRing)}
            >
              <span aria-hidden className="text-[15px] leading-none font-semibold">+</span>
            </button>
            <button
              type="button"
              onClick={zoomOutStep}
              disabled={transform.k <= ZOOM_MIN}
              aria-disabled={transform.k <= ZOOM_MIN}
              aria-label="Zoom out"
              className={cn(zoomButtonClass, transform.k <= ZOOM_MIN && 'opacity-40', rowFocusRing)}
            >
              <span aria-hidden className="text-[15px] leading-none font-semibold">&minus;</span>
            </button>
            <button
              type="button"
              onClick={resetView}
              disabled={transform.k <= ZOOM_MIN}
              aria-disabled={transform.k <= ZOOM_MIN}
              aria-label="Reset view"
              className={cn(zoomButtonClass, transform.k <= ZOOM_MIN && 'opacity-40', rowFocusRing)}
            >
              <RotateCcw size={13} strokeWidth={1.8} aria-hidden />
            </button>
          </div>
        )}
      </div>

      {/* ═══ RIGHT — SOURCE RANK ═══ */}
      <div className="w-full min-[820px]:w-[320px] min-[820px]:h-full shrink-0 border-t min-[820px]:border-t-0 min-[820px]:border-l border-border flex flex-col pt-5 pr-5 pb-5 pl-5 min-[820px]:pl-[18px]">
        <h3 className="mb-3.5 shrink-0 text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
          By Volume
        </h3>

        {loading && (
          <ul className="flex flex-1 flex-col gap-0.5" aria-hidden>
            {Array.from({ length: 6 }).map((_, i) => (
              <li
                key={i}
                className="h-7 rounded-md bg-[color-mix(in_oklab,var(--foreground)_6%,transparent)] opacity-30"
              />
            ))}
          </ul>
        )}

        {!loading && error && (
          <div className="flex flex-col items-start gap-2.5 py-1">
            <p className="font-mono tabular-nums text-[12px] text-muted-foreground">
              Could not reach the threat-map endpoint.
            </p>
            <button
              type="button"
              onClick={handleRetry}
              className={cn(
                'font-mono tabular-nums text-[11px] font-semibold text-[var(--brand-text)] underline decoration-dotted underline-offset-2 rounded-sm px-0.5',
                rowFocusRing,
              )}
            >
              Retry
            </button>
          </div>
        )}

        {!loading && !error && sorted.length === 0 && (
          <EmptyState
            size="sm"
            title="No attributed sources"
            description="This list populates when an external IP resolves to a country. GeoIP runs offline — no lookup leaves your server."
            action={
              <Link
                href="/dashboard/surface"
                className={cn(
                  'font-mono tabular-nums text-[11px] font-semibold text-[var(--brand-text)] underline decoration-dotted underline-offset-2 rounded-sm px-0.5',
                  rowFocusRing,
                )}
              >
                Open Surface &rarr;
              </Link>
            }
            className="flex-1"
          />
        )}

        {!loading && !error && sorted.length > 0 && (
          <>
            {/* Desktop / wide: ranked rows, keyboard-operable, linked to map markers. */}
            <ol className="hidden min-[820px]:flex min-[820px]:flex-col flex-1 gap-0.5 overflow-y-auto -mx-1.5 pr-0.5">
              {sorted.map((entry, i) => {
                const code = entry.country_code?.toUpperCase() ?? '??';
                const tier = tierFor(entry.count, maxCount);
                const barPct = maxCount > 0 ? (entry.count / maxCount) * 100 : 0;
                const resolved = resolveCountryName(code);
                const asnLine = formatAsnLine(entry);
                const isUplink = isHomeUplink(entry, homeAsn);
                const isSelected = selectedCode === code;
                return (
                  <li key={code + i}>
                    <button
                      type="button"
                      ref={(el) => {
                        if (el) desktopRowRefs.current.set(code, el);
                        else desktopRowRefs.current.delete(code);
                      }}
                      aria-current={isSelected ? 'true' : undefined}
                      onMouseEnter={() => setHoveredCode(code)}
                      onMouseLeave={() => setHoveredCode((c) => (c === code ? null : c))}
                      onFocus={() => setHoveredCode(code)}
                      onBlur={() => setHoveredCode((c) => (c === code ? null : c))}
                      onClick={() => toggleSelected(code)}
                      style={isSelected ? { borderLeftColor: SEV_VAR[tier] } : undefined}
                      className={cn(
                        'flex w-full flex-col justify-center gap-0.5 rounded-md border-l-2 border-transparent px-1.5 text-left transition-colors duration-150 ease-[cubic-bezier(0.22,1,0.36,1)]',
                        asnLine ? 'min-h-[44px] py-1.5' : 'h-7',
                        isSelected
                          ? 'bg-[color-mix(in_oklab,var(--foreground)_4%,transparent)]'
                          : 'hover:bg-[color-mix(in_oklab,var(--foreground)_3%,transparent)]',
                        'focus-visible:bg-[color-mix(in_oklab,var(--foreground)_3%,transparent)]',
                        rowFocusRing,
                      )}
                    >
                      <span className="flex items-center gap-2.5">
                        <span className="w-[22px] shrink-0 font-mono tabular-nums text-[11px] font-semibold uppercase text-foreground">
                          {code}
                        </span>
                        <span
                          className={cn(
                            'min-w-0 flex-1 truncate text-[12px] font-normal text-muted-foreground',
                            !resolved.known && 'italic text-muted-foreground/60',
                          )}
                        >
                          {resolved.name}
                        </span>
                        {isUplink && (
                          <span
                            className="shrink-0 rounded-[4px] border px-1.5 py-[1px] font-mono text-[9px] font-semibold uppercase tracking-[0.1em]"
                            style={{
                              color: 'var(--brand-accent-text)',
                              background: 'color-mix(in oklab, var(--brand-accent) 14%, transparent)',
                              borderColor: 'color-mix(in oklab, var(--brand-accent) 30%, transparent)',
                            }}
                          >
                            Your Uplink
                          </span>
                        )}
                        <span className="h-1 w-14 shrink-0 overflow-hidden rounded-full bg-border">
                          <span
                            className="block h-1 rounded-full"
                            style={{ width: `${barPct}%`, background: SEV_VAR[tier] }}
                          />
                        </span>
                        <span className="w-[34px] shrink-0 text-right font-mono tabular-nums text-[11px] font-semibold text-foreground">
                          {entry.count}
                        </span>
                      </span>
                      {asnLine && (
                        <span className="block pl-[32px]">
                          <span
                            title={asnLine}
                            className="block truncate font-mono text-[10.5px] leading-[14px] text-muted-foreground"
                          >
                            {asnLine}
                          </span>
                        </span>
                      )}
                    </button>
                  </li>
                );
              })}
            </ol>

            {/* Narrow (<820px): 2-col chip grid — full rows don't fit a stacked half-width panel. */}
            <div
              role="list"
              aria-label="Attack sources by volume"
              className="grid grid-cols-2 gap-2 max-h-[46vh] overflow-y-auto overscroll-contain min-[820px]:hidden"
            >
              {sorted.map((entry, i) => {
                const code = entry.country_code?.toUpperCase() ?? '??';
                const tier = tierFor(entry.count, maxCount);
                const resolved = resolveCountryName(code);
                const asnLine = formatAsnLine(entry);
                const isSelected = selectedCode === code;
                return (
                  <div key={code + i} role="listitem">
                    <button
                      type="button"
                      ref={(el) => {
                        if (el) chipRefs.current.set(code, el);
                        else chipRefs.current.delete(code);
                      }}
                      aria-current={isSelected ? 'true' : undefined}
                      onPointerEnter={() => setHoveredCode(code)}
                      onPointerLeave={() => setHoveredCode((c) => (c === code ? null : c))}
                      onClick={() => toggleSelected(code)}
                      style={isSelected ? { borderLeftColor: SEV_VAR[tier] } : undefined}
                      className={cn(
                        'flex w-full min-h-[44px] flex-col justify-center gap-0.5 rounded-lg border border-border border-l-2 px-2.5 py-1.5 text-left',
                        isSelected && 'bg-[color-mix(in_oklab,var(--foreground)_4%,transparent)]',
                        rowFocusRing,
                      )}
                    >
                      <span className="flex items-center gap-2">
                        <span
                          aria-hidden
                          className="h-1.5 w-1.5 shrink-0 rounded-full"
                          style={{ background: SEV_VAR[tier] }}
                        />
                        <span className="shrink-0 font-mono tabular-nums text-[11px] font-semibold uppercase text-foreground">
                          {code}
                        </span>
                        <span
                          className={cn(
                            'min-w-0 flex-1 truncate text-[11px] text-muted-foreground',
                            !resolved.known && 'italic text-muted-foreground/60',
                          )}
                        >
                          {resolved.name}
                        </span>
                        <span className="shrink-0 font-mono tabular-nums text-[11px] font-semibold text-foreground">
                          {entry.count}
                        </span>
                      </span>
                      {asnLine && (
                        <span
                          title={asnLine}
                          className="block truncate pl-[18px] text-[10px] text-muted-foreground"
                        >
                          {asnLine}
                        </span>
                      )}
                    </button>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>
    </Panel>
  );
}

export default OriginMap;
