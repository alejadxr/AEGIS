/**
 * AEGIS premium primitive library.
 *
 * One canonical surface (<Panel>) + header (<SectionHeader>) + KPI tile
 * (<KPI>) + row (<DataRow>) + status pill (<StatusBadge>) + empty state
 * (<EmptyState>) + provenance tag (<ProvenanceBadge>).
 *
 * ALL dashboard surfaces should funnel through these primitives to
 * eliminate dark-mode background drift (some black, some gray, some
 * dark-blue) that came from re-implementing the card shell in every file.
 */
export { Panel } from './Panel';
export type { PanelProps, PanelVariant, PanelPadding, PanelBorder } from './Panel';

export { SectionHeader } from './SectionHeader';
export type { SectionHeaderProps } from './SectionHeader';

export { KPI } from './KPI';
export type { KPIProps, KPITone } from './KPI';

export { DataRow } from './DataRow';
export type { DataRowProps } from './DataRow';

export { StatusBadge } from './StatusBadge';
export type { StatusBadgeProps, StatusVariant, StatusSize } from './StatusBadge';

export { EmptyState } from './EmptyState';
export type { EmptyStateProps } from './EmptyState';

export { ProvenanceBadge } from './ProvenanceBadge';
export type { ProvenanceBadgeProps, Provenance } from './ProvenanceBadge';
