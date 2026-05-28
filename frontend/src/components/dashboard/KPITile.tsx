'use client';

/**
 * KPITile — thin compatibility wrapper around the new <KPI> primitive.
 *
 * Kept so existing dashboard imports don't break. New code should import
 * { KPI } from '@/components/aegis' directly.
 */
import { KPI, type KPITone } from '@/components/aegis';

interface KPITileProps {
  label: string;
  value: string | number;
  sub?: string;
  tone?: KPITone;
  href?: string;
  warm?: boolean;
  ariaLabel?: string;
}

export function KPITile({
  label,
  value,
  sub,
  tone = 'neutral',
  href,
  warm = false,
  ariaLabel,
}: KPITileProps) {
  return (
    <KPI
      label={label}
      value={value}
      sub={sub}
      tone={tone}
      href={href}
      warm={warm}
      ariaLabel={ariaLabel}
    />
  );
}
