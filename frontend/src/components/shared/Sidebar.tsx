'use client';

// Deprecated: AEGIS uses a horizontal TopNav as of v1.6.2.
// This file is preserved as a no-op to keep historical imports compiling.
// New code should import from '@/components/shared/TopNav' instead.

interface SidebarProps {
  onCollapsedChange?: (collapsed: boolean) => void;
  mobileOpen?: boolean;
  onMobileClose?: () => void;
}

export function Sidebar(_props: SidebarProps) {
  return null;
}

export function SidebarToggle(_props: { onClick: () => void }) {
  return null;
}
