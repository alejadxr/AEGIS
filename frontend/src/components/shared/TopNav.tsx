'use client';

import { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  Search01Icon,
  Notification03Icon,
  Logout01Icon,
  UserIcon,
  Sun01Icon,
  Moon02Icon,
  Settings01Icon,
} from 'hugeicons-react';
import { clearApiKey, clearJwtToken } from '@/lib/api';
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

export interface TopNavSection {
  id: string;
  label: string;
  href: string; // default landing route
  routes: string[]; // routes this section owns (prefix-match)
}

export const TOP_NAV_SECTIONS: TopNavSection[] = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    href: '/dashboard',
    routes: ['/dashboard'],
  },
  {
    id: 'threats',
    label: 'Threats',
    href: '/dashboard/response',
    routes: [
      '/dashboard/response',
      '/dashboard/threats',
      '/dashboard/ip-intel',
    ],
  },
  {
    id: 'defense',
    label: 'Defense',
    href: '/dashboard/firewall',
    routes: [
      '/dashboard/firewall',
      '/dashboard/phantom',
      '/dashboard/deception',
      '/dashboard/antivirus',
      '/dashboard/ransomware',
      '/dashboard/edr',
    ],
  },
  {
    id: 'assets',
    label: 'Assets',
    href: '/dashboard/surface',
    routes: [
      '/dashboard/surface',
      '/dashboard/infra',
      '/dashboard/attack-path',
    ],
  },
];

export function getActiveSectionId(pathname: string): string {
  // exact match for /dashboard root only
  if (pathname === '/dashboard' || pathname === '/dashboard/') return 'dashboard';
  // pick the section whose routes (excluding bare /dashboard) match longest prefix
  let best: { id: string; len: number } | null = null;
  for (const s of TOP_NAV_SECTIONS) {
    for (const r of s.routes) {
      if (r === '/dashboard') continue;
      if (pathname === r || pathname.startsWith(r + '/')) {
        if (!best || r.length > best.len) best = { id: s.id, len: r.length };
      }
    }
  }
  return best?.id ?? 'dashboard';
}

interface Incident {
  id: string;
  title: string;
  severity: string;
  detected_at: string;
  status: string;
}

const severityDotColor: Record<string, string> = {
  critical: 'bg-[var(--danger)]',
  high: 'bg-[var(--brand-accent)]',
  medium: 'bg-[var(--warning)]',
  low: 'bg-[var(--info)]',
};

function timeAgo(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  if (diff < 0) return 'just now';
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

async function fetchRecentIncidents(): Promise<Incident[]> {
  const apiKey = typeof window !== 'undefined' ? localStorage.getItem('aegis_api_key') : null;
  const jwtToken = typeof window !== 'undefined' ? localStorage.getItem('aegis_jwt_token') : null;
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (jwtToken) headers['Authorization'] = `Bearer ${jwtToken}`;
  else if (apiKey) headers['X-API-Key'] = apiKey;
  const res = await fetch(`${BASE_URL}/response/incidents?limit=5`, { headers });
  if (!res.ok) throw new Error('Failed to fetch incidents');
  return res.json();
}

export function TopNav() {
  const pathname = usePathname();
  const router = useRouter();
  const activeId = getActiveSectionId(pathname);

  const [showUserMenu, setShowUserMenu] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showSearch, setShowSearch] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [notifLoading, setNotifLoading] = useState(false);
  const [hasUnread, setHasUnread] = useState(false);
  const [isDark, setIsDark] = useState(true);

  const notifRef = useRef<HTMLDivElement>(null);
  const userRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLDivElement>(null);

  // theme bootstrap
  useEffect(() => {
    const saved = localStorage.getItem('aegis-theme') as 'dark' | 'light' | null;
    const system = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    const current = document.documentElement.getAttribute('data-theme') as 'dark' | 'light' | null;
    const theme = saved || current || system;
    setIsDark(theme === 'dark');
    document.documentElement.setAttribute('data-theme', theme);
  }, []);

  const toggleTheme = () => {
    const next = isDark ? 'light' : 'dark';
    setIsDark(!isDark);
    localStorage.setItem('aegis-theme', next);
    document.documentElement.setAttribute('data-theme', next);
  };

  // close menus on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      const t = e.target as Node;
      if (notifRef.current && !notifRef.current.contains(t)) setShowNotifications(false);
      if (userRef.current && !userRef.current.contains(t)) setShowUserMenu(false);
      if (searchRef.current && !searchRef.current.contains(t)) setShowSearch(false);
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  // preload unread
  useEffect(() => {
    fetchRecentIncidents()
      .then((data) => {
        if (data.length > 0) setHasUnread(true);
        setIncidents(data.slice(0, 5));
      })
      .catch(() => setHasUnread(false));
  }, []);

  const openNotifications = async () => {
    setShowNotifications((v) => !v);
    setHasUnread(false);
    if (incidents.length > 0) return;
    setNotifLoading(true);
    try {
      const data = await fetchRecentIncidents();
      setIncidents(data.slice(0, 5));
    } catch {
      setIncidents([]);
    } finally {
      setNotifLoading(false);
    }
  };

  const handleLogout = () => {
    clearApiKey();
    clearJwtToken();
    router.push('/');
  };

  return (
    <header
      role="banner"
      className="sticky top-0 z-40 bg-background border-b border-border max-md:pl-[var(--safe-left)] max-md:pr-[var(--safe-right)]"
    >
      <div className="max-w-[1440px] mx-auto h-[52px] md:h-16 px-4 sm:px-6 lg:px-8 flex items-center justify-between gap-4">
        {/* LEFT: Logo + brand */}
        <Link
          href="/dashboard"
          className="tap-44 flex items-center gap-2.5 shrink-0 group min-h-[44px] md:min-h-0"
          aria-label="AEGIS home"
        >
          <div className="relative w-7 h-7 rounded-md bg-gradient-to-br from-[color-mix(in_oklab,var(--brand-accent)_30%,transparent)] to-[color-mix(in_oklab,var(--brand-accent)_5%,transparent)] border border-[color-mix(in_oklab,var(--brand-accent)_35%,transparent)] flex items-center justify-center shrink-0">
            <span className="font-mono text-[var(--brand-accent)] font-bold text-[11px] tracking-wider">A</span>
            <span className="absolute inset-0 rounded-md bg-[color-mix(in_oklab,var(--brand-accent)_12%,transparent)] blur-md opacity-60 -z-10" />
          </div>
          <div className="flex items-baseline gap-1.5 min-w-0">
            <span className="text-foreground font-semibold text-[14px] tracking-tight">AEGIS</span>
            {process.env.NEXT_PUBLIC_AEGIS_VERSION && (
              <span className="hidden sm:inline text-[9px] font-mono text-muted-foreground/60 tracking-widest uppercase">
                v{process.env.NEXT_PUBLIC_AEGIS_VERSION}
              </span>
            )}
          </div>
        </Link>

        {/* CENTER: Top-level nav (desktop) */}
        <nav
          role="navigation"
          aria-label="Primary"
          className="hidden md:flex items-center h-full"
        >
          <ul className="flex items-center gap-1 h-full">
            {TOP_NAV_SECTIONS.map((section) => {
              const isActive = section.id === activeId;
              return (
                <li key={section.id} className="h-full flex items-stretch">
                  <Link
                    href={section.href}
                    aria-current={isActive ? 'page' : undefined}
                    className={cn(
                      'relative inline-flex items-center px-4 text-[13px] font-medium motion-safe:transition-colors motion-safe:duration-150 outline-none',
                      'focus-visible:ring-2 focus-visible:ring-[color-mix(in_oklab,var(--brand-accent)_55%,transparent)] focus-visible:ring-offset-0 rounded-sm',
                      isActive
                        ? 'text-foreground'
                        : 'text-muted-foreground hover:text-foreground'
                    )}
                  >
                    {section.label}
                    <span
                      className={cn(
                        'absolute left-3 right-3 -bottom-px h-[2px] rounded-full motion-safe:transition-opacity motion-safe:duration-150',
                        isActive ? 'opacity-100' : 'opacity-0'
                      )}
                      style={{ backgroundColor: 'var(--brand-accent)' }}
                      aria-hidden
                    />
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>

        {/* RIGHT: Actions */}
        <div className="flex items-center max-md:gap-2 gap-1 shrink-0">
          {/* Search (desktop) */}
          <div ref={searchRef} className="relative hidden md:block">
            <button
              type="button"
              onClick={() => setShowSearch((v) => !v)}
              aria-label="Search"
              className="w-9 h-9 inline-flex items-center justify-center rounded-md text-muted-foreground hover:text-foreground hover:bg-[color-mix(in_oklab,var(--foreground)_6%,transparent)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[color-mix(in_oklab,var(--brand-accent)_55%,transparent)]"
            >
              <Search01Icon size={16} />
            </button>
            {showSearch && (
              <div className="absolute right-0 top-full mt-1.5 w-72 bg-card border border-border rounded-xl p-2 z-[70] animate-fade-in">
                <div className="relative">
                  <Search01Icon className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground/60" size={14} />
                  <input
                    type="text"
                    autoFocus
                    placeholder="Search..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full h-8 rounded-md bg-background border border-border pl-8 pr-2 text-[13px] text-foreground placeholder:text-muted-foreground/60 outline-none focus:border-[color-mix(in_oklab,var(--brand-accent)_50%,transparent)]"
                  />
                </div>
              </div>
            )}
          </div>

          {/* Notifications */}
          <div ref={notifRef} className="relative">
            <button
              type="button"
              onClick={openNotifications}
              aria-label="Notifications"
              aria-haspopup="menu"
              aria-expanded={showNotifications}
              className="tap-44 relative w-9 h-9 inline-flex items-center justify-center rounded-md text-muted-foreground hover:text-foreground hover:bg-[color-mix(in_oklab,var(--foreground)_6%,transparent)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[color-mix(in_oklab,var(--brand-accent)_55%,transparent)] motion-safe:active:opacity-70 motion-safe:transition-opacity motion-safe:duration-100"
            >
              <Notification03Icon size={16} />
              {hasUnread && (
                <span
                  className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full"
                  style={{ backgroundColor: 'var(--danger)' }}
                />
              )}
            </button>
            {showNotifications && (
              <div className="absolute right-0 top-full mt-1.5 w-80 bg-card border border-border rounded-xl z-[70] animate-fade-in overflow-hidden">
                <div className="px-3.5 py-2.5 border-b border-border flex items-center justify-between">
                  <span className="text-[12px] font-medium text-foreground/80">Recent Incidents</span>
                  {incidents.length > 0 && (
                    <Badge variant="destructive" className="text-[10px] font-mono">{incidents.length}</Badge>
                  )}
                </div>
                {notifLoading ? (
                  <div className="px-3.5 py-5 text-center text-[11px] text-muted-foreground">Loading...</div>
                ) : incidents.length === 0 ? (
                  <div className="px-3.5 py-5 text-center text-[11px] text-muted-foreground">No notifications</div>
                ) : (
                  <div>
                    {incidents.map((inc) => (
                      <button
                        key={inc.id}
                        onClick={() => { setShowNotifications(false); router.push('/dashboard/response'); }}
                        className="w-full text-left flex items-start gap-2.5 px-3.5 py-2.5 border-b border-border/50 hover:bg-muted/50 transition-colors duration-150"
                      >
                        <span className={cn('mt-1 shrink-0 block w-1.5 h-1.5 rounded-full', severityDotColor[inc.severity] || 'bg-muted-foreground')} />
                        <div className="flex-1 min-w-0">
                          <p className="text-[11px] text-foreground/80 font-medium truncate">{inc.title}</p>
                          <p className="text-[10px] text-muted-foreground/60 font-mono mt-0.5">{timeAgo(inc.detected_at)}</p>
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* User menu */}
          <div ref={userRef} className="relative">
            <button
              type="button"
              onClick={() => setShowUserMenu((v) => !v)}
              aria-label="User menu"
              aria-haspopup="menu"
              aria-expanded={showUserMenu}
              className="tap-44 inline-flex items-center gap-2 h-9 px-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-[color-mix(in_oklab,var(--foreground)_6%,transparent)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[color-mix(in_oklab,var(--brand-accent)_55%,transparent)] motion-safe:active:opacity-70 motion-safe:transition-opacity motion-safe:duration-100"
            >
              <div className="w-7 h-7 rounded-md bg-muted border border-border flex items-center justify-center">
                <UserIcon size={13} className="text-muted-foreground" />
              </div>
              <span className="text-[12px] font-medium hidden lg:block">Operator</span>
            </button>
            {showUserMenu && (
              <div
                role="menu"
                className="absolute right-0 top-full mt-1.5 w-52 bg-card border border-border rounded-xl py-1 z-[70] animate-fade-in"
              >
                <Link
                  href="/dashboard/settings"
                  role="menuitem"
                  onClick={() => setShowUserMenu(false)}
                  className="w-full flex items-center gap-2 px-3 py-2 max-md:py-3 text-[12px] text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-all duration-150 motion-safe:active:opacity-70"
                >
                  <Settings01Icon size={14} />
                  Settings
                </Link>
                <button
                  role="menuitem"
                  onClick={() => { toggleTheme(); setShowUserMenu(false); }}
                  className="w-full flex items-center gap-2 px-3 py-2 max-md:py-3 text-[12px] text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-all duration-150 motion-safe:active:opacity-70"
                >
                  {isDark ? <Sun01Icon size={14} /> : <Moon02Icon size={14} />}
                  {isDark ? 'Light mode' : 'Dark mode'}
                </button>
                <div className="my-1 h-px bg-border" />
                <button
                  role="menuitem"
                  onClick={handleLogout}
                  className="w-full flex items-center gap-2 px-3 py-2 max-md:py-3 text-[12px] text-muted-foreground hover:text-[var(--danger)] hover:bg-muted/50 transition-all duration-150 motion-safe:active:opacity-70"
                >
                  <Logout01Icon size={14} />
                  Sign out
                </button>
              </div>
            )}
          </div>

          {/* Mobile hamburger + drawer removed: navigation now lives in
              MobileTabBar (bottom tab bar owns top-level sections below
              md). The drawer's only unique control was a search <input>
              whose value (searchQuery) was never read by anything — a
              non-functional control the project's honesty rule forbids
              shipping. Desktop search above is untouched. */}
        </div>
      </div>
    </header>
  );
}
