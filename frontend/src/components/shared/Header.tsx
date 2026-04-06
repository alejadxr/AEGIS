'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import {
  Search01Icon,
  Notification03Icon,
  Logout01Icon,
  UserIcon,
  Sun01Icon,
  Moon02Icon,
} from 'hugeicons-react';
import { SidebarToggle } from './Sidebar';
import { clearApiKey, clearJwtToken } from '@/lib/api';
import { cn } from '@/lib/utils';

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

interface Incident {
  id: string;
  title: string;
  severity: string;
  detected_at: string;
  status: string;
}

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

const severityDotColor: Record<string, string> = {
  critical: 'bg-[#EF4444]',
  high: 'bg-[#F97316]',
  medium: 'bg-[#F59E0B]',
  low: 'bg-[#3B82F6]',
};

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

interface HeaderProps {
  onMobileMenuToggle?: () => void;
}

export function Header({ onMobileMenuToggle }: HeaderProps) {
  const router = useRouter();
  const [searchQuery, setSearchQuery] = useState('');
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [notifLoading, setNotifLoading] = useState(false);
  const [hasUnread, setHasUnread] = useState(false);
  const [isDark, setIsDark] = useState(true);
  const notifRef = useRef<HTMLDivElement>(null);

  // Initialize theme from localStorage
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

  const handleLogout = () => {
    clearApiKey();
    clearJwtToken();
    router.push('/');
  };

  const openNotifications = async () => {
    setShowNotifications(true);
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

  useEffect(() => {
    fetchRecentIncidents()
      .then((data) => {
        if (data.length > 0) setHasUnread(true);
        setIncidents(data.slice(0, 5));
      })
      .catch(() => {
        setHasUnread(false);
      });
  }, []);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setShowNotifications(false);
      }
    }
    if (showNotifications) document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [showNotifications]);

  return (
    <header className="relative z-50 h-14 bg-[rgb(var(--c6-bg-rgb)/0.85)] backdrop-blur-xl border-b border-white/[0.06] flex items-center justify-between px-4 md:px-6 shrink-0">
      {/* Left: Hamburger (mobile) + Search */}
      <div className="flex items-center gap-3 flex-1 min-w-0">
        {/* Mobile hamburger */}
        {onMobileMenuToggle && (
          <SidebarToggle onClick={onMobileMenuToggle} />
        )}
        {/* Search */}
        <div className="relative hidden sm:block w-full max-w-[280px] md:max-w-xs">
          <Search01Icon className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600" size={16} />
          <input
            type="text"
            placeholder="Search assets, incidents, IOCs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full c6-input rounded-xl px-4 py-2 pl-10 text-sm placeholder:text-zinc-600 focus:outline-none focus:border-[#22D3EE]/30 transition-colors"
          />
        </div>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-2 shrink-0">
        {/* Notifications */}
        <div ref={notifRef} className="relative">
          <button
            onClick={openNotifications}
            className="relative p-2 rounded-xl text-zinc-500 hover:text-zinc-300 hover:bg-white/[0.03] transition-colors"
          >
            <Notification03Icon size={18} />
            {hasUnread && (
              <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-[#EF4444] rounded-full border-2 border-[rgb(var(--c6-bg-rgb)/1)]" />
            )}
          </button>

          {showNotifications && (
            <div className="absolute right-0 top-full mt-2 w-80 bg-[#18181B] border border-white/[0.06] rounded-2xl shadow-2xl shadow-black/50 z-[70] animate-fade-in overflow-hidden">
              <div className="px-4 py-3 border-b border-white/[0.06] flex items-center justify-between">
                <span className="text-[13px] font-semibold text-white">Recent Incidents</span>
                {incidents.length > 0 && (
                  <span className="text-[11px] bg-[#EF4444]/10 text-[#EF4444] px-1.5 py-0.5 rounded-md font-medium">{incidents.length}</span>
                )}
              </div>

              {notifLoading ? (
                <div className="px-4 py-6 text-center text-[12px] text-zinc-600">Loading...</div>
              ) : incidents.length === 0 ? (
                <div className="px-4 py-6 text-center text-[12px] text-zinc-600">No notifications</div>
              ) : (
                <div>
                  {incidents.map((inc) => (
                    <div
                      key={inc.id}
                      className="flex items-start gap-3 px-4 py-3 border-b border-white/[0.03] hover:bg-white/[0.02] transition-colors cursor-pointer"
                      onClick={() => { setShowNotifications(false); router.push('/dashboard/response'); }}
                    >
                      <span className={cn('mt-1.5 shrink-0 block w-2 h-2 rounded-full', severityDotColor[inc.severity] || 'bg-zinc-600')} />
                      <div className="flex-1 min-w-0">
                        <p className="text-[12px] text-zinc-200 font-medium truncate">{inc.title}</p>
                        <p className="text-[11px] text-zinc-600 font-mono mt-0.5">{timeAgo(inc.detected_at)}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          className="p-2 rounded-xl text-zinc-500 hover:text-zinc-300 hover:bg-white/[0.03] transition-colors"
          title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {isDark ? <Sun01Icon size={18} /> : <Moon02Icon size={18} />}
        </button>

        {/* Divider */}
        <div className="w-px h-6 bg-white/[0.06] mx-1" />

        {/* User */}
        <div className="relative">
          <button
            onClick={() => setShowUserMenu(!showUserMenu)}
            className="flex items-center gap-2.5 px-2 py-1.5 rounded-xl text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.03] transition-colors"
          >
            <div className="w-7 h-7 rounded-full bg-gradient-to-br from-[#22D3EE]/20 to-[#F97316]/20 border border-white/[0.06] flex items-center justify-center">
              <UserIcon size={14} className="text-zinc-400" />
            </div>
            <span className="text-sm font-medium hidden sm:block">Operator</span>
          </button>
          {showUserMenu && (
            <>
              <div className="fixed inset-0 z-40" onClick={() => setShowUserMenu(false)} />
              <div className="absolute right-0 top-full mt-2 w-48 bg-[#18181B] border border-white/[0.06] rounded-2xl shadow-2xl shadow-black/50 py-1.5 z-[70] animate-fade-in">
                <button
                  onClick={handleLogout}
                  className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-zinc-400 hover:text-[#EF4444] hover:bg-white/[0.03] transition-colors rounded-xl mx-0"
                >
                  <Logout01Icon size={16} />
                  Disconnect
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </header>
  );
}
