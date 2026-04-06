'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { hasAuth } from '@/lib/api';
import { Sidebar } from '@/components/shared/Sidebar';
import { Header } from '@/components/shared/Header';
import { AskAI } from '@/components/shared/AskAI';
import { cn } from '@/lib/utils';

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    if (!hasAuth()) {
      router.push('/');
    } else {
      setReady(true);
    }
  }, [router]);

  const handleCollapsedChange = useCallback((c: boolean) => {
    setCollapsed(c);
  }, []);

  const toggleMobile = useCallback(() => {
    setMobileOpen((prev) => !prev);
  }, []);

  const closeMobile = useCallback(() => {
    setMobileOpen(false);
  }, []);

  if (!ready) {
    return (
      <div className="min-h-screen c6-page flex items-center justify-center">
        <div className="w-5 h-5 border-2 border-white/10 border-t-[#22D3EE] rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen c6-page">
      <Sidebar
        onCollapsedChange={handleCollapsedChange}
        mobileOpen={mobileOpen}
        onMobileClose={closeMobile}
      />
      <div
        className={cn(
          'flex flex-col min-h-screen transition-all duration-300',
          // Mobile: no left padding (sidebar is overlay)
          'pl-0',
          // Desktop: shift content based on sidebar collapsed state
          collapsed ? 'md:pl-[68px]' : 'md:pl-[240px]'
        )}
      >
        <Header onMobileMenuToggle={toggleMobile} />
        <main className="flex-1 p-4 md:p-6 overflow-auto">
          {children}
        </main>
      </div>
      <AskAI />
    </div>
  );
}
