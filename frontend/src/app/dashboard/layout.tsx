'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { hasAuth } from '@/lib/api';
import { Sidebar } from '@/components/shared/Sidebar';
import { Header } from '@/components/shared/Header';
import { AskAI } from '@/components/shared/AskAI';
import { GuideTour } from '@/components/shared/GuideTour';
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
  const [showGuide, setShowGuide] = useState(false);

  useEffect(() => {
    if (!hasAuth()) {
      router.push('/');
    } else {
      setReady(true);
      if (!localStorage.getItem('aegis_guide_seen')) {
        setShowGuide(true);
      }
    }
  }, [router]);

  const handleGuideClose = useCallback(() => {
    setShowGuide(false);
    localStorage.setItem('aegis_guide_seen', '1');
  }, []);

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
      <div className="min-h-screen bg-background text-foreground flex items-center justify-center">
        <div className="w-4 h-4 border border-border border-t-primary rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Sidebar
        onCollapsedChange={handleCollapsedChange}
        mobileOpen={mobileOpen}
        onMobileClose={closeMobile}
      />
      <div
        className={cn(
          'flex flex-col min-h-screen transition-all duration-200',
          'pl-0',
          collapsed ? 'md:pl-[56px]' : 'md:pl-[220px]'
        )}
      >
        <Header onMobileMenuToggle={toggleMobile} />
        <main className="flex-1 p-4 md:p-5 overflow-auto">
          {children}
        </main>
      </div>
      <AskAI />
      {showGuide && <GuideTour onClose={handleGuideClose} />}
    </div>
  );
}
