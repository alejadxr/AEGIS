'use client';

import { useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { hasAuth } from '@/lib/api';
import { TopNav } from '@/components/shared/TopNav';
import { SectionTabs } from '@/components/nav/SectionTabs';
import { AskAI } from '@/components/shared/AskAI';
import { GuideTour } from '@/components/shared/GuideTour';

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const [ready, setReady] = useState(false);
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

  if (!ready) {
    return (
      <div className="min-h-screen bg-background text-foreground flex items-center justify-center">
        <div className="w-4 h-4 border border-border border-t-primary rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <TopNav />
      <SectionTabs />
      <main className="max-w-[1440px] mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {children}
      </main>
      <AskAI />
      {showGuide && <GuideTour onClose={handleGuideClose} />}
    </div>
  );
}
