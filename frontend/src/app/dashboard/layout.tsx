'use client';

import { useEffect, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { hasAuth } from '@/lib/api';
import { TopNav } from '@/components/shared/TopNav';
import { SectionTabs } from '@/components/nav/SectionTabs';
import { AskAI } from '@/components/shared/AskAI';
import { MobileTabBar } from '@/components/nav/MobileTabBar';

// v1.6.3: routes accessible without an API key (public guide / docs).
const PUBLIC_DASHBOARD_PATHS = new Set<string>(['/dashboard/guide']);

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const pathname = usePathname() || '';
  const [ready, setReady] = useState(false);

  useEffect(() => {
    // v1.6.3: redirect to /login (not /) with ?next= so user lands on the
    // page they intended after sign-in. /dashboard/guide stays public.
    if (PUBLIC_DASHBOARD_PATHS.has(pathname)) {
      setReady(true);
      return;
    }
    if (!hasAuth()) {
      const next = encodeURIComponent(pathname || '/dashboard');
      router.replace(`/login?next=${next}`);
    } else {
      setReady(true);
    }
  }, [router, pathname]);

  if (!ready) {
    return (
      <div className="min-h-dvh bg-background text-foreground flex items-center justify-center">
        <div className="w-4 h-4 border border-border border-t-primary rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-dvh bg-background text-foreground max-md:pl-[var(--safe-left)] max-md:pr-[var(--safe-right)]">
      {/* --nav-h / --cmdbar-h / --sticky-top now live in globals.css (:root
          + a min-width:768px block that restores the exact 65/53/118 desktop
          values) so they can differ below md. Do not re-add them inline. */}
      <TopNav />
      <SectionTabs />
      <main className="max-w-[1440px] mx-auto px-4 sm:px-6 lg:px-8 pt-6 pb-[calc(var(--tabbar-total)+24px)]">
        {children}
      </main>
      <AskAI />
      <MobileTabBar />
    </div>
  );
}
