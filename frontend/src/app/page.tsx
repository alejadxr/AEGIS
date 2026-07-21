'use client';

/**
 * Root route — a redirect, not a second sign-in screen.
 *
 * This file used to be a 288-line login form: a near-duplicate of /login, but
 * the ONLY one that supported email/password auth. Nothing ever routed here
 * (dashboard/layout.tsx, dashboard/firewall and DemoModeBanner all redirect to
 * `/login?next=…`), so the richer form was unreachable by redirect while the
 * weaker one was canonical, and each carried its own drifting version string.
 *
 * Both auth modes now live in /login. This route only decides where to send you.
 */

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { hasAuth } from '@/lib/api';

export default function RootPage() {
  const router = useRouter();

  useEffect(() => {
    let authed = false;
    try {
      authed = hasAuth();
    } catch {
      // localStorage unavailable (private browsing / disabled storage) — treat
      // as signed out and let /login explain the situation.
    }
    router.replace(authed ? '/dashboard' : '/login?next=%2Fdashboard');
  }, [router]);

  // Deliberately renders nothing: this resolves within a tick, and a flash of
  // branded chrome before an immediate redirect reads as jank.
  return null;
}
