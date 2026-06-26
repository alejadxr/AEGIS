'use client';

import { Suspense, useEffect, useRef, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { setApiKey, hasAuth } from '@/lib/api';

function LoginCard() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const nextParam = searchParams.get('next') || '/dashboard';
  const inputRef = useRef<HTMLInputElement>(null);
  const [key, setKey] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // If already authenticated, skip the form and follow ?next.
  useEffect(() => {
    if (hasAuth()) {
      router.replace(nextParam);
      return;
    }
    inputRef.current?.focus();
  }, [router, nextParam]);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const trimmed = key.trim();
    if (!trimmed) {
      setError('API key required');
      inputRef.current?.focus();
      return;
    }
    setBusy(true);
    try {
      setApiKey(trimmed);
      router.replace(nextParam);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to set API key';
      setError(msg);
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen flex items-center justify-center bg-[#0a0a0b] text-zinc-200 px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-semibold tracking-tight text-zinc-100">AEGIS</h1>
          <p className="text-sm text-zinc-500 mt-2">Sign in with your API key</p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="bg-[#18181B] border border-white/[0.06] rounded-2xl p-6 space-y-4 shadow-xl"
        >
          <div>
            <label htmlFor="api-key" className="block text-xs uppercase tracking-wider text-zinc-400 mb-2">
              API Key
            </label>
            <input
              ref={inputRef}
              id="api-key"
              type="password"
              autoComplete="off"
              spellCheck={false}
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="aegis_..."
              className="w-full px-3 py-2 rounded-lg bg-[#0a0a0b] border border-white/[0.08] text-zinc-100 focus:outline-none focus:border-cyan-500/60 transition-colors font-mono text-sm"
              aria-invalid={!!error}
              aria-describedby={error ? 'login-error' : undefined}
            />
          </div>

          {error && (
            <p id="login-error" className="text-sm text-red-400" role="alert">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={busy}
            className="w-full px-4 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed text-zinc-900 font-medium transition-colors"
          >
            {busy ? 'Signing in…' : 'Sign in'}
          </button>

          <div className="pt-2 text-center border-t border-white/[0.06]">
            <Link
              href="/dashboard/guide"
              className="inline-block mt-3 text-sm text-zinc-400 hover:text-zinc-200 transition-colors"
            >
              Continue as guest →
            </Link>
          </div>
        </form>

        {nextParam !== '/dashboard' && (
          <p className="text-xs text-zinc-500 text-center mt-4">
            You&apos;ll be redirected to <code className="font-mono text-zinc-400">{nextParam}</code> after sign-in
          </p>
        )}
      </div>
    </main>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-[#0a0a0b]" />}>
      <LoginCard />
    </Suspense>
  );
}
