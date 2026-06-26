'use client';

import { Suspense, useEffect, useRef, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { ShieldCheck, KeyRound, ArrowRight, AlertCircle } from 'lucide-react';
import { setApiKey, hasAuth } from '@/lib/api';

const BUILD_VERSION = '1.6.3.3';

function StatusPing() {
  return (
    <span className="inline-flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-[0.18em] text-emerald-400/80">
      <span className="relative inline-flex h-1.5 w-1.5">
        <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-500 opacity-60 animate-ping" />
        <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-500" />
      </span>
      LIVE
    </span>
  );
}

function LoginCard() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const nextParam = searchParams.get('next') || '/dashboard';
  const inputRef = useRef<HTMLInputElement>(null);
  const [key, setKey] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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
    if (trimmed.length < 16) {
      setError('Key looks too short — paste the full token');
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
    <main className="relative min-h-screen flex items-center justify-center bg-background text-foreground px-4 overflow-hidden">
      {/* Ambient brand-orange glow, top-left */}
      <div
        className="pointer-events-none absolute -top-40 -left-40 h-[420px] w-[420px] rounded-full blur-3xl opacity-30"
        style={{
          background:
            'radial-gradient(circle at center, #F97316 0%, rgba(249,115,22,0.2) 40%, transparent 70%)',
        }}
        aria-hidden
      />
      {/* Faint grid overlay */}
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.04]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(255,255,255,0.5) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.5) 1px, transparent 1px)',
          backgroundSize: '32px 32px',
        }}
        aria-hidden
      />

      <div className="relative w-full max-w-[420px]">
        {/* Brand block */}
        <div className="mb-7 flex flex-col items-center text-center">
          <div className="flex items-center gap-2.5 mb-4">
            <div className="grid place-items-center h-9 w-9 rounded-xl bg-[#F97316]/15 border border-[#F97316]/30 text-[#F97316]">
              <ShieldCheck size={18} strokeWidth={2.25} />
            </div>
            <span className="text-2xl font-semibold tracking-[-0.02em] text-foreground">AEGIS</span>
          </div>
          <p className="text-[13px] text-muted-foreground/85 leading-snug max-w-[280px]">
            Sign in to your operator console. Your API key never leaves the browser — it&apos;s stored
            in localStorage and sent on every request.
          </p>
        </div>

        {/* Form card */}
        <form
          onSubmit={handleSubmit}
          className="bg-card border border-border/60 rounded-2xl p-6 space-y-5 shadow-2xl shadow-black/40 backdrop-blur-sm"
        >
          <div className="flex items-center justify-between">
            <label
              htmlFor="api-key"
              className="text-[10px] font-mono uppercase tracking-[0.18em] text-muted-foreground/70"
            >
              API Key
            </label>
            <StatusPing />
          </div>

          <div className="relative">
            <KeyRound
              size={15}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground/60"
              aria-hidden
            />
            <input
              ref={inputRef}
              id="api-key"
              type="password"
              autoComplete="off"
              spellCheck={false}
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="c6_..."
              className="w-full pl-9 pr-3 py-2.5 rounded-lg bg-background/80 border border-border/60 text-foreground placeholder:text-muted-foreground/35 focus:outline-none focus:border-[#F97316]/60 focus:ring-2 focus:ring-[#F97316]/15 transition-colors font-mono text-[13px] tabular-nums"
              aria-invalid={!!error}
              aria-describedby={error ? 'login-error' : undefined}
              disabled={busy}
            />
          </div>

          {error && (
            <div
              id="login-error"
              role="alert"
              className="flex items-start gap-2 px-3 py-2 rounded-md bg-red-500/10 border border-red-500/30"
            >
              <AlertCircle size={13} className="text-red-400 mt-0.5 shrink-0" aria-hidden />
              <p className="text-[12px] text-red-300/90">{error}</p>
            </div>
          )}

          <button
            type="submit"
            disabled={busy}
            className="group w-full inline-flex items-center justify-center gap-1.5 px-4 py-2.5 rounded-lg bg-[#F97316] hover:bg-[#F97316]/90 disabled:opacity-50 disabled:cursor-not-allowed text-black font-medium text-[13px] transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#F97316]/60 focus-visible:ring-offset-2 focus-visible:ring-offset-card"
          >
            {busy ? (
              <>
                <span className="h-3 w-3 rounded-full border-2 border-black/30 border-t-black animate-spin" aria-hidden />
                <span>Signing in</span>
              </>
            ) : (
              <>
                <span>Sign in</span>
                <ArrowRight
                  size={14}
                  className="transition-transform duration-150 group-hover:translate-x-0.5"
                  aria-hidden
                />
              </>
            )}
          </button>

          <div className="pt-1 flex items-center justify-between text-[11px] text-muted-foreground/65">
            <Link
              href="/dashboard/guide"
              className="inline-flex items-center gap-1 hover:text-foreground transition-colors"
            >
              Continue as guest
              <ArrowRight size={11} aria-hidden />
            </Link>
            <a
              href="https://github.com/alejadxr/AEGIS#api-keys"
              target="_blank"
              rel="noreferrer noopener"
              className="hover:text-foreground transition-colors"
            >
              Where do I get a key?
            </a>
          </div>
        </form>

        {/* Footer meta */}
        <div className="mt-5 flex items-center justify-between text-[10px] font-mono uppercase tracking-[0.18em] text-muted-foreground/45">
          <span>v{BUILD_VERSION}</span>
          {nextParam !== '/dashboard' ? (
            <span>
              next →{' '}
              <code className="font-mono text-muted-foreground/70 normal-case tracking-normal">
                {nextParam}
              </code>
            </span>
          ) : (
            <span>autonomous defense</span>
          )}
        </div>
      </div>
    </main>
  );
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-background grid place-items-center">
          <div className="h-5 w-5 rounded-full border-2 border-border border-t-[#F97316] animate-spin" />
        </div>
      }
    >
      <LoginCard />
    </Suspense>
  );
}
