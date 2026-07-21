'use client';

/**
 * The single sign-in surface.
 *
 * There used to be two: this route and `/` (a 288-line near-duplicate). Only
 * this one was ever routed to — `dashboard/layout.tsx`, `dashboard/firewall`
 * and `DemoModeBanner` all redirect to `/login?next=…` — yet the ORPHANED copy
 * was the more capable one: it supported email/password auth while this route
 * only took an API key. So the canonical login was the weaker login.
 *
 * Both modes now live here, `/` is a redirect, and there is one place to change
 * auth behaviour.
 */

import { Suspense, useEffect, useRef, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { ShieldCheck, KeyRound, ArrowRight, AlertCircle, Mail, Lock } from 'lucide-react';
import { setApiKey, setJwtToken, hasAuth, api } from '@/lib/api';

// Read from package.json via next.config.mjs — this used to be hand-typed and had
// drifted to 1.6.3.3 while the product shipped 1.6.4.8.
const BUILD_VERSION = process.env.NEXT_PUBLIC_AEGIS_VERSION || '';

type AuthMode = 'apikey' | 'credentials';

function StatusPing() {
  return (
    <span className="inline-flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-[0.18em] text-emerald-400/80">
      <span className="relative inline-flex h-1.5 w-1.5">
        <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-500 opacity-60 motion-safe:animate-ping" />
        <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-500" />
      </span>
      LIVE
    </span>
  );
}

const FIELD_CLASS =
  'w-full pl-9 pr-3 py-2.5 rounded-lg bg-background/80 border border-border/60 text-foreground ' +
  'placeholder:text-muted-foreground/35 focus:outline-none focus:border-[#F97316]/60 ' +
  'focus:ring-2 focus:ring-[#F97316]/15 transition-colors text-[13px]';

function LoginCard() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const nextParam = searchParams.get('next') || '/dashboard';

  const [mode, setMode] = useState<AuthMode>('apikey');
  const [key, setKey] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const keyRef = useRef<HTMLInputElement>(null);
  const emailRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (hasAuth()) {
      router.replace(nextParam);
      return;
    }
    (mode === 'apikey' ? keyRef : emailRef).current?.focus();
  }, [router, nextParam, mode]);

  function switchMode(next: AuthMode) {
    setMode(next);
    setError(null);
  }

  async function submitApiKey() {
    const trimmed = key.trim();
    if (!trimmed) {
      setError('API key required');
      keyRef.current?.focus();
      return;
    }
    if (trimmed.length < 16) {
      setError('Key looks too short — paste the full token');
      keyRef.current?.focus();
      return;
    }
    setBusy(true);
    try {
      localStorage.removeItem('aegis_jwt_token');
      setApiKey(trimmed);
      // Exchange the key for a JWT when the backend supports it. If that call
      // fails the key itself is still valid auth (sent as X-API-Key on every
      // request), so we proceed rather than blocking the operator on it.
      try {
        const result = await api.auth.login(trimmed);
        if (result?.token) setJwtToken(result.token);
      } catch {
        // key-only auth — fine
      }
      router.replace(nextParam);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to set API key');
      setBusy(false);
    }
  }

  async function submitCredentials() {
    if (!email.trim()) {
      setError('Email required');
      emailRef.current?.focus();
      return;
    }
    if (!password) {
      setError('Password required');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      localStorage.removeItem('aegis_api_key');
      localStorage.removeItem('aegis_jwt_token');
      const result = await api.auth.loginCredentials(email.trim(), password);
      if (result?.token) setJwtToken(result.token);
      router.replace(nextParam);
    } catch {
      setError('Invalid email or password');
      setBusy(false);
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (mode === 'apikey') void submitApiKey();
    else void submitCredentials();
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
          <p className="text-[13px] text-muted-foreground/85 leading-snug max-w-[300px]">
            {mode === 'apikey'
              ? 'Sign in to your operator console. Your API key never leaves the browser — it’s stored in localStorage and sent on every request.'
              : 'Sign in with your operator account. Credentials are exchanged for a session token; the password is never stored.'}
          </p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="bg-card border border-border/60 rounded-2xl p-6 space-y-5 shadow-2xl shadow-black/40 backdrop-blur-sm"
        >
          {/* Mode switch — a real radiogroup, not two styled divs, so it is
              keyboard-operable and announced correctly. */}
          <div
            role="radiogroup"
            aria-label="Authentication method"
            className="grid grid-cols-2 gap-1 p-1 rounded-lg bg-background/60 border border-border/50"
          >
            {([
              { id: 'apikey', label: 'API Key' },
              { id: 'credentials', label: 'Email' },
            ] as Array<{ id: AuthMode; label: string }>).map((opt) => {
              const active = mode === opt.id;
              return (
                <button
                  key={opt.id}
                  type="button"
                  role="radio"
                  aria-checked={active}
                  onClick={() => switchMode(opt.id)}
                  disabled={busy}
                  className={
                    'rounded-md py-1.5 text-[11px] font-mono uppercase tracking-[0.14em] transition-colors ' +
                    (active
                      ? 'bg-[#F97316]/15 text-[#F97316] border border-[#F97316]/30'
                      : 'text-muted-foreground/70 border border-transparent hover:text-foreground')
                  }
                >
                  {opt.label}
                </button>
              );
            })}
          </div>

          {mode === 'apikey' ? (
            <>
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
                  ref={keyRef}
                  id="api-key"
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  value={key}
                  onChange={(e) => setKey(e.target.value)}
                  placeholder="c6_..."
                  className={`${FIELD_CLASS} font-mono tabular-nums`}
                  aria-invalid={!!error}
                  aria-describedby={error ? 'login-error' : undefined}
                  disabled={busy}
                />
              </div>
            </>
          ) : (
            <>
              <div className="flex items-center justify-between">
                <label
                  htmlFor="email"
                  className="text-[10px] font-mono uppercase tracking-[0.18em] text-muted-foreground/70"
                >
                  Operator account
                </label>
                <StatusPing />
              </div>
              <div className="relative">
                <Mail
                  size={15}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground/60"
                  aria-hidden
                />
                <input
                  ref={emailRef}
                  id="email"
                  type="email"
                  autoComplete="username"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="operator@example.com"
                  className={FIELD_CLASS}
                  aria-invalid={!!error}
                  aria-describedby={error ? 'login-error' : undefined}
                  disabled={busy}
                />
              </div>
              <div className="relative">
                <Lock
                  size={15}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground/60"
                  aria-hidden
                />
                <input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Password"
                  className={FIELD_CLASS}
                  aria-invalid={!!error}
                  disabled={busy}
                />
              </div>
            </>
          )}

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
                <span
                  className="h-3 w-3 rounded-full border-2 border-black/30 border-t-black motion-safe:animate-spin"
                  aria-hidden
                />
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
          <div className="h-5 w-5 rounded-full border-2 border-border border-t-[#F97316] motion-safe:animate-spin" />
        </div>
      }
    >
      <LoginCard />
    </Suspense>
  );
}
