'use client';

import { useState, useEffect, useRef } from 'react';
import { useRouter } from 'next/navigation';
import { setApiKey, setJwtToken, hasAuth, api } from '@/lib/api';
import Link from 'next/link';
import { Lock, ShieldCheck, Fingerprint, Mail, KeyRound } from 'lucide-react';

type AuthMode = 'apikey' | 'login';

export default function LoginPage() {
  const router = useRouter();
  const [authMode, setAuthMode] = useState<AuthMode>('apikey');
  const [key, setKey] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);
  const [mounted, setMounted] = useState(false);
  const apiKeyInputRef = useRef<HTMLInputElement>(null);
  const emailInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (hasAuth()) {
      router.push('/dashboard');
    } else {
      setChecking(false);
      setTimeout(() => setMounted(true), 50);
      setTimeout(() => apiKeyInputRef.current?.focus(), 600);
    }
  }, [router]);

  // Focus appropriate input when switching modes
  useEffect(() => {
    if (!checking && mounted) {
      setTimeout(() => {
        if (authMode === 'apikey') {
          apiKeyInputRef.current?.focus();
        } else {
          emailInputRef.current?.focus();
        }
      }, 100);
    }
  }, [authMode, checking, mounted]);

  const handleApiKeyConnect = async () => {
    if (!key.trim()) {
      setError('API key is required');
      return;
    }
    setLoading(true);
    setError('');
    try {
      // Clear any stale tokens before login
      localStorage.removeItem('aegis_jwt_token');
      setApiKey(key.trim());
      const result = await api.auth.login(key.trim());
      // Store the JWT token from API key login for future requests
      if (result.token) {
        setJwtToken(result.token);
      }
      router.push('/dashboard');
    } catch {
      // Still set the key and navigate (API key auth works via X-API-Key header)
      setApiKey(key.trim());
      router.push('/dashboard');
    } finally {
      setLoading(false);
    }
  };

  const handleLoginConnect = async () => {
    if (!email.trim()) {
      setError('Email is required');
      return;
    }
    if (!password) {
      setError('Password is required');
      return;
    }
    setLoading(true);
    setError('');
    try {
      // Clear any stale tokens before login
      localStorage.removeItem('aegis_api_key');
      localStorage.removeItem('aegis_jwt_token');
      const result = await api.auth.loginCredentials(email.trim(), password);
      if (result.token) {
        setJwtToken(result.token);
      }
      router.push('/dashboard');
    } catch {
      setError('Invalid email or password');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      if (authMode === 'apikey') {
        handleApiKeyConnect();
      } else {
        handleLoginConnect();
      }
    }
  };

  if (checking) {
    return (
      <div className="min-h-screen c6-page flex items-center justify-center">
        <div className="w-5 h-5 border-2 border-white/10 border-t-[#22D3EE] rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="min-h-screen c6-page flex items-center justify-center p-4 relative overflow-hidden">
      {/* Background radial glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] rounded-full pointer-events-none"
        style={{ background: 'radial-gradient(circle, rgba(34,211,238,0.04) 0%, transparent 70%)' }}
      />
      <div className="absolute top-1/4 right-1/4 w-[400px] h-[400px] rounded-full pointer-events-none"
        style={{ background: 'radial-gradient(circle, rgba(249,115,22,0.03) 0%, transparent 70%)' }}
      />

      <div
        className={`relative w-full max-w-md z-10 transition-all duration-700 ease-out ${
          mounted ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-6'
        }`}
      >
        {/* Logo & Title */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl c6-card mb-6">
            <span className="font-mono text-[#22D3EE] text-xl font-semibold tracking-wider">C6</span>
          </div>
          <h1 className="text-5xl font-bold tracking-tight">
            <span className="c6-logo-gradient">AEGIS</span>
          </h1>
          <p className="mt-3 text-zinc-500 text-sm font-medium">
            Autonomous Defense Platform
          </p>
        </div>

        {/* Login Card */}
        <div className="c6-card p-8 space-y-6">
          {/* Auth Mode Toggle */}
          <div className="flex rounded-xl bg-[#09090B] border border-white/[0.06] p-1">
            <button
              onClick={() => { setAuthMode('apikey'); setError(''); }}
              className={`flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-[13px] font-medium transition-all duration-200 ${
                authMode === 'apikey'
                  ? 'bg-white/[0.06] text-[#22D3EE] shadow-sm'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              <KeyRound className="w-3.5 h-3.5" />
              API Key
            </button>
            <button
              onClick={() => { setAuthMode('login'); setError(''); }}
              className={`flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-[13px] font-medium transition-all duration-200 ${
                authMode === 'login'
                  ? 'bg-white/[0.06] text-[#22D3EE] shadow-sm'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              <Mail className="w-3.5 h-3.5" />
              Login
            </button>
          </div>

          {/* API Key Mode */}
          {authMode === 'apikey' && (
            <div>
              <label className="block text-xs font-medium text-zinc-400 mb-2">
                API Key
              </label>
              <div className="relative">
                <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-600" />
                <input
                  ref={apiKeyInputRef}
                  type="password"
                  value={key}
                  onChange={(e) => { setKey(e.target.value); setError(''); }}
                  onKeyDown={handleKeyDown}
                  placeholder="Enter your API key"
                  className="w-full c6-input rounded-xl px-4 py-3 pl-11 text-sm focus:outline-none focus:border-[#22D3EE]/40 focus:ring-1 focus:ring-[#22D3EE]/20 transition-all duration-200"
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>
            </div>
          )}

          {/* Login Mode */}
          {authMode === 'login' && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-zinc-400 mb-2">
                  Email
                </label>
                <div className="relative">
                  <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-600" />
                  <input
                    ref={emailInputRef}
                    type="email"
                    value={email}
                    onChange={(e) => { setEmail(e.target.value); setError(''); }}
                    onKeyDown={handleKeyDown}
                    placeholder="admin@organization.com"
                    className="w-full c6-input rounded-xl px-4 py-3 pl-11 text-sm focus:outline-none focus:border-[#22D3EE]/40 focus:ring-1 focus:ring-[#22D3EE]/20 transition-all duration-200"
                    autoComplete="email"
                    spellCheck={false}
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-zinc-400 mb-2">
                  Password
                </label>
                <div className="relative">
                  <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-600" />
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => { setPassword(e.target.value); setError(''); }}
                    onKeyDown={handleKeyDown}
                    placeholder="Enter your password"
                    className="w-full c6-input rounded-xl px-4 py-3 pl-11 text-sm focus:outline-none focus:border-[#22D3EE]/40 focus:ring-1 focus:ring-[#22D3EE]/20 transition-all duration-200"
                    autoComplete="current-password"
                  />
                </div>
              </div>
            </div>
          )}

          {error && (
            <p className="text-[#EF4444] text-xs font-medium">{error}</p>
          )}

          <button
            onClick={authMode === 'apikey' ? handleApiKeyConnect : handleLoginConnect}
            disabled={loading}
            className="w-full bg-[#22D3EE] hover:bg-[#06B6D4] disabled:opacity-50 disabled:cursor-not-allowed text-[#09090B] font-semibold py-3 rounded-xl transition-all duration-200 hover:shadow-lg hover:shadow-[#22D3EE]/10 active:scale-[0.98]"
          >
            {loading ? (
              <span className="flex items-center justify-center gap-2">
                <span className="w-4 h-4 border-2 border-[#09090B]/30 border-t-[#09090B] rounded-full animate-spin" />
                {authMode === 'apikey' ? 'Connecting...' : 'Signing in...'}
              </span>
            ) : (
              authMode === 'apikey' ? 'Connect' : 'Sign In'
            )}
          </button>
        </div>

        {/* Trust badges */}
        <div className="flex items-center justify-center gap-8 mt-8">
          {[
            { icon: Lock, label: 'Encrypted' },
            { icon: ShieldCheck, label: 'Zero Trust' },
            { icon: Fingerprint, label: 'SOC2' },
          ].map(({ icon: Icon, label }) => (
            <div key={label} className="flex items-center gap-2">
              <Icon className="w-3.5 h-3.5 text-zinc-600" />
              <span className="text-xs text-zinc-600 font-medium">{label}</span>
            </div>
          ))}
        </div>

        <div className="text-center mt-8 space-y-3">
          <Link
            href="/setup"
            className="inline-flex items-center gap-1.5 text-xs text-zinc-500 hover:text-[#22D3EE] transition-colors font-medium"
          >
            First time? Set up AEGIS
            <span className="text-[10px]">&rarr;</span>
          </Link>
          <p className="text-xs text-zinc-700">
            AEGIS Defense Platform &middot; v1.0.0
          </p>
        </div>
      </div>
    </div>
  );
}
