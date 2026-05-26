import { NextRequest, NextResponse } from 'next/server'

// AEGIS access-log middleware (Next.js Edge runtime — no fs APIs available).
// Emits one [AEGIS] JSON line per request to stdout. PM2 redirects stdout to
// /Users/alejandxr/web-logs/landing-wilab.log which AEGIS log_watcher tails
// via AEGIS_EXTRA_LOG_PATHS. Schema mirrors the unified feed.
export function middleware(request: NextRequest) {
  const ip =
    request.headers.get('cf-connecting-ip') ||
    request.headers.get('x-real-ip') ||
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    'unknown'
  const ua = request.headers.get('user-agent') || '-'
  const path = request.nextUrl.pathname + request.nextUrl.search
  const record: Record<string, unknown> = {
    ts: new Date().toISOString(),
    app: 'landing-wilab',
    src_ip: ip,
    method: request.method,
    path,
    status: 200,
  }
  const country = request.headers.get('cf-ipcountry')
  const ref = request.headers.get('referer')
  const host = request.headers.get('host')
  const fwd = request.headers.get('x-forwarded-for')
  const cfray = request.headers.get('cf-ray')
  if (ua && ua !== '-') record.ua = ua
  if (country) record.country = country
  if (ref) record.ref = ref
  if (host) record.host = host
  if (fwd) record.fwd_chain = fwd
  if (cfray) record.cf_ray = cfray
  console.log('[AEGIS] ' + JSON.stringify(record))
  return NextResponse.next()
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|_next/data).*)'],
}
