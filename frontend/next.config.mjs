import { createRequire } from 'module';

// v1.6.4.8: expose the real package version to the client so it can never be
// hand-typed stale again (TopNav/CommandBar/JSON-LD previously hardcoded
// "v1.6.2" in five separate places). createRequire (not the `with { type:
// "json" }` import-attribute syntax) so this works regardless of the Node
// version running next build in any given environment.
const require = createRequire(import.meta.url);
const pkg = require('./package.json');

const securityHeaders = [
  // The dashboard is never meant to be framed: clickjacking an "approve
  // action" or "unblock" button is the obvious abuse.
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Content-Security-Policy', value: "frame-ancestors 'none'" },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
];

/** @type {import('next').NextConfig} */
const nextConfig = {
  env: {
    NEXT_PUBLIC_AEGIS_VERSION: pkg.version,
  },
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};

export default nextConfig;
