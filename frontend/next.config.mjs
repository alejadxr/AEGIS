import { createRequire } from 'module';

// v1.6.4.8: expose the real package version to the client so it can never be
// hand-typed stale again (TopNav/CommandBar/JSON-LD previously hardcoded
// "v1.6.2" in five separate places). createRequire (not the `with { type:
// "json" }` import-attribute syntax) so this works regardless of the Node
// version running next build in any given environment.
const require = createRequire(import.meta.url);
const pkg = require('./package.json');

/** @type {import('next').NextConfig} */
const nextConfig = {
  env: {
    NEXT_PUBLIC_AEGIS_VERSION: pkg.version,
  },
};

export default nextConfig;
