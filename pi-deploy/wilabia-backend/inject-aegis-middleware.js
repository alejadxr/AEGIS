#!/usr/bin/env node
/**
 * Idempotent patcher for ~/wilabia-original/backend/src/index.js
 * Inserts the AEGIS unified-feed middleware after the CORS block and before
 * the rate-limiter chain (per recon report — file is at line 152 end of cors).
 */
const fs = require('fs');
const TARGET = '/Users/alejandxr/wilabia-original/backend/src/index.js';

const src = fs.readFileSync(TARGET, 'utf8');
if (src.includes('AEGIS unified-feed middleware')) {
  console.log('AEGIS middleware already injected — skipping');
  process.exit(0);
}

// Match the anchor with flexible whitespace around the closing }));
const ANCHOR_RE = /allowedHeaders: \['Content-Type', 'Authorization', 'X-Filename', 'X-Push-Endpoint', 'Cache-Control', 'Pragma'\]\r?\n\}\)\);\r?\n/;
const m = src.match(ANCHOR_RE);
if (!m) {
  console.error('ERROR: anchor not found in target file (cors block end)');
  process.exit(1);
}
const ANCHOR = m[0];

const BLOCK = `
// === AEGIS unified-feed middleware ===
// Emits one JSON line per request to /Users/alejandxr/web-logs/aegis-feed.jsonl
// which AEGIS log_watcher tails. trust proxy=1 is already set on line 71 so
// req.ip resolves the real client IP from cf-connecting-ip / x-forwarded-for.
// Listens on res.on('finish') so the response status is correct.
app.use((req, res, next) => {
  res.on('finish', () => {
    try {
      const ip = req.headers['cf-connecting-ip']
                 || (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
                 || req.ip;
      const record = {
        ts: new Date().toISOString(),
        app: 'wilabia-backend',
        src_ip: ip,
        method: req.method,
        path: req.originalUrl,
        status: res.statusCode,
      };
      const ua = (req.headers['user-agent'] || '').substring(0, 300);
      const host = req.headers['host'] || '';
      const ref = req.headers['referer'] || '';
      const fwd = req.headers['x-forwarded-for'] || '';
      const cfray = req.headers['cf-ray'] || '';
      const country = req.headers['cf-ipcountry'] || '';
      if (ua) record.ua = ua;
      if (host) record.host = host;
      if (ref) record.ref = ref;
      if (fwd) record.fwd_chain = fwd;
      if (cfray) record.cf_ray = cfray;
      if (country) record.country = country;
      fs.appendFileSync('/Users/alejandxr/web-logs/aegis-feed.jsonl', JSON.stringify(record) + '\\n');
    } catch (_) { /* never let logging take down the request */ }
  });
  next();
});

`;

const out = src.replace(ANCHOR, ANCHOR + BLOCK);
fs.writeFileSync(TARGET, out);
console.log(`OK: injected ${BLOCK.length} bytes`);
