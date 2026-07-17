/**
 * AEGIS PM2 ecosystem — Mac Pro production.
 *
 * ============================================================================
 * WHY THIS FILE EXISTS: the bash-wrapper memory-monitoring bug
 * ============================================================================
 * The previous launch command was effectively:
 *
 *     pm2 start "/bin/bash -c 'source venv/bin/activate && python -m uvicorn ...'"
 *
 * PM2 monitors the RSS of the process it directly spawns. With a bash wrapper,
 * that process is `/bin/bash` (~1 MB RSS) — NOT the uvicorn Python worker it
 * forks as a child. So `max_memory_restart` was comparing ~1 MB against its
 * threshold and NEVER firing. The Python worker was free to grow to 3.2 GB
 * over 15 h with the safety valve permanently disarmed.
 *
 * THE FIX: point `script` directly at the venv Python binary and set
 * `interpreter: "none"` so PM2 does not wrap it in a Node shim. Now the
 * process PM2 monitors IS the uvicorn worker, so `max_memory_restart` sees the
 * real RSS and actually fires.
 *
 * ============================================================================
 * MEMORY CEILING RATIONALE
 * ============================================================================
 * Diagnosis baseline: ~950 MB (range 810–1170 MB), dominated by the GeoIP City
 * CSV (600–800 MB) plus GeoIP ASN, Sigma rules, behavioral-ML models and the
 * PG connection pool. A clean, healthy process sits around 1.0–1.2 GB.
 *
 * We set max_memory_restart = 2000M: ~800 MB of headroom above the high-end
 * baseline (won't false-positive OOM a healthy worker on a busy day) but well
 * below the 3.2 GB runaway point, so a real leak restarts the worker long
 * before it becomes a problem. Pair with the in-code structure fixes
 * (bounded dicts + task tracking) so restarts are a backstop, not the plan.
 *
 * ============================================================================
 * DEPLOY (operator runs this — do NOT auto-apply):
 *   pm2 delete cayde6-api cayde6-frontend
 *   pm2 start /Users/alejandxr/Cayde-6/ecosystem.config.js
 *   pm2 save
 * ============================================================================
 *
 * Secrets: NONE live here. API keys / DB URLs stay in backend/.env, loaded by
 * the app (pydantic-settings). Only non-secret operational flags are set below.
 */

// Absolute prod root on Mac Pro (macOS, user `alejandxr`). NOT /root/... —
// the diagnosis assumed a Linux layout; the real prod host is macOS.
const AEGIS_ROOT = "/Users/alejandxr/Cayde-6";

module.exports = {
  apps: [
    {
      // ----------------------------------------------------------------------
      // Backend API — uvicorn worker, monitored DIRECTLY by PM2.
      // ----------------------------------------------------------------------
      name: "cayde6-api",
      // Point straight at the venv interpreter so PM2 tracks the Python worker
      // RSS (this is the whole point — see header comment).
      script: `${AEGIS_ROOT}/backend/venv/bin/python`,
      args: "-m uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1",
      cwd: `${AEGIS_ROOT}/backend`,
      // Tell PM2 NOT to prepend its own Node interpreter — `script` is already
      // a native executable.
      interpreter: "none",

      env: {
        PYTHONPATH: `${AEGIS_ROOT}/backend`,
        PYTHONUNBUFFERED: "1",
        // Operational flags only — real secrets live in backend/.env.
        AEGIS_AI_MODE: "offline",
        AEGIS_REAL_FW: "1",
      },

      // Memory safety valve — now actually armed (see rationale above).
      max_memory_restart: "2000M",

      // Restart hygiene: brief backoff, cap restart storms.
      autorestart: true,
      restart_delay: 3000,
      max_restarts: 10,
      min_uptime: "20s",
      watch: false,
      kill_timeout: 8000,

      // Logs (PM2 default location unless overridden by the operator).
      time: true,
    },

    {
      // ----------------------------------------------------------------------
      // Frontend — Next.js 14 via `next start` (NOT standalone; port 3007).
      // Node process, so PM2 monitors it correctly out of the box. A ceiling
      // is still set as a cheap backstop.
      // ----------------------------------------------------------------------
      name: "cayde6-frontend",
      // Invoke the local Next binary directly (equivalent to `npx next start`)
      // so PM2 monitors the Next server process itself.
      script: `${AEGIS_ROOT}/frontend/node_modules/next/dist/bin/next`,
      args: "start -p 3007",
      cwd: `${AEGIS_ROOT}/frontend`,
      interpreter: "node",

      env: {
        NODE_ENV: "production",
        PORT: "3007",
      },

      // Next.js prod server is comparatively light; 1 GB is generous headroom.
      max_memory_restart: "1000M",

      autorestart: true,
      restart_delay: 3000,
      max_restarts: 10,
      min_uptime: "20s",
      watch: false,
      kill_timeout: 8000,
      time: true,
    },
  ],
};
