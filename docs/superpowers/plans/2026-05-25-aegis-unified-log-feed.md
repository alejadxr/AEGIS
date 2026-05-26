# AEGIS Unified Log Feed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every public-facing Wilab web app emit one structured access-log line per HTTP request to a single real-time file at `/Users/alejandxr/web-logs/aegis-feed.jsonl`, with real client IP and full request context, so AEGIS gets complete HTTP-layer visibility from one tail target.

**Architecture:** Each app is responsible for writing one JSON-line per request to the shared feed file via append-mode (atomic on POSIX for lines <4KB). Existing per-app logs stay untouched (no regression risk). AEGIS reads ONLY the feed via `AEGIS_EXTRA_LOG_PATHS`. A shared helper module on Mac Pro (Python + Node) standardizes the schema. Logrotate keeps file under 200MB with hourly rotation.

**Tech Stack:** Python 3.13 (stdlib http.server), Node.js 20 (Express middleware), Next.js 14 middleware, FastAPI middleware, logrotate, PM2.

---

## Unified Schema

Every line is one JSON object terminated by `\n`. Mandatory fields are non-empty strings/numbers. Optional fields may be omitted.

```json
{
  "ts": "2026-05-25T23:00:00.123Z",
  "app": "sable",
  "src_ip": "203.0.113.42",
  "method": "GET",
  "path": "/wp-admin/setup-config.php",
  "status": 404,
  "bytes": 1234,
  "rt_ms": 12,
  "ua": "Mozilla/5.0 ...",
  "ref": "https://...",
  "host": "sable.somoswilab.com",
  "fwd_chain": "203.0.113.42, 100.64.0.5",
  "country": "US",
  "proto": "https",
  "cf_ray": "8a1b2c3d4e5f-MIA"
}
```

Mandatory: `ts`, `app`, `src_ip`, `method`, `path`, `status`.
Optional: rest (omit if unknown — do NOT emit empty strings except for `ua`/`ref` which AEGIS Sigma rules check).

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `/Users/alejandxr/web-logs/aegis-feed.jsonl` | CREATE (runtime) | Append-only unified feed |
| `/Users/alejandxr/aegis-feed/feed_writer.py` | CREATE | Python helper (used by web-server-logger.py and any FastAPI app) |
| `/Users/alejandxr/aegis-feed/feed_writer.js` | CREATE | Node helper (used by Express + Next.js middleware) |
| `/Users/alejandxr/web-server-logger.py` | MODIFY | Call feed_writer for every request |
| `RemoteProjects/MacPro/Sable/src/middleware.ts` | MODIFY | Dual-write `[HTTP]` line AND JSON to feed |
| `RemoteProjects/MacPro/landing-wilab/src/middleware.ts` | CREATE | New access-log middleware writing to feed |
| `RemoteProjects/MacPro/wilabia-original/server.js` (backend) | MODIFY | `trust proxy` + morgan custom format → feed |
| `RemoteProjects/MacPro/sid-wilab/backend/app/main.py` | MODIFY | FastAPI middleware → feed |
| `/etc/newsyslog.d/aegis-feed.conf` (Mac Pro) | CREATE | Rotation: hourly, keep 24, gzip |
| `RemoteProjects/Laboratorio/Cayde-6/backend/.env` | MODIFY | Add `AEGIS_EXTRA_LOG_PATHS=/Users/alejandxr/web-logs/aegis-feed.jsonl` |
| `RemoteProjects/Laboratorio/Cayde-6/backend/app/services/log_watcher.py` | MODIFY | Honor `AEGIS_EXTRA_LOG_PATHS` env var |

---

## Task 1: Create Python feed_writer helper

**Files:**
- Create: `/Users/alejandxr/aegis-feed/feed_writer.py` (on Mac Pro)
- Test: `/Users/alejandxr/aegis-feed/test_feed_writer.py`

- [ ] **Step 1: Write the failing test**

On Mac Pro create `/Users/alejandxr/aegis-feed/test_feed_writer.py`:

```python
import json, os, tempfile, time
from feed_writer import emit

def test_emit_minimal():
    with tempfile.NamedTemporaryFile(mode='r', suffix='.jsonl', delete=False) as f:
        path = f.name
    os.environ["AEGIS_FEED_PATH"] = path
    emit(app="testapp", src_ip="1.2.3.4", method="GET", path="/x", status=200)
    with open(path) as fh:
        line = fh.readline()
    rec = json.loads(line)
    assert rec["app"] == "testapp"
    assert rec["src_ip"] == "1.2.3.4"
    assert rec["method"] == "GET"
    assert rec["status"] == 200
    assert "ts" in rec and rec["ts"].endswith("Z")
    os.unlink(path)

def test_emit_skips_empty_optionals():
    with tempfile.NamedTemporaryFile(mode='r', suffix='.jsonl', delete=False) as f:
        path = f.name
    os.environ["AEGIS_FEED_PATH"] = path
    emit(app="t", src_ip="1.2.3.4", method="GET", path="/", status=200, country="")
    rec = json.loads(open(path).readline())
    assert "country" not in rec
    os.unlink(path)
```

- [ ] **Step 2: Run test to verify it fails**

```
python C:/Users/wilsd/remote-ssh.py mac "cd /Users/alejandxr/aegis-feed && python3 -m pytest test_feed_writer.py -v"
```

Expected: FAIL with `ModuleNotFoundError: No module named 'feed_writer'`.

- [ ] **Step 3: Write minimal implementation**

Create `/Users/alejandxr/aegis-feed/feed_writer.py`:

```python
"""AEGIS unified log feed writer (Python)."""
import json
import os
from datetime import datetime, timezone

DEFAULT_PATH = "/Users/alejandxr/web-logs/aegis-feed.jsonl"


def emit(*, app, src_ip, method, path, status, **optional):
    """Append one JSON line to the AEGIS feed. POSIX append is atomic up to PIPE_BUF (~4KB)."""
    record = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{datetime.now().microsecond // 1000:03d}Z",
        "app": app,
        "src_ip": src_ip,
        "method": method,
        "path": path,
        "status": int(status),
    }
    for k, v in optional.items():
        if v not in ("", None):
            record[k] = v
    line = json.dumps(record, ensure_ascii=False) + "\n"
    target = os.environ.get("AEGIS_FEED_PATH", DEFAULT_PATH)
    try:
        with open(target, "a", buffering=1) as f:  # line-buffered
            f.write(line)
    except OSError:
        pass  # never let logging take down the app
```

- [ ] **Step 4: Run test to verify it passes**

```
python C:/Users/wilsd/remote-ssh.py mac "cd /Users/alejandxr/aegis-feed && python3 -m pytest test_feed_writer.py -v"
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/plans/2026-05-25-aegis-unified-log-feed.md
# (feed_writer.py lives on Mac Pro outside this repo — track via pi-deploy mirror)
mkdir -p pi-deploy/aegis-feed
scp from Mac Pro back into repo for source-of-truth tracking
git add pi-deploy/aegis-feed/feed_writer.py pi-deploy/aegis-feed/test_feed_writer.py
git commit -m "feat(aegis-feed): Python writer for unified log feed"
```

---

## Task 2: Create Node feed_writer helper

**Files:**
- Create: `/Users/alejandxr/aegis-feed/feed_writer.js` (on Mac Pro)
- Test: `/Users/alejandxr/aegis-feed/feed_writer.test.js`
- Mirror to repo: `RemoteProjects/Laboratorio/Cayde-6/pi-deploy/aegis-feed/feed_writer.js`

- [ ] **Step 1: Write the failing test**

Create `/Users/alejandxr/aegis-feed/feed_writer.test.js`:

```javascript
const fs = require('fs');
const os = require('os');
const path = require('path');
const { emit } = require('./feed_writer');

test('emit writes a JSON line with mandatory fields', () => {
  const tmp = path.join(os.tmpdir(), `aegis-test-${Date.now()}.jsonl`);
  process.env.AEGIS_FEED_PATH = tmp;
  emit({ app: 'testapp', src_ip: '1.2.3.4', method: 'GET', path: '/x', status: 200 });
  const rec = JSON.parse(fs.readFileSync(tmp, 'utf8').trim());
  expect(rec.app).toBe('testapp');
  expect(rec.src_ip).toBe('1.2.3.4');
  expect(rec.status).toBe(200);
  expect(rec.ts).toMatch(/Z$/);
  fs.unlinkSync(tmp);
});

test('emit omits empty optionals', () => {
  const tmp = path.join(os.tmpdir(), `aegis-test2-${Date.now()}.jsonl`);
  process.env.AEGIS_FEED_PATH = tmp;
  emit({ app: 't', src_ip: '1.2.3.4', method: 'GET', path: '/', status: 200, country: '' });
  const rec = JSON.parse(fs.readFileSync(tmp, 'utf8').trim());
  expect(rec.country).toBeUndefined();
  fs.unlinkSync(tmp);
});
```

- [ ] **Step 2: Run test to verify it fails**

```
python C:/Users/wilsd/remote-ssh.py mac "cd /Users/alejandxr/aegis-feed && npx jest --no-coverage feed_writer.test.js 2>&1 | tail -5"
```

Expected: FAIL `Cannot find module './feed_writer'`.

- [ ] **Step 3: Write minimal implementation**

Create `/Users/alejandxr/aegis-feed/feed_writer.js`:

```javascript
'use strict';
const fs = require('fs');

const DEFAULT_PATH = '/Users/alejandxr/web-logs/aegis-feed.jsonl';

function _ts() {
  const d = new Date();
  return d.toISOString().replace(/(\.\d{3})Z$/, '$1Z'); // ms precision Z-terminated
}

function emit({ app, src_ip, method, path, status, ...optional }) {
  const record = { ts: _ts(), app, src_ip, method, path, status: Number(status) };
  for (const [k, v] of Object.entries(optional)) {
    if (v !== '' && v !== null && v !== undefined) record[k] = v;
  }
  const target = process.env.AEGIS_FEED_PATH || DEFAULT_PATH;
  try {
    fs.appendFileSync(target, JSON.stringify(record) + '\n');
  } catch (_) { /* never crash the app */ }
}

module.exports = { emit };
```

- [ ] **Step 4: Run test to verify it passes**

```
python C:/Users/wilsd/remote-ssh.py mac "cd /Users/alejandxr/aegis-feed && npx jest --no-coverage feed_writer.test.js 2>&1 | tail -5"
```

Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
# (scp the file back into repo)
git add pi-deploy/aegis-feed/feed_writer.js pi-deploy/aegis-feed/feed_writer.test.js
git commit -m "feat(aegis-feed): Node writer for unified log feed"
```

---

## Task 3: Wire web-server-logger.py to feed

The file at `/Users/alejandxr/web-server-logger.py` already extracts real client IPs from `Cf-Connecting-Ip` / `X-Forwarded-For`. It currently writes a single pipe-delimited line per request at line 180-191. Goal: ALSO write a JSON line to the unified feed without changing the existing per-app log behavior.

**Files:**
- Modify: `/Users/alejandxr/web-server-logger.py` (around lines 180-195)

- [ ] **Step 1: Read the current write block**

```
python C:/Users/wilsd/remote-ssh.py mac "sed -n '160,200p' /Users/alejandxr/web-server-logger.py"
```

Confirm the variables in scope (`real_ip`, `country`, `status`, `method`, `path`, `user_agent`, `attack_type`).

- [ ] **Step 2: Patch the script**

After the existing `with open(LOG_FILE, "a") as f: f.write(log_line + "\n")` block (~line 191), add:

```python
        # AEGIS unified feed (dual-write — non-fatal)
        try:
            import sys as _sys
            _sys.path.insert(0, "/Users/alejandxr/aegis-feed")
            from feed_writer import emit as _aegis_emit
            _app_name = os.environ.get("AEGIS_APP_NAME", "unknown")
            _aegis_emit(
                app=_app_name,
                src_ip=real_ip,
                method=self.command,
                path=self.path,
                status=int(getattr(self, "_last_status", 200)),
                ua=user_agent or "",
                ref=self.headers.get("Referer", "") or "",
                host=self.headers.get("Host", "") or "",
                country=country or "",
                fwd_chain=self.headers.get("X-Forwarded-For", "") or "",
                cf_ray=self.headers.get("Cf-Ray", "") or "",
                attack_type=attack_type or "",
            )
        except Exception:
            pass
```

The `_last_status` attribute: set it inside `do_GET` / `do_POST` right after `self.send_response(code)` so the emit picks the real status, otherwise defaults to 200. Add `self._last_status = code` before each `send_response(code)` call.

- [ ] **Step 3: Restart and smoke-test**

```
python C:/Users/wilsd/remote-ssh.py mac "echo 1108 | sudo -S pm2 restart sid wilabia-frontend && sleep 3 && curl -s -H 'Cf-Connecting-Ip: 198.51.100.42' http://localhost:3001/ -o /dev/null -w 'code=%{http_code}\n'"
```

Then verify:

```
python C:/Users/wilsd/remote-ssh.py mac "tail -1 /Users/alejandxr/web-logs/aegis-feed.jsonl | python3 -m json.tool"
```

Expected: a JSON record with `app: "sid"`, `src_ip: "198.51.100.42"`, `method: "GET"`, `path: "/"`, `status: 200`.

- [ ] **Step 4: Commit**

scp the modified `web-server-logger.py` back to the repo at `pi-deploy/web-server-logger.py` and:

```bash
git add pi-deploy/web-server-logger.py
git commit -m "feat(web-server-logger): dual-write to AEGIS unified feed"
```

---

## Task 4: Sable middleware emits feed line

**Files:**
- Modify: `RemoteProjects/MacPro/Sable/src/middleware.ts`

- [ ] **Step 1: Read current middleware**

```bash
grep -n -E "\\[HTTP\\]|console\\.log|res\\.statusCode" C:/Users/wilsd/RemoteProjects/MacPro/Sable/src/middleware.ts
```

Note the current `[HTTP]` line emission.

- [ ] **Step 2: Add feed emit alongside existing log**

After the existing `console.log('[HTTP]', ...)` call, append:

```typescript
// AEGIS unified feed
try {
  const { emit } = require('/Users/alejandxr/aegis-feed/feed_writer');
  emit({
    app: 'sable',
    src_ip: clientIp,
    method: request.method,
    path: request.nextUrl.pathname + request.nextUrl.search,
    status: response.status,
    ua: request.headers.get('user-agent') || '',
    ref: request.headers.get('referer') || '',
    host: request.headers.get('host') || '',
    country: request.headers.get('cf-ipcountry') || '',
    fwd_chain: request.headers.get('x-forwarded-for') || '',
    cf_ray: request.headers.get('cf-ray') || '',
  });
} catch (_) { /* non-fatal */ }
```

Where `clientIp` is the existing variable that already pulls from `cf-connecting-ip` / `x-forwarded-for`. Confirm it exists at the relevant line; if not, derive: `const clientIp = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';`.

- [ ] **Step 3: Deploy and verify**

```bash
cd C:/Users/wilsd/RemoteProjects/MacPro/Sable && npm run build 2>&1 | tail -5
# rsync via tar+ssh because no rsync on Windows:
tar --exclude=node_modules --exclude=.next/cache -czf /tmp/sable-mid.tar.gz src/middleware.ts && base64 -w0 /tmp/sable-mid.tar.gz | python C:/Users/wilsd/remote-ssh.py mac "base64 -d | tar -xzC ~/Sable/"
python C:/Users/wilsd/remote-ssh.py mac "cd ~/Sable && npm run build 2>&1 | tail -3 && pm2 restart sable"
sleep 6
python C:/Users/wilsd/remote-ssh.py mac "curl -s -H 'Cf-Connecting-Ip: 198.51.100.55' http://localhost:3006/ -o /dev/null -w 'sable=%{http_code}\n' && tail -2 /Users/alejandxr/web-logs/aegis-feed.jsonl | python3 -m json.tool"
```

Expected: a JSON line with `app: "sable"`, `src_ip: "198.51.100.55"`.

- [ ] **Step 4: Commit**

```bash
cd C:/Users/wilsd/RemoteProjects/MacPro/Sable
git add src/middleware.ts && git commit -m "feat(sable): emit AEGIS unified-feed line per request"
```

---

## Task 5: Landing-wilab access middleware (new)

**Files:**
- Create: `RemoteProjects/MacPro/landing-wilab/src/middleware.ts`

- [ ] **Step 1: Check whether middleware.ts already exists**

```bash
ls C:/Users/wilsd/RemoteProjects/MacPro/landing-wilab/src/middleware.ts 2>&1
```

If it exists, MODIFY (add emit). If not, CREATE per below.

- [ ] **Step 2: Write the middleware**

Create `RemoteProjects/MacPro/landing-wilab/src/middleware.ts`:

```typescript
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const response = NextResponse.next();
  try {
    const { emit } = require('/Users/alejandxr/aegis-feed/feed_writer');
    const clientIp =
      request.headers.get('cf-connecting-ip') ||
      request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
      'unknown';
    emit({
      app: 'landing-wilab',
      src_ip: clientIp,
      method: request.method,
      path: request.nextUrl.pathname + request.nextUrl.search,
      status: 200, // Next.js middleware sees response before status is set
      ua: request.headers.get('user-agent') || '',
      ref: request.headers.get('referer') || '',
      host: request.headers.get('host') || '',
      country: request.headers.get('cf-ipcountry') || '',
      fwd_chain: request.headers.get('x-forwarded-for') || '',
      cf_ray: request.headers.get('cf-ray') || '',
    });
  } catch (_) {}
  return response;
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

- [ ] **Step 3: Deploy + restart**

```bash
cd C:/Users/wilsd/RemoteProjects/MacPro/landing-wilab && npm run build 2>&1 | tail -5
base64 -w0 src/middleware.ts > /tmp/lw.b64 && B=$(cat /tmp/lw.b64) && python C:/Users/wilsd/remote-ssh.py mac "echo '$B' | base64 -d > ~/landing-wilab/src/middleware.ts && cd ~/landing-wilab && npm run build 2>&1 | tail -3 && pm2 restart landing-wilab"
sleep 6
python C:/Users/wilsd/remote-ssh.py mac "curl -s -H 'Cf-Connecting-Ip: 198.51.100.66' http://localhost:3003/ -o /dev/null -w 'lw=%{http_code}\n' && tail -2 /Users/alejandxr/web-logs/aegis-feed.jsonl | python3 -m json.tool"
```

Expected: line with `app: "landing-wilab"`, `src_ip: "198.51.100.66"`.

- [ ] **Step 4: Commit**

```bash
cd C:/Users/wilsd/RemoteProjects/MacPro/landing-wilab
git add src/middleware.ts && git commit -m "feat(landing): emit AEGIS unified-feed line per request"
```

---

## Task 6: Wilabia-backend (Express) access log to feed

**Files:**
- Modify: `RemoteProjects/MacPro/wilabia-original/server.js` (or wherever the Express app initializes)

- [ ] **Step 1: Locate the Express init point**

```bash
grep -nE "express\\(\\)|app\\.listen|trust proxy" C:/Users/wilsd/RemoteProjects/MacPro/wilabia-original/server.js | head -10
```

- [ ] **Step 2: Add trust-proxy and feed middleware**

In `server.js` immediately after `const app = express();` and BEFORE any routes, insert:

```javascript
app.set('trust proxy', true);

const { emit: aegisEmit } = require('/Users/alejandxr/aegis-feed/feed_writer');
app.use((req, res, next) => {
  res.on('finish', () => {
    try {
      aegisEmit({
        app: 'wilabia-backend',
        src_ip: req.ip,
        method: req.method,
        path: req.originalUrl,
        status: res.statusCode,
        bytes: Number(res.getHeader('content-length') || 0),
        rt_ms: Date.now() - req._aegisStart,
        ua: req.headers['user-agent'] || '',
        ref: req.headers.referer || '',
        host: req.headers.host || '',
        country: req.headers['cf-ipcountry'] || '',
        fwd_chain: req.headers['x-forwarded-for'] || '',
        cf_ray: req.headers['cf-ray'] || '',
      });
    } catch (_) {}
  });
  req._aegisStart = Date.now();
  next();
});
```

- [ ] **Step 3: Deploy + restart**

```bash
base64 -w0 C:/Users/wilsd/RemoteProjects/MacPro/wilabia-original/server.js > /tmp/wb.b64 && B=$(cat /tmp/wb.b64) && python C:/Users/wilsd/remote-ssh.py mac "echo '$B' | base64 -d > ~/wilabia-original/server.js && pm2 restart wilabia-backend"
sleep 4
python C:/Users/wilsd/remote-ssh.py mac "curl -s -H 'X-Forwarded-For: 198.51.100.77' http://localhost:8080/health -o /dev/null -w 'wb=%{http_code}\n' && tail -2 /Users/alejandxr/web-logs/aegis-feed.jsonl | python3 -m json.tool"
```

Expected: `app: "wilabia-backend"`, `src_ip: "198.51.100.77"`, `rt_ms` set.

- [ ] **Step 4: Commit**

```bash
cd C:/Users/wilsd/RemoteProjects/MacPro/wilabia-original
git add server.js && git commit -m "feat(wilabia-backend): trust proxy + emit AEGIS unified-feed"
```

---

## Task 7: SID backend (FastAPI) access log to feed

**Files:**
- Modify: `RemoteProjects/MacPro/sid-wilab/backend/app/main.py`

- [ ] **Step 1: Find the FastAPI init**

```bash
grep -nE "FastAPI\\(\\)|app = FastAPI|@app\\.middleware" C:/Users/wilsd/RemoteProjects/MacPro/sid-wilab/backend/app/main.py | head -10
```

- [ ] **Step 2: Add HTTP middleware**

Insert after `app = FastAPI(...)`:

```python
import sys
sys.path.insert(0, "/Users/alejandxr/aegis-feed")
import time as _aegis_time
from feed_writer import emit as _aegis_emit

@app.middleware("http")
async def _aegis_access_log(request, call_next):
    start = _aegis_time.time()
    response = await call_next(request)
    src_ip = (
        request.headers.get("cf-connecting-ip")
        or (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
    try:
        _aegis_emit(
            app="sid-backend",
            src_ip=src_ip,
            method=request.method,
            path=str(request.url.path) + (("?" + request.url.query) if request.url.query else ""),
            status=response.status_code,
            rt_ms=int((_aegis_time.time() - start) * 1000),
            ua=request.headers.get("user-agent", ""),
            ref=request.headers.get("referer", ""),
            host=request.headers.get("host", ""),
            country=request.headers.get("cf-ipcountry", ""),
            fwd_chain=request.headers.get("x-forwarded-for", ""),
            cf_ray=request.headers.get("cf-ray", ""),
        )
    except Exception:
        pass
    return response
```

Also ensure uvicorn is invoked with `--proxy-headers --forwarded-allow-ips="127.0.0.1,100.64.0.0/10"`. Edit `~/sid-wilab/backend/run.sh` or the PM2 ecosystem entry.

- [ ] **Step 3: Deploy + restart**

```bash
base64 -w0 C:/Users/wilsd/RemoteProjects/MacPro/sid-wilab/backend/app/main.py > /tmp/sb.b64 && B=$(cat /tmp/sb.b64) && python C:/Users/wilsd/remote-ssh.py mac "echo '$B' | base64 -d > ~/sid-wilab/backend/app/main.py && pm2 restart sid-backend"
sleep 4
python C:/Users/wilsd/remote-ssh.py mac "curl -s -H 'Cf-Connecting-Ip: 198.51.100.88' http://localhost:8800/health -o /dev/null -w 'sb=%{http_code}\n' && tail -2 /Users/alejandxr/web-logs/aegis-feed.jsonl | python3 -m json.tool"
```

Expected: `app: "sid-backend"`, `src_ip: "198.51.100.88"`, `rt_ms` set.

- [ ] **Step 4: Commit**

```bash
cd C:/Users/wilsd/RemoteProjects/MacPro/sid-wilab
git add backend/app/main.py && git commit -m "feat(sid-backend): proxy-aware emit to AEGIS unified-feed"
```

---

## Task 8: Logrotate config for the feed

**Files:**
- Create: `/etc/newsyslog.d/aegis-feed.conf` (macOS uses newsyslog, not logrotate)

- [ ] **Step 1: Write the config**

```bash
python C:/Users/wilsd/remote-ssh.py mac "echo 1108 | sudo -S tee /etc/newsyslog.d/aegis-feed.conf <<'EOF'
# logfilename                                       [owner:group]    mode count size when  flags [/pid_file] [sig_num]
/Users/alejandxr/web-logs/aegis-feed.jsonl  alejandxr:staff  640  24    204800  *     JG
EOF"
```

Fields: keep 24 rotations, rotate at 200MB OR every hour (`*` = any time + size trigger), compress with gzip (`G`), copy-and-truncate not used here (`J` flag is journal-style; safe).

- [ ] **Step 2: Validate config**

```
python C:/Users/wilsd/remote-ssh.py mac "echo 1108 | sudo -S newsyslog -nv 2>&1 | grep aegis-feed"
```

Expected: a line showing the rule parsed.

- [ ] **Step 3: Force one rotation to confirm**

```
python C:/Users/wilsd/remote-ssh.py mac "echo 1108 | sudo -S newsyslog -F && ls -la /Users/alejandxr/web-logs/aegis-feed.jsonl*"
```

Expected: `aegis-feed.jsonl` reset to small size, `aegis-feed.jsonl.0.gz` exists.

- [ ] **Step 4: Commit (config tracked in repo)**

```bash
mkdir -p RemoteProjects/Laboratorio/Cayde-6/pi-deploy/newsyslog
cp the config back into repo
git add pi-deploy/newsyslog/aegis-feed.conf
git commit -m "feat(infra): newsyslog rotation for AEGIS unified feed"
```

---

## Task 9: AEGIS log_watcher honors AEGIS_EXTRA_LOG_PATHS

**Files:**
- Modify: `RemoteProjects/Laboratorio/Cayde-6/backend/app/services/log_watcher.py`
- Modify: `~/Cayde-6/backend/.env` on Mac Pro

- [ ] **Step 1: Write the failing test**

Create `RemoteProjects/Laboratorio/Cayde-6/backend/tests/test_log_watcher_extras.py`:

```python
import os, tempfile
from app.services import log_watcher

def test_extra_paths_glob_expands(monkeypatch, tmp_path):
    f1 = tmp_path / "a-access.log"
    f1.write_text("")
    f2 = tmp_path / "b-access.log"
    f2.write_text("")
    monkeypatch.setenv("AEGIS_EXTRA_LOG_PATHS", str(tmp_path / "*-access.log"))
    paths = log_watcher._resolve_extra_log_paths()
    assert str(f1) in paths and str(f2) in paths

def test_extra_paths_empty_returns_empty(monkeypatch):
    monkeypatch.delenv("AEGIS_EXTRA_LOG_PATHS", raising=False)
    assert log_watcher._resolve_extra_log_paths() == []
```

- [ ] **Step 2: Run test to verify it fails**

```
cd C:/Users/wilsd/RemoteProjects/Laboratorio/Cayde-6/backend && python -m pytest tests/test_log_watcher_extras.py -v
```

Expected: FAIL — `_resolve_extra_log_paths` not defined.

- [ ] **Step 3: Implement**

In `log_watcher.py`, add a helper near the top of the module (after imports):

```python
def _resolve_extra_log_paths() -> list[str]:
    """Glob-expand AEGIS_EXTRA_LOG_PATHS. Colon-separated, supports * and ?."""
    import glob as _glob
    raw = os.environ.get("AEGIS_EXTRA_LOG_PATHS", "")
    result = []
    for pattern in (p.strip() for p in raw.split(":") if p.strip()):
        for fpath in sorted(_glob.glob(os.path.expanduser(pattern))):
            if os.path.isfile(fpath):
                result.append(fpath)
    return result
```

In `_tail_pm2_files()`, after the existing handles loop is built and before the `logger.info("file-tail started")` log, append:

```python
        for extra_path in _resolve_extra_log_paths():
            try:
                fp = open(extra_path, "r", errors="replace")
                fp.seek(0, 2)
                inode = os.stat(extra_path).st_ino
                handles.append([fp, inode, extra_path, "extra", "out"])
                logger.info(f"log_watcher: tailing extra path: {extra_path}")
            except Exception as exc:
                logger.warning(f"log_watcher: cannot open extra path {extra_path}: {exc}")
```

- [ ] **Step 4: Verify tests pass**

```
cd C:/Users/wilsd/RemoteProjects/Laboratorio/Cayde-6/backend && python -m pytest tests/test_log_watcher_extras.py -v
```

Expected: 2 passed.

- [ ] **Step 5: Set env var on Mac Pro and deploy patch**

```
scp C:/Users/wilsd/RemoteProjects/Laboratorio/Cayde-6/backend/app/services/log_watcher.py alejandxr@100.87.222.58:~/Cayde-6/backend/app/services/log_watcher.py
python C:/Users/wilsd/remote-ssh.py mac "grep -q AEGIS_EXTRA_LOG_PATHS ~/Cayde-6/backend/.env || echo 'AEGIS_EXTRA_LOG_PATHS=/Users/alejandxr/web-logs/aegis-feed.jsonl' >> ~/Cayde-6/backend/.env && pm2 restart cayde6-api && sleep 5 && pm2 logs cayde6-api --lines 80 --nostream --raw 2>&1 | grep -E 'tailing extra path|file-tail started' | head -5"
```

Expected: a log line `log_watcher: tailing extra path: /Users/alejandxr/web-logs/aegis-feed.jsonl`.

- [ ] **Step 6: Commit**

```bash
cd C:/Users/wilsd/RemoteProjects/Laboratorio/Cayde-6
git add backend/app/services/log_watcher.py backend/tests/test_log_watcher_extras.py
git commit -m "feat(log_watcher): honor AEGIS_EXTRA_LOG_PATHS env var (glob, colon-separated)"
```

---

## Task 10: End-to-end attack verification

- [ ] **Step 1: Inject a benign SQLi-pattern request against each app**

For each app in `{sable, sid, landing-wilab, wilabia-frontend}`, do (one at a time, with cleanup):

```
TEST_IP="203.0.113.$((RANDOM % 254 + 1))"
echo "Testing $TEST_IP against sable"
python C:/Users/wilsd/remote-ssh.py mac "curl -s -H 'Cf-Connecting-Ip: $TEST_IP' 'http://localhost:3006/?id=1+UNION+SELECT+pwd+FROM+users--' -o /dev/null -w '%{http_code}\n'"
sleep 6
python C:/Users/wilsd/remote-ssh.py mac "grep '$TEST_IP' /Users/alejandxr/web-logs/aegis-feed.jsonl | tail -2"
python C:/Users/wilsd/remote-ssh.py mac "pm2 logs cayde6-api --lines 200 --nostream --raw 2>&1 | grep -E '$TEST_IP|sqli|scanner_detect' | tail -5"
python C:/Users/wilsd/remote-ssh.py pi "curl -s http://localhost:8765/blocked | python3 -c \"import sys,json; d=json.load(sys.stdin); print('BLOCKED' if '$TEST_IP' in d.get('blocked',[]) else 'NOT BLOCKED')\""
python C:/Users/wilsd/remote-ssh.py pi "curl -s -X DELETE http://localhost:8765/block/$TEST_IP"
```

Expected for each: feed line present with that IP, AEGIS log mentions `sqli`/`scanner_detect`, Pi `/blocked` returns BLOCKED, then cleanup unblocks.

- [ ] **Step 2: If any app fails detection, diagnose**

If feed line is present but AEGIS didn't detect → grep Sigma rules for `union.+select` pattern: `python C:/Users/wilsd/remote-ssh.py mac "grep -lE 'UNION|union' ~/Cayde-6/backend/app/rules/sigma/*.yaml | head -5"`. Confirm the pattern hits the JSON format (path field needs to be scanned).

- [ ] **Step 3: Commit verification log**

Save the e2e run output to `docs/superpowers/runs/2026-05-25-aegis-feed-e2e.md` and commit.

```bash
git add docs/superpowers/runs/2026-05-25-aegis-feed-e2e.md
git commit -m "docs(aegis-feed): end-to-end verification run"
```

---

## Task 11: Push and announce

- [ ] **Step 1: Push the branch / main**

```bash
cd C:/Users/wilsd/RemoteProjects/Laboratorio/Cayde-6 && git push origin main
```

- [ ] **Step 2: Update AEGIS docs**

Append a short section to `CLAUDE.md` (Cayde-6 root) describing the new feed and what an app must emit to be defended. Then commit and push.

---

## Self-Review Notes

- **Spec coverage:** all 6 web apps now emit to the same feed (Tasks 3-7), feed is rotated (Task 8), AEGIS consumes it (Task 9), e2e verified (Task 10). ✓
- **Placeholder scan:** every step has either code or a concrete command. No "TBD". ✓
- **Type consistency:** the `emit()` keyword arguments are identical across Python (`/Users/alejandxr/aegis-feed/feed_writer.py`) and JS (`feed_writer.js`); field names match the schema header at the top. ✓
- **Gaps to flag at execution time:**
  - Task 4 assumes Sable's middleware already has a `clientIp` variable — Task 1 of execution should `grep` to confirm; if not, derive inline (instructions included).
  - Task 5 assumes landing-wilab has no existing middleware.ts — Step 1 checks.
  - Task 6 assumes the Express entry is `server.js` — adjust if monorepo uses different naming.
  - Task 7 assumes uvicorn launch is editable — if `run.sh` is autogenerated, edit the PM2 ecosystem instead.
