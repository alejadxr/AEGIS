// Load .env FIRST (side-effect import)
import 'dotenv/config';
import http from 'http';
import { attachJarvisLive } from './routes/jarvisLive.js';

// Global safety net: a single uncaught exception or unhandled promise rejection
// should NOT take down a production process serving the optical lab. Log loudly
// and keep serving. Real bugs still surface in logs; transient noise stays a noop.
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err && err.stack ? err.stack : err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[unhandledRejection]', reason && reason.stack ? reason.stack : reason);
});

import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';
import fs from 'fs';

// Check local SMB mount at startup
const localPath = process.env.LOCAL_TRACKING_PATH;
if (localPath) {
  if (fs.existsSync(localPath)) {
    console.log(`[SMB] Local mount available at ${localPath}`);
  } else {
    console.warn(`[SMB] WARNING: LOCAL_TRACKING_PATH=${localPath} not mounted. FTP will be used as fallback.`);
  }
}

// Routes
import geminiRoutes from './routes/gemini.js';
import ocrBenchmarkRoutes from './routes/ocrBenchmark.js';
import catalogRoutes from './routes/catalog.js';
import jobsRoutes from './routes/jobs.js';
import customersRoutes from './routes/customers.js';
import customerAliasesRoutes from './routes/customerAliases.js';
import reworkOcrRoutes from './routes/reworkOcr.js';
import tasksRoutes from './routes/tasks.js';
import uploadRoutes from './routes/upload.js';
import authRoutes from './routes/auth.js';
import lensCategoriesRoutes from './routes/lensCategories.js';
import ordersRoutes from './routes/orders.js';
import priceListRoutes from './routes/priceList.js';
import errorReporterRoutes from './routes/errorReporter.js';
import reworksRoutes from './routes/reworks.js';
import baseSelectionRoutes from './routes/baseSelection.js';
import dbViewerRoutes from './routes/dbViewer.js';
import courierRoutes from './routes/courier.js';
import lasBuilderRoutes from './routes/lasBuilder.js';
import clientConfigRoutes from './routes/clientConfig.js';
import bulkRecalcRoutes from './routes/bulkRecalc.js';
import programRoutes from './routes/program.js';
import figsRoutes from './routes/figs.js';
import fullRecalcRoutes from './routes/fullRecalc.js';
import recipeDefaultsRoutes from './routes/recipeDefaults.js';
import externalLabOrderRoutes from './routes/externalLabOrder.js';
import { seedGlobalDefaultsIfMissing } from './models/RecipeDefaults.js';
import { startRemoteAlertChecker, getStaleOrders } from './services/remoteAlerts.js';

// Force restart to clear rate limits


const app = express();
const PORT = process.env.PORT || 8080;

// Trust proxy for Cloudflare tunnel (fixes X-Forwarded-For rate limiter errors)
app.set('trust proxy', 1);

// ===========================================
// SECURITY MIDDLEWARE
// ===========================================

// Security headers with Helmet
app.use(helmet({
  contentSecurityPolicy: false, // Disable CSP for API server
  crossOriginEmbedderPolicy: false,
  // SECURITY FIX: Prevent clickjacking
  frameguard: { action: 'deny' },
  // SECURITY FIX: Prevent MIME type sniffing
  noSniff: true,
  // SECURITY FIX: XSS filter
  xssFilter: true,
  // SECURITY FIX: HSTS
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true
  },
  // CORS-compatibility: this API is intentionally cross-origin (wilabia.somoswilab.com
  // → api-wilabia.somoswilab.com). The default helmet `Cross-Origin-Resource-Policy:
  // same-origin` blocks the frontend from reading responses despite valid CORS
  // headers. Allow cross-origin reads explicitly. Same for Opener Policy.
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  crossOriginOpenerPolicy: { policy: 'unsafe-none' },
}));

// CORS - Whitelist de dominios permitidos
const allowedOrigins = [
  'https://wilabia.somoswilab.com',
  'https://api-wilabia.somoswilab.com',
  'http://wilabia.somoswilab.com',
  'http://api-wilabia.somoswilab.com',
];

// En desarrollo, permitir localhost y IP directa de Mac Pro
if (process.env.NODE_ENV !== 'production') {
  allowedOrigins.push('http://localhost:3000');
  allowedOrigins.push('http://localhost:5173');
  allowedOrigins.push('http://localhost:8080');
  allowedOrigins.push('http://127.0.0.1:3000');
  allowedOrigins.push('http://127.0.0.1:5173');
  // Mac Pro development server (Tailscale IP)
  allowedOrigins.push('http://100.112.2.49:3000');
  allowedOrigins.push('http://100.112.2.49:5173');
}

// Throttle CORS warning logs — scanners spam the same blocked origin hundreds of
// times per minute. Log each unique origin at most once every 5 min to keep logs readable.
const corsBlockedLog = new Map();
const CORS_LOG_TTL_MS = 5 * 60 * 1000;
const KNOWN_SCANNER_ORIGINS = /^https?:\/\/(example\.com|test\.com|localhost\b|0\.0\.0\.0)/i;

app.use(cors({
  origin: function (origin, callback) {
    // Permitir requests sin origin (mobile apps, Postman, curl, etc.)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    // Reject quietly: return false (no Error) so cors stops the request without a stack trace.
    // Express returns 401/403-equivalent; scanners still get blocked, logs stay clean.
    const now = Date.now();
    const last = corsBlockedLog.get(origin) || 0;
    if (!KNOWN_SCANNER_ORIGINS.test(origin) && (now - last) > CORS_LOG_TTL_MS) {
      console.warn(`[CORS] Blocked origin: ${origin}`);
      corsBlockedLog.set(origin, now);
      // Trim map if it grows too much
      if (corsBlockedLog.size > 500) {
        const cutoff = now - CORS_LOG_TTL_MS;
        for (const [k, v] of corsBlockedLog) if (v < cutoff) corsBlockedLog.delete(k);
      }
    }
    return callback(null, false);  // silent reject (no Error → no stack trace)
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Filename', 'X-Push-Endpoint', 'Cache-Control', 'Pragma']
}));

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
      fs.appendFileSync('/Users/alejandxr/web-logs/aegis-feed.jsonl', JSON.stringify(record) + '\n');
    } catch (_) { /* never let logging take down the request */ }
  });
  next();
});


// Rate Limiters
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 500, // 500 requests por IP en 15 min
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false
});

const loginLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hora
  max: 5, // Solo 5 intentos de login por hora
  skipSuccessfulRequests: true,
  message: { error: 'Too many login attempts, please try again in 1 hour' }
});

const geminiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minuto
  max: 30, // Máximo 30 requests por minuto (API costosa)
  message: { error: 'AI API rate limit exceeded, please slow down' }
});

// SECURITY FIX: Rate limiter for order creation to prevent spam/DoS
const orderCreateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hora
  max: 50, // Máximo 50 órdenes por hora por IP
  message: { error: 'Too many orders created, please try again later' }
});

// Apply rate limiters
app.use('/api/', generalLimiter);
// Login limiter disabled - no lockout by attempts
// app.use('/api/auth/login', loginLimiter);
app.use('/api/gemini/', geminiLimiter);
app.use('/api/orders', orderCreateLimiter); // SECURITY FIX: Limit order creation

// Body parser
app.use(express.json({ limit: '20mb' }));

// Catch malformed-JSON SyntaxErrors thrown by body-parser BEFORE they escalate to
// uncaughtException and kill the process. Scanners + misbehaving clients regularly
// send garbage bodies; respond 400 and stay alive.
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    console.warn(`[BodyParser] Malformed JSON from ${req.ip} ${req.method} ${req.path}: ${err.message}`);
    return res.status(400).json({ error: 'Invalid JSON body' });
  }
  if (err && err instanceof SyntaxError && 'body' in err) {
    console.warn(`[BodyParser] SyntaxError from ${req.ip} ${req.method} ${req.path}: ${err.message}`);
    return res.status(400).json({ error: 'Invalid JSON body' });
  }
  next(err);
});

// NoSQL Injection Prevention - sanitize all inputs
app.use(mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }) => {
    console.warn(`[Security] NoSQL injection attempt blocked in ${key} from IP: ${req.ip}`);
  }
}));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Test connection endpoint (used by frontend on startup)
app.get('/test-connection', (req, res) => {
  res.json({ success: true, message: 'Connection successful' });
});

// Routes
app.use('/api/gemini', geminiRoutes);
app.use('/api/gemini', ocrBenchmarkRoutes);
app.use('/api/catalog', catalogRoutes);
app.use('/api/jobs', jobsRoutes);
app.use('/api/customers', customersRoutes);
app.use('/api/customer-aliases', customerAliasesRoutes);
app.use('/api/rework-ocr', reworkOcrRoutes);
app.use('/api/tasks', tasksRoutes);
app.use('/api/upload', uploadRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/lens-categories', lensCategoriesRoutes);
app.use('/api/orders', ordersRoutes);
app.use('/api/price-list', priceListRoutes);
app.use('/api/report-error', errorReporterRoutes);
app.use('/api/reworks', reworksRoutes);
app.use('/api/base-selection', baseSelectionRoutes);
app.use('/api/db-viewer', dbViewerRoutes);
app.use('/api/courier', courierRoutes);
app.use('/api/catalog', lasBuilderRoutes);
app.use('/api/client-config', clientConfigRoutes);
app.use('/api/bulk-recalc', bulkRecalcRoutes);
app.use('/api/program', programRoutes);
app.use('/api/figs', figsRoutes);
app.use('/api/full-recalc', fullRecalcRoutes);
app.use('/api/recipe-defaults', recipeDefaultsRoutes);
app.use('/api/external-lab', externalLabOrderRoutes);

// Legacy routes (for backwards compatibility with existing frontend)
app.use('/gemini', geminiRoutes);
app.use('/jobs', jobsRoutes);
app.use('/customers', customersRoutes);
app.use('/tasks', tasksRoutes);
app.use('/catalog', catalogRoutes);

// Direct legacy endpoints
app.post('/extract-recipe', (req, res, next) => { req.url = '/extract-recipe'; geminiRoutes(req, res, next); });
app.post('/benchmark-recipe-ocr', (req, res, next) => { req.url = '/benchmark-recipe-ocr'; geminiRoutes(req, res, next); });
app.post('/analyze-frame', (req, res, next) => { req.url = '/analyze-frame'; geminiRoutes(req, res, next); });
app.post('/extract-spark-data', (req, res, next) => { req.url = '/extract-spark-data'; geminiRoutes(req, res, next); });
app.post('/extract-rework-info', (req, res, next) => { req.url = '/extract-rework-info'; geminiRoutes(req, res, next); });
app.post('/estimate-all-measurements', (req, res, next) => { req.url = '/estimate-all-measurements'; geminiRoutes(req, res, next); });
app.post('/analyze-damage', (req, res, next) => { req.url = '/analyze-damage'; geminiRoutes(req, res, next); });
app.post('/analyze-rework-damage', (req, res, next) => { req.url = '/analyze-rework-damage'; geminiRoutes(req, res, next); });
app.post('/detect-direct-instruction', (req, res, next) => { req.url = '/detect-direct-instruction'; geminiRoutes(req, res, next); });
app.get('/base-catalog.csv', (req, res, next) => { req.url = '/base-catalog.csv'; catalogRoutes(req, res, next); });
app.get('/base-catalog', (req, res, next) => { req.url = '/base-catalog'; catalogRoutes(req, res, next); });
app.post('/next-order-id', (req, res, next) => { req.url = '/next-order-id'; catalogRoutes(req, res, next); });
app.get('/order-counter', (req, res, next) => { req.url = '/order-counter'; catalogRoutes(req, res, next); });
app.post('/order-counter', (req, res, next) => { req.url = '/order-counter'; catalogRoutes(req, res, next); });
app.post('/log', (req, res, next) => { req.url = '/log'; catalogRoutes(req, res, next); });
app.get('/log/:clientId', (req, res, next) => { req.url = `/log/${req.params.clientId}`; catalogRoutes(req, res, next); });
app.get('/urgent-orders', (req, res, next) => { req.url = '/urgent-orders'; jobsRoutes(req, res, next); });
app.post('/urgent-orders', (req, res, next) => { req.url = '/urgent-orders'; jobsRoutes(req, res, next); });
app.delete('/urgent-orders/:orderId', (req, res, next) => { req.url = `/urgent-orders/${req.params.orderId}`; jobsRoutes(req, res, next); });
app.get('/rxi/:rxn', (req, res, next) => { req.url = `/rxi/${req.params.rxn}`; jobsRoutes(req, res, next); });

// Connect to MongoDB
const connectDB = async () => {
  try {
    const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/wilabia';
    await mongoose.connect(mongoUri);
    console.log('Connected to MongoDB');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
};

// Start server
const startServer = async () => {
  await connectDB();

  try {
    await seedGlobalDefaultsIfMissing();
  } catch (err) {
    console.error('[RecipeDefaults] Seed failed:', err.message);
  }

  // API endpoint to check stale remote orders
  app.get('/api/remote-alerts/stale', async (req, res) => {
    try {
      const orders = await getStaleOrders();
      res.json({ count: orders.length, orders });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  const httpServer = http.createServer(app);
  // Cloudflare tunnel keeps connections open ~60s. Node's default
  // keepAliveTimeout (5s on older versions, varies per release) causes the
  // backend to close the TCP socket before Cloudflare's next reuse → the
  // tunnel reports "connection reset by peer" and the browser shows
  // "Load failed" on iOS Safari. Bumping these above Cloudflare's window
  // makes the backend hold the connection long enough.
  // Headers timeout MUST be greater than keepAliveTimeout (Node rule).
  httpServer.keepAliveTimeout = 120_000;
  httpServer.headersTimeout    = 125_000;
  attachJarvisLive(httpServer);
  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`WilabIA Backend running on http://localhost:${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
    console.log(`Jarvis Live WS: ws://localhost:${PORT}/api/jarvis/live`);

    // Start remote alert checker (hourly push notifications)
    startRemoteAlertChecker();
  });
};

startServer();
