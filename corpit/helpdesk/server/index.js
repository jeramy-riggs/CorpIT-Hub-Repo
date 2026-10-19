/**
 * HelpDesk Dashboard — Server Entry Point
 * Express server with Okta integration, SQLite caching, and scheduled sync.
 */
// pm2's registered exec cwd for this app is /home/ubuntu, not the project root, so a
// bare dotenv.config() silently loaded nothing here and left every OKTA_/SLACK_/etc var
// undefined — the real cause of the Okta sync's "Only absolute URLs are supported"
// failures (since 2026-06-01). Anchor to the .env next to this file, immune to cwd.
// (Fixed 2026-08-21.)
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const cron = require('node-cron');

const logger = require('./utils/logger');
const { initDatabase } = require('./db/database');
const { syncAll } = require('./services/sync-service');

const dashboardRoutes = require('./routes/dashboard');
const usersRoutes = require('./routes/users');
const appsRoutes = require('./routes/apps');
const healthRoutes = require('./routes/health');
const slackRoutes = require('./routes/slack');
const { startAlertWatcher } = require('./services/slack-alert-watcher');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3002;

// ── Security ────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
    },
  },
}));
app.use(compression());
// In dev, CRA auto-increments past occupied ports (3000, 3001, 3002 are taken).
// Allow any localhost origin in dev; disable CORS entirely in production.
app.use(cors({
  origin: process.env.NODE_ENV === 'development'
    ? (origin, cb) => {
        if (!origin || /^https?:\/\/localhost(:\d+)?$/.test(origin)) cb(null, true);
        else cb(new Error('CORS not allowed'));
      }
    : false,
}));
app.use(express.json());

// ── Logging ─────────────────────────────────────────────────
app.use(morgan('short', {
  stream: { write: (msg) => logger.info(msg.trim()) },
}));

// ── Rate Limiting ───────────────────────────────────────────
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, slow down.' },
});
app.use('/api', apiLimiter);

// ── API Routes ──────────────────────────────────────────────
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/users', usersRoutes);
app.use('/api/apps', appsRoutes);
app.use('/api/health', healthRoutes);
app.use('/api/slack', slackRoutes);

// ── Serve React Build ───────────────────────────────────────
const clientBuild = path.join(__dirname, '..', 'client', 'build');
app.use(express.static(clientBuild, {
  maxAge: '7d',           // Cache static assets (hashed filenames = safe)
  immutable: true,        // Tell browsers hashed files never change
  index: false,           // Don't auto-serve index.html for directory requests
}));

// ── API 404 — must come before the SPA catch-all ────────────
// Without this, invalid API paths like /api/nonexistent would
// return index.html (200) instead of a proper JSON 404.
app.all('/api/*', (_req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

// ── SPA Catch-All ───────────────────────────────────────────
app.get('*', (_req, res) => {
  res.sendFile(path.join(clientBuild, 'index.html'));
});

// ── Error Handler ───────────────────────────────────────────
app.use((err, _req, res, _next) => {
  logger.error(`Unhandled error: ${err.message}`, { stack: err.stack });
  res.status(500).json({ error: 'Internal server error' });
});
// ── Start ───────────────────────────────────────────────────
async function boot() {
  try {
    initDatabase();
    logger.info('Database initialized');
    startAlertWatcher();

    app.listen(PORT, '127.0.0.1', () => {
      logger.info(`HelpDesk Dashboard running on port ${PORT}`);
    });

    const cronExpr = process.env.SYNC_CRON || '*/30 * * * *';
    cron.schedule(cronExpr, async () => {
      logger.info('Scheduled Okta sync starting…');
      await syncAll().catch(err => logger.error(`Scheduled sync error: ${err.message}`));
    });

    logger.info('Running initial Okta data sync in background…');
    syncAll().catch(err => {
      logger.warn(`Initial sync failed (Okta may not be configured yet): ${err.message}`);
    });
  } catch (err) {
    logger.error(`Fatal startup error: ${err.message}`);
    process.exit(1);
  }
}

boot();
