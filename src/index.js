const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const scanRoutes = require('./routes/scan');
const cveRoutes = require('./routes/cve');
const chatRoutes = require('./routes/chat');
const logger = require('./utils/logger');

const app = express();
const PORT = process.env.PORT || 5000;
const HOST = process.env.HOST || '0.0.0.0';

// ── Security Middleware ────────────────────────────────────────────────────────
app.use(helmet());
app.use(cors({
  origin: '*',          // VS Code extension origin
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'],
}));

// ── Rate Limiting ──────────────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});
app.use(limiter);

// ── General Middleware ─────────────────────────────────────────────────────────
app.use(express.json({ limit: '2mb' }));
app.use(morgan('combined', {
  stream: { write: (msg) => logger.http(msg.trim()) },
}));

// ── Routes ─────────────────────────────────────────────────────────────────────
app.use('/api/scan', scanRoutes);
app.use('/api/cve', cveRoutes);
app.use('/api/chat', chatRoutes);

// ── Health Check ───────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
  });
});

// ── 404 Handler ────────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: `Route ${req.method} ${req.path} not found` });
});

// ── Global Error Handler ───────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message}`, { stack: err.stack });
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
  });
});

// ── Start ──────────────────────────────────────────────────────────────────────
app.listen(PORT, HOST, () => {
  logger.info(`SecureGuard API running on http://${HOST}:${PORT}`);
});

module.exports = app;
