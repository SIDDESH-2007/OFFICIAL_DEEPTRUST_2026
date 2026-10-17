/**
 * app.js
 * Express configuration and gateway routing for DeepTrust Platform
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
const { allowedOrigin } = require('./middleware/origin-policy');
const { connectDB } = require('./config/db.config');

const adminRoutes = require('./routes/admin.routes');
const authRoutes = require('./routes/auth.routes');
const healthRoutes = require('./routes/health.routes');
const faceRoutes = require('./routes/face.routes');
const livenessRoutes = require('./routes/liveness.routes');
const voiceRoutes = require('./routes/voice.routes');
const mfaRoutes = require('./routes/mfa.routes');
const riskRoutes = require('./routes/risk.routes');
const dashboardRoutes = require('./routes/dashboard.routes');
const notificationsRoutes = require('./routes/notifications.routes');

const app = express();

// Give every API request a server-generated trace ID. Client input never controls it.
app.use((req, res, next) => {
  req.requestId = crypto.randomUUID();
  res.setHeader('X-Request-ID', req.requestId);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// Authentication, security reports and patient-facing API responses must not be cached.
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  next();
});

// Bound expensive voice uploads before parsing their JSON bodies.
app.use('/api/v1/voice', rateLimit({
  windowMs: 60 * 1000, max: 30, standardHeaders: 'draft-8', legacyHeaders: false,
  message: { success: false, message: 'Too many voice requests. Wait one minute and retry.' }
}), express.json({ limit: '5mb' }));

// Middleware - increase payload limit for base64 camera frames and audio
app.use(express.json({ limit: '25mb' }));

// Security Headers (Helmet)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'", "http://127.0.0.1:5000", "http://localhost:5000", "https://*.loca.lt"],
      mediaSrc: ["'self'", "blob:", "data:"],
      frameAncestors: ["'none'"]
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// Notification polling has its own bounded budget; it cannot exhaust login/API capacity.
const { isNotificationRead } = require('./middleware/notification-budget');
const notificationLimiter = rateLimit({
  windowMs: 60 * 1000, max: 180, standardHeaders: 'draft-8', legacyHeaders: false,
  message: { success: false, message: 'Notification request limit reached. Retry shortly.' }
});
app.use((req, res, next) => isNotificationRead(req) ? notificationLimiter(req, res, next) : next());

// Rate Limiting
const isSessionMonitorRequest = req => /^(\/api\/v1\/session\/(activity|behavior-summary)|\/api\/v1\/admin\/sessions\/(control|detail\/[^/]+)|\/api\/v1\/admin\/audit\/identity\/[^/]+\/session\/[^/]+\/timeline)$/.test(req.path);
const sessionMonitorLimiter = rateLimit({windowMs: 60 * 1000, max: 240, message: {success: false, message: 'Session monitoring request limit reached.'}});
app.use((req,res,next) => isSessionMonitorRequest(req) ? sessionMonitorLimiter(req,res,next) : next());
const globalLimiter = rateLimit({
  skip: req => isSessionMonitorRequest(req) || isNotificationRead(req),
  windowMs: 15 * 60 * 1000,
  max: 300,
  message: { success: false, message: "Too many requests, please try again later." }
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: "Too many authentication attempts." }
});
app.use(globalLimiter);
app.use('/api/v1/auth', authLimiter);
app.use('/api/v1/admin/login', authLimiter);

// CORS Hardening
const allowedOrigins = process.env.FRONTEND_ORIGINS ? process.env.FRONTEND_ORIGINS.split(',') : ['http://localhost:5000', 'http://127.0.0.1:5000'];
app.use(cors((req, callback) => callback(null, {
  origin: (origin, done) => done(null, allowedOrigin(origin, req.headers.host, allowedOrigins.map(value => value.trim()))),
  credentials: true
})));

// Trigger MongoDB connection test on startup
connectDB().catch(err => console.warn('[App Init] MongoDB notice:', err.message));

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../client')));

// API v1 Specific Routes
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/face', faceRoutes);
app.use('/api/v1/liveness', livenessRoutes);
app.use('/api/v1/voice', voiceRoutes);
app.use('/api/v1/mfa', mfaRoutes);
app.use('/api/v1/risk', riskRoutes);
// app.use('/api/v1/dashboard', dashboardRoutes); // Forwarded via universal proxy
app.use('/api/v1/notifications', notificationsRoutes);
app.use('/api/v1/ready', require('./routes/readiness.routes'));
app.use('/api/v1/health', healthRoutes);

// Universal API v1 Forwarder to FastAPI AI Backend
const AI_SERVICE_URL = process.env.AI_SERVICE_URL || 'http://127.0.0.1:8000';
const configuredAiTimeout = Number(process.env.AI_PROXY_TIMEOUT_MS || 15000);
const AI_PROXY_TIMEOUT_MS = Math.max(2000, Math.min(30000, Number.isFinite(configuredAiTimeout) ? configuredAiTimeout : 15000));
app.use('/api/v1', async (req, res, next) => {
    try {
        const targetUrl = `${AI_SERVICE_URL}/api/v1${req.url}`;
        const forwardHeaders = { 'Content-Type': 'application/json' };
        if (req.headers.authorization) forwardHeaders['Authorization'] = req.headers.authorization;
        if (req.headers['x-client-id']) forwardHeaders['x-client-id'] = req.headers['x-client-id'];
        if (req.headers['x-client-secret']) forwardHeaders['x-client-secret'] = req.headers['x-client-secret'];
        if (req.headers['x-org-id']) forwardHeaders['x-org-id'] = req.headers['x-org-id'];
        if (req.headers['user-agent']) forwardHeaders['User-Agent'] = req.headers['user-agent'];
        const clientIp = req.ip || req.socket?.remoteAddress || '127.0.0.1';
        forwardHeaders['X-Forwarded-For'] = clientIp;

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), AI_PROXY_TIMEOUT_MS);
        const options = {
            method: req.method,
            headers: forwardHeaders,
            signal: controller.signal
        };
        if (req.method !== 'GET' && req.method !== 'HEAD' && req.body && Object.keys(req.body).length > 0) {
            options.body = JSON.stringify(req.body);
        }

        let response;
        try {
            response = await fetch(targetUrl, options);
        } finally {
            clearTimeout(timeout);
        }
        const contentType = response.headers.get('content-type') || '';

        if (contentType.includes('application/pdf') || contentType.includes('application/octet-stream') || contentType.includes('text/csv')) {
            res.status(response.status);
            const contentDisposition = response.headers.get('content-disposition');
            if (contentDisposition) {
                res.setHeader('Content-Disposition', contentDisposition);
            }
            res.setHeader('Content-Type', contentType);
            const arrayBuffer = await response.arrayBuffer();
            return res.send(Buffer.from(arrayBuffer));
        }

        if (!contentType.includes('application/json')) {
            return res.status(502).json({
                success: false,
                message: 'Core security service returned an invalid response.',
                request_id: req.requestId
            });
        }
        const data = await response.json();
        return res.status(response.status).json(data);
    } catch (err) {
        const timedOut = err && err.name === 'AbortError';
        return res.status(timedOut ? 504 : 502).json({
            success: false,
            message: timedOut ? 'Core security service timed out. Please retry.' : 'Core security service is temporarily unavailable.',
            request_id: req.requestId
        });
    }
});

// Legacy & Admin Routes
app.use('/api/admin', adminRoutes);
app.use('/api/health', healthRoutes);
app.use('/api/system', healthRoutes);

// Mobile Monitor Web Routes
app.get(['/mobile/pair', '/mobile/verify', '/mobile/monitor', '/mobile/event/:id'], (req, res) => {
    res.sendFile(path.join(__dirname, '../client/mobile.html'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    if (err.type === 'entity.too.large') return res.status(413).json({ message: 'Request payload is too large.' });
    if (err.type === 'entity.parse.failed') return res.status(400).json({ message: 'Invalid JSON request.' });
    console.error('Unhandled error:', err);
    res.status(500).json({ message: 'Internal Server Error' });
});

module.exports = app;
