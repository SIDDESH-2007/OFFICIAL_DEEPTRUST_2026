/**
 * routes/auth.routes.js
 * API v1 Authentication Gateway for DeepTrust
 */

const express = require('express');
const router = express.Router();
const AuthController = require('../controllers/auth.controller');

const AI_SERVICE_URL = process.env.AI_SERVICE_URL || 'http://127.0.0.1:8000';

async function forwardToAi(path, req, res, fallbackHandler) {
    try {
        const url = `${AI_SERVICE_URL}${path}`;
        const response = await fetch(url, {
            method: req.method,
            headers: {
                'Content-Type': 'application/json',
                ...(req.headers.authorization ? { 'Authorization': req.headers.authorization } : {}),
                ...(req.headers['user-agent'] ? { 'User-Agent': req.headers['user-agent'] } : {}),
                'X-Forwarded-For': req.ip || req.socket?.remoteAddress || '127.0.0.1'
            },
            body: req.method !== 'GET' ? JSON.stringify(req.body) : undefined
        });

        const data = await response.json();
        return res.status(response.status).json(data);
    } catch (err) {
        if (fallbackHandler) {
            return fallbackHandler(req, res);
        }
        return res.status(503).json({
            status: "UNAVAILABLE",
            message: "Authentication Service is currently offline."
        });
    }
}

// POST /api/v1/auth/login
router.post('/login', (req, res) => forwardToAi('/api/v1/auth/login', req, res, AuthController.login));

// GET /api/v1/auth/verification-session/:id
router.get('/verification-session/:id', (req, res) => forwardToAi(`/api/v1/auth/verification-session/${req.params.id}`, req, res));

// POST /api/v1/auth/finalize
router.post('/finalize', (req, res) => forwardToAi('/api/v1/auth/finalize', req, res));

// POST /api/v1/auth/voice-recovery/verify
router.post('/voice-recovery/verify', (req, res) => forwardToAi('/api/v1/auth/voice-recovery/verify', req, res));
router.post('/voice-recovery/alternate/verify', (req, res) => forwardToAi('/api/v1/auth/voice-recovery/alternate/verify', req, res));

// GET /api/v1/auth/me
router.get('/me', (req, res) => forwardToAi('/api/v1/auth/me', req, res, AuthController.getCurrentUser));

// POST /api/v1/auth/logout
router.post('/logout', (req, res) => forwardToAi('/api/v1/auth/logout', req, res));

// POST /api/v1/auth/register
router.post('/register', (req, res) => forwardToAi('/api/v1/auth/register', req, res, AuthController.register));

// POST /api/v1/auth/forgot-password
router.post('/forgot-password', AuthController.forgotPassword);

// Email verification endpoints
router.post('/email/send-code', (req, res) => forwardToAi('/api/v1/auth/email/send-code', req, res));
router.post('/email/verify-code', (req, res) => forwardToAi('/api/v1/auth/email/verify-code', req, res));
router.post('/email/resend-code', (req, res) => forwardToAi('/api/v1/auth/email/resend-code', req, res));
router.post('/email-verification/request', AuthController.emailVerificationStatus);
router.get('/email-verification/confirm', AuthController.emailVerificationStatus);

module.exports = router;
