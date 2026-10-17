/**
 * routes/notifications.routes.js
 * Express Gateway Route for Notifications
 */

const express = require('express');
const router = express.Router();
const { authMiddleware, requireNonAuditor } = require('../middleware/auth.middleware');

const AI_SERVICE_URL = process.env.AI_SERVICE_URL || 'http://127.0.0.1:8000';

async function forwardToAi(path, req, res) {
    try {
        const response = await fetch(`${AI_SERVICE_URL}${path}`, {
            method: req.method,
            headers: {
                'Content-Type': 'application/json',
                ...(req.headers.authorization ? { 'Authorization': req.headers.authorization } : {})
            },
            body: req.method !== 'GET' ? JSON.stringify(req.body) : undefined
        });

        const data = await response.json();
        return res.status(response.status).json(data);
    } catch (err) {
        return res.status(502).json({
            success: false,
            message: "Service temporarily unavailable"
        });
    }
}

router.get('/', authMiddleware, (req, res) => forwardToAi('/api/v1/notifications', req, res));
router.get('/unread-count', authMiddleware, (req, res) => forwardToAi('/api/v1/notifications/unread-count', req, res));
router.post('/read-all', authMiddleware, requireNonAuditor, (req, res) => forwardToAi('/api/v1/notifications/read-all', req, res));

module.exports = router;

