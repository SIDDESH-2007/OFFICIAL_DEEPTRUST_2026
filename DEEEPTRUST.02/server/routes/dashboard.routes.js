/**
 * routes/dashboard.routes.js
 * Express Gateway Route for Dashboard Summary & Live Activity
 */

const express = require('express');
const router = express.Router();
const { authMiddleware } = require('../middleware/auth.middleware');

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

router.get('/summary', authMiddleware, (req, res) => forwardToAi('/api/v1/dashboard/summary', req, res));
router.get('/recent-activity', authMiddleware, (req, res) => forwardToAi('/api/v1/dashboard/recent-activity', req, res));

module.exports = router;

