/**
 * routes/risk.routes.js
 * Express Gateway Route for Zero-Trust Risk Evaluation
 */

const express = require('express');
const router = express.Router();

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
        return res.status(503).json({
            status: "UNAVAILABLE",
            message: "Risk Engine is offline."
        });
    }
}

router.post('/evaluate', (req, res) => forwardToAi('/api/v1/risk/evaluate', req, res));

module.exports = router;
