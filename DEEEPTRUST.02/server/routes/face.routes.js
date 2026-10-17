/**
 * routes/face.routes.js
 * Express Gateway Route for Face Verification & Active Liveness AI Microservice
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
        console.warn(`[Face Gateway Proxy Error] ${path}:`, err.message);
        return res.status(503).json({
            status: "UNAVAILABLE",
            message: "Face Verification Unavailable. Computer Vision Engine is offline."
        });
    }
}

// Account-scoped setup uses the verification token, with Google MFA authorization.
router.post('/setup/status', (req, res) => forwardToAi('/api/v1/face/setup/status', req, res));
router.post('/setup/authorize', (req, res) => forwardToAi('/api/v1/face/setup/authorize', req, res));

// Health Check
router.get('/health', (req, res) => forwardToAi('/api/v1/face/health', req, res));

// Real Face Detection (YuNet DNN)
router.post('/detect', (req, res) => forwardToAi('/api/v1/face/detect', req, res));

// Face Enrollment (SFace DNN -> MongoDB)
router.post('/enroll', (req, res) => forwardToAi('/api/v1/face/enroll', req, res));

// Identity Matching (SFace Cosine Similarity -> MongoDB face_profiles)
router.post('/match', (req, res) => forwardToAi('/api/v1/face/match', req, res));

module.exports = router;
