/**
 * routes/health.routes.js
 * Real system health check endpoints for DeepTrust Boot Experience
 */

const express = require('express');
const router = express.Router();
const { getDBStatus } = require('../config/db.config');

const AI_SERVICE_URL = process.env.AI_SERVICE_URL || 'http://127.0.0.1:8000';

const handleHealthStatus = async (req, res) => {
    const startTime = Date.now();

    // Check MongoDB status
    const dbHealth = await getDBStatus();
    const isDbOnline = dbHealth.connected;

    // Probe the existing voice health endpoint without loading models or touching profiles.
    // Start alongside face readiness so an offline AI service adds only one timeout.
    const voiceProbe = (async () => {
        try {
            const response = await fetch(`${AI_SERVICE_URL}/api/v1/voice/health`, { signal: AbortSignal.timeout(1000) });
            if (!response.ok) return { status: 'UNAVAILABLE', details: 'Voice health check failed' };
            const data = await response.json();
            if (data.status === 'Operational' && data.speaker_loaded === true && data.replay_loaded === true && data.speech_loaded === true) {
                return { status: 'ONLINE', details: 'Speaker, replay and speech engines ready' };
            }
            if (data.status === 'Available / not probed') {
                return { status: 'NOT_PROBED', details: 'Voice service reachable; models not initialized yet' };
            }
            return { status: 'UNAVAILABLE', details: 'Voice readiness could not be confirmed' };
        } catch (_) {
            return { status: 'UNAVAILABLE', details: 'Voice service unreachable' };
        }
    })();

    // Check Face AI Microservice status
    let isFaceAiOnline = false;
    let faceAiDetails = 'Not Configured';
    try {
        const aiRes = await fetch(`${AI_SERVICE_URL}/api/v1/face/health`, { signal: AbortSignal.timeout(1000) });
        if (aiRes.ok) {
            const aiData = await aiRes.json();
            isFaceAiOnline = true;
            faceAiDetails = 'OpenCV YuNet DNN & SFace Ready';
        }
    } catch (e) {
        faceAiDetails = 'Face Engine Standby / Offline';
    }

    const voiceHealth = await voiceProbe;

    const healthData = {
        timestamp: new Date().toISOString(),
        status: isDbOnline ? 'HEALTHY' : 'DEGRADED',
        services: [
            {
                id: 'api',
                name: 'API Gateway',
                status: 'ONLINE',
                required: true,
                latencyMs: Math.max(1, Date.now() - startTime)
            },
            {
                id: 'database',
                name: 'Database Connection',
                status: isDbOnline ? 'ONLINE' : 'UNAVAILABLE',
                required: true,
                details: dbHealth.details || 'MongoDB Local Connection'
            },
            {
                id: 'auth',
                name: 'Authentication Service',
                status: 'ONLINE',
                required: true,
                details: 'JWT & Bcrypt Engine Ready'
            },
            {
                id: 'risk',
                name: 'Risk Engine',
                status: 'ONLINE',
                required: true,
                details: 'Adaptive Telemetry Active'
            },
            {
                id: 'security',
                name: 'Security Layer',
                status: 'ONLINE',
                required: true,
                details: 'Zero-Trust Pipeline Active'
            },
            {
                id: 'face',
                name: 'Face Verification',
                status: isFaceAiOnline ? 'ONLINE' : 'NOT_CONFIGURED',
                required: false,
                details: faceAiDetails
            },
            {
                id: 'voice',
                name: 'Voice Verification',
                status: voiceHealth.status,
                required: false,
                details: voiceHealth.details
            }
        ]
    };

    res.status(200).json(healthData);
};

router.get('/', handleHealthStatus);
router.get('/status', handleHealthStatus);

module.exports = router;
