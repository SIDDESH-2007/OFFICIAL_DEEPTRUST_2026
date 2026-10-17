const express = require('express');
const router = express.Router();
const securityController = require('../controllers/security.controller');
const { requireAuth } = require('../middleware/auth.middleware');

// Enrollments (requires valid full auth token)
router.post('/face/enroll', requireAuth, securityController.enrollFace);
router.post('/voice/enroll', requireAuth, securityController.enrollVoice);

// Verifications (requires temp session token from login)
router.post('/face/verify', securityController.verifyFace);
router.post('/voice/verify', securityController.verifyVoice);

// Behavioral
router.post('/behavior', securityController.recordBehavior);

// Final Risk Calculation
router.post('/risk', securityController.calculateFinalRisk);

module.exports = router;
