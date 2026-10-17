/**
 * routes/admin.routes.js
 * Defines endpoints for admin operations
 */

const express = require('express');
const router = express.Router();

const AdminController = require('../controllers/admin.controller');

// Import middlewares for the multi-stage pipeline
const faceMiddleware = require('../middleware/face.middleware');
const behaviorMiddleware = require('../middleware/behavior.middleware');
const captchaMiddleware = require('../middleware/captcha.middleware');

/**
 * POST /api/admin/login
 * Flow: 
 * 1. Face & Pattern Verification (faceMiddleware)
 * 2. Behavior Analysis (behaviorMiddleware)
 * 3. Captcha Verification (captchaMiddleware)
 * If all pass -> AdminController.login
 */
router.post(
    '/login',
    faceMiddleware,
    behaviorMiddleware,
    captchaMiddleware,
    AdminController.login
);

module.exports = router;
