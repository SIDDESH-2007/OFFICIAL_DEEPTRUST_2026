const express = require('express');
const authMiddleware = require('../middleware/auth.middleware');
const dashboardController = require('../controllers/dashboard.controller');

const router = express.Router();

router.get('/overview', authMiddleware, dashboardController.getOverview);

module.exports = router;
