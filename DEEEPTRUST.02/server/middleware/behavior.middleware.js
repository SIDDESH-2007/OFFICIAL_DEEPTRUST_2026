/**
 * middleware/behavior.middleware.js
 * Stage 2: Analyze mouse behavior score
 */
const RiskService = require('../services/risk.service');
const LogService = require('../services/log.service');

const behaviorMiddleware = async (req, res, next) => {
    try {
        const { username, behaviorData } = req.body;

        const riskScore = RiskService.calculateScore(behaviorData);

        if (riskScore > 0.8) {
            // High risk -> likely a bot
            await LogService.logFailedAttempt(username, 'Stage 2: High Behavior Risk', { behaviorData, riskScore });
            return res.status(403).json({ message: "Stage 2 Failed: Abnormal behavior detected" });
        }

        // Behavior seems human
        next();
    } catch (error) {
        res.status(500).json({ message: "Server error during Stage 2 analysis" });
    }
};

module.exports = behaviorMiddleware;
