/**
 * services/risk.service.js
 * Calculates behavior risk score based on mouse tracker data
 */

const RiskService = {
    calculateScore(behaviorData) {
        if (!behaviorData) return 1.0; // Max risk if no data

        let score = 0.0;

        // Mock heuristics
        // 1. If very few movements but an instant click -> high risk
        if (behaviorData.totalMoves < 5 && behaviorData.totalClicks > 0) {
            score += 0.5;
        }

        // 2. If duration is under 500ms (superhuman speed) -> high risk
        if (behaviorData.duration < 500) {
            score += 0.4;
        }

        // Returns score between 0.0 (safe) to 1.0 (bot)
        return Math.min(score, 1.0);
    }
};

module.exports = RiskService;
