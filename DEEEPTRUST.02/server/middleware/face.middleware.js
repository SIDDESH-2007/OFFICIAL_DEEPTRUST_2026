/**
 * middleware/face.middleware.js
 * Stage 1: Face verification + pattern verification
 */
const LogService = require('../services/log.service');

const faceMiddleware = async (req, res, next) => {
    try {
        const { username, pattern, faceData } = req.body;

        // Mock Logic: Check if pattern and faceData exist
        if (!pattern || !faceData) {
            await LogService.logFailedAttempt(username, 'Stage 1: Missing Credentials', req.body);
            return res.status(401).json({ message: "Stage 1 Failed: Invalid Pattern or Face Data" });
        }

        // Ideally, run face matching AI model here
        // if (faceMatched) next() else block

        // Mock success
        next();
    } catch (error) {
        res.status(500).json({ message: "Server error during Stage 1 verification" });
    }
};

module.exports = faceMiddleware;
