/**
 * services/log.service.js
 * Logs suspicious activities to the cloud database
 */
const AttackLog = require('../models/attackLog.model');
const logger = require('../utils/logger');

const LogService = {
    async logFailedAttempt(username, stage, evidence) {
        try {
            logger.warn(`Failed Login Attempt -> User: ${username} | Stage: ${stage}`);

            // In a real scenario, you save it to DB
            const logEntry = new AttackLog({
                username: username || 'unknown',
                failedStage: stage,
                evidence,
                timestamp: new Date()
            });
            await logEntry.saveToCloud();

        } catch (error) {
            logger.error(`Error saving attack log: ${error.message}`);
        }
    },

    async logSuccess(username) {
        logger.info(`Successful Admin Login -> User: ${username}`);
    }
};

module.exports = LogService;
