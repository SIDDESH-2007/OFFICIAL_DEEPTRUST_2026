/**
 * config/cloud.config.js
 * Connection config for Cloud Storage (Firebase / AWS)
 */

const logger = require('../utils/logger');

const saveToCloudDB = async (collection, data) => {
    // Mock save operation
    return new Promise((resolve) => {
        setTimeout(() => {
            logger.info(`[CLOUD] Saved document to ${collection}`);
            resolve(true);
        }, 300);
    });
};

module.exports = { saveToCloudDB };
