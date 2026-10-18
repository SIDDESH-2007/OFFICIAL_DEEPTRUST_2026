/**
 * models/attackLog.model.js
 * Mock Model for storing attack logs
 */
const { saveToCloudDB } = require('../config/cloud.config');

class AttackLog {
    constructor(data) {
        this.username = data.username;
        this.failedStage = data.failedStage;
        this.evidence = data.evidence;
        this.timestamp = data.timestamp;
    }

    async saveToCloud() {
        // In reality, this communicates with Mongoose or Firebase Admin
        try {
            await saveToCloudDB('attack_logs', this);
        } catch (err) {
            console.error("Failed to save attack log", err);
        }
    }
}

module.exports = AttackLog;
