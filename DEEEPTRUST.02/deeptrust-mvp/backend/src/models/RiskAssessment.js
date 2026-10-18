const mongoose = require('mongoose');

const riskAssessmentSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    sessionId: { type: String, required: true },
    credentialRisk: { type: Number, default: 0 },
    deviceRisk: { type: Number, default: 0 },
    behavioralRisk: { type: Number, default: 0 },
    biometricRisk: { type: Number, default: 0 },
    patternRisk: { type: Number, default: 0 },
    finalRiskScore: { type: Number, required: true },
    riskLevel: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], required: true },
    decision: { type: String, enum: ['ALLOW', 'CHALLENGE', 'BLOCK'], required: true },
    timestamp: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

riskAssessmentSchema.index({ userId: 1, timestamp: -1 });

module.exports = mongoose.model('RiskAssessment', riskAssessmentSchema);
