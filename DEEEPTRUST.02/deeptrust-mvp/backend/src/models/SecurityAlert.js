const mongoose = require('mongoose');

const securityAlertSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Optional, alert could be system-wide
    eventType: { type: String, required: true },
    severity: { type: String, enum: ['INFO', 'WARNING', 'CRITICAL'], required: true },
    message: { type: String, required: true },
    riskScore: { type: Number },
    timestamp: { type: Date, default: Date.now },
    status: { type: String, enum: ['OPEN', 'INVESTIGATING', 'RESOLVED', 'DISMISSED'], default: 'OPEN' },
  },
  { timestamps: true }
);

securityAlertSchema.index({ status: 1, severity: 1 });
securityAlertSchema.index({ timestamp: -1 });

module.exports = mongoose.model('SecurityAlert', securityAlertSchema);
