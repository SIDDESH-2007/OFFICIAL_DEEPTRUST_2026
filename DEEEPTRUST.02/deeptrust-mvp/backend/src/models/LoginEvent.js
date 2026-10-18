const mongoose = require('mongoose');

const loginEventSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    timestamp: { type: Date, default: Date.now },
    ipAddress: { type: String },
    userAgent: { type: String },
    deviceHash: { type: String },
    loginResult: { 
      type: String, 
      enum: ['SUCCESS', 'FAILED', 'BLOCKED', 'CHALLENGED'], 
      required: true 
    },
    riskScore: { type: Number },
    riskLevel: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] },
  },
  { timestamps: true }
);

loginEventSchema.index({ userId: 1, timestamp: -1 });

module.exports = mongoose.model('LoginEvent', loginEventSchema);
