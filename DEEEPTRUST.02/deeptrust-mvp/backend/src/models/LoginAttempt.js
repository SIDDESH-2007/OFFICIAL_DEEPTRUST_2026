const mongoose = require('mongoose');

const loginAttemptSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    ipAddress: String,
    deviceFingerprint: String,
    riskScore: Number,
    status: {
      type: String,
      enum: ['success', 'failed_credentials', 'face_auth_required', 'blocked'],
      required: true,
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model('LoginAttempt', loginAttemptSchema);
