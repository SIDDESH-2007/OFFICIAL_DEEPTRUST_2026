const mongoose = require('mongoose');

const trustedDeviceSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    deviceHash: { type: String, required: true },
    browser: { type: String },
    operatingSystem: { type: String },
    firstSeen: { type: Date, default: Date.now },
    lastSeen: { type: Date, default: Date.now },
    status: { type: String, enum: ['TRUSTED', 'UNTRUSTED', 'REVOKED'], default: 'TRUSTED' },
  },
  { timestamps: true }
);

trustedDeviceSchema.index({ userId: 1, deviceHash: 1 }, { unique: true });

module.exports = mongoose.model('TrustedDevice', trustedDeviceSchema);
