const mongoose = require('mongoose');

const behaviorEventSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    sessionId: { type: String, required: true },
    typingMetrics: { type: Object }, // e.g., cadence, speed
    mouseMetrics: { type: Object }, // e.g., velocity, pattern
    focusChanges: { type: Number, default: 0 },
    tabVisibilityChanges: { type: Number, default: 0 },
    timestamp: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

behaviorEventSchema.index({ userId: 1, sessionId: 1 });

module.exports = mongoose.model('BehaviorEvent', behaviorEventSchema);
