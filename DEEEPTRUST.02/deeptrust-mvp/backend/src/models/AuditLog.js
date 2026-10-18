const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema(
  {
    actor: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Who performed the action
    action: { type: String, required: true },
    target: { type: String }, // Resource affected
    timestamp: { type: Date, default: Date.now },
    metadata: { type: Object },
  },
  { timestamps: true }
);

auditLogSchema.index({ timestamp: -1 });

module.exports = mongoose.model('AuditLog', auditLogSchema);
