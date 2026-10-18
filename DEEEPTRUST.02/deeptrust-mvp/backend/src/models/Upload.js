const mongoose = require('mongoose');

const uploadSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    fileName: { type: String, required: true },
    filePath: { type: String, required: true },
    mimeType: { type: String, required: true },
    status: { type: String, enum: ['Processing', 'Completed', 'Failed'], default: 'Processing' },
    authenticityScore: Number,
    deepfakeProbability: Number,
    riskLevel: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH'] },
    confidence: Number,
  },
  { timestamps: true }
);

module.exports = mongoose.model('Upload', uploadSchema);
