const mongoose = require('mongoose');

const biometricProfileSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    faceEmbedding: { type: String, required: true }, // Ideally encrypted or secure representation
    enrollmentStatus: { type: String, enum: ['PENDING', 'ENROLLED', 'FAILED'], default: 'PENDING' },
  },
  { timestamps: true }
);

module.exports = mongoose.model('BiometricProfile', biometricProfileSchema);
