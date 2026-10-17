const Upload = require('../models/Upload');
const LoginAttempt = require('../models/LoginAttempt');

exports.getOverview = async (req, res) => {
  const userId = req.user.sub;

  const [totalMediaScanned, authenticMediaCount, deepfakesDetected, highRiskAlerts, recentUploads] = await Promise.all([
    Upload.countDocuments({ userId }),
    Upload.countDocuments({ userId, riskLevel: 'LOW' }),
    Upload.countDocuments({ userId, riskLevel: 'HIGH' }),
    LoginAttempt.countDocuments({ userId, riskScore: { $gte: 70 } }),
    Upload.find({ userId }).sort({ createdAt: -1 }).limit(10),
  ]);

  return res.json({
    ok: true,
    overview: {
      totalMediaScanned,
      authenticMediaCount,
      deepfakesDetected,
      highRiskAlerts,
    },
    analytics: {
      trend: [4, 7, 9, 6, 11, 10, 14],
      labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
    },
    history: recentUploads,
  });
};
