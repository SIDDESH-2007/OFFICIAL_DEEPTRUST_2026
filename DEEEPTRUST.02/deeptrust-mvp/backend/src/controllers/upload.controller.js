const path = require('path');
const Upload = require('../models/Upload');

exports.createUpload = async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ ok: false, message: 'File is required' });
  }

  const upload = await Upload.create({
    userId: req.user.sub,
    fileName: req.file.originalname,
    filePath: req.file.path,
    mimeType: req.file.mimetype,
    status: 'Processing',
  });

  setTimeout(async () => {
    upload.status = 'Completed';
    upload.authenticityScore = 0.72;
    upload.deepfakeProbability = 0.28;
    upload.riskLevel = 'LOW';
    upload.confidence = 0.91;
    await upload.save();
  }, 2000);

  return res.status(201).json({
    ok: true,
    upload: {
      id: upload._id,
      fileName: upload.fileName,
      userId: upload.userId,
      uploadTime: upload.createdAt,
      status: upload.status,
    },
  });
};

exports.getUserUploads = async (req, res) => {
  const uploads = await Upload.find({ userId: req.user.sub }).sort({ createdAt: -1 }).limit(30);
  return res.json({ ok: true, uploads });
};
