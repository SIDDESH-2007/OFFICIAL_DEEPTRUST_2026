const express = require('express');
const multer = require('multer');
const path = require('path');
const authMiddleware = require('../middleware/auth.middleware');
const uploadController = require('../controllers/upload.controller');

const router = express.Router();

const storage = multer.diskStorage({
  destination: path.join(__dirname, '..', '..', 'uploads'),
  filename: (req, file, cb) => {
    const stamp = Date.now();
    cb(null, `${stamp}_${file.originalname.replace(/\s+/g, '_')}`);
  },
});

const upload = multer({ storage });

router.post('/', authMiddleware, upload.single('mediaFile'), uploadController.createUpload);
router.get('/', authMiddleware, uploadController.getUserUploads);

module.exports = router;
