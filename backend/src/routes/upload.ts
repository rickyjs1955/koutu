// backend/src/routes/upload.ts
import { Router, Request, Response } from 'express';
import multer from 'multer';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';

const router = Router();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Make sure this directory exists
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueName = `${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

router.post('/upload', upload.single('image'), (req, res) => {
  try {
    if (!req.file) {
      res.status(400).json({
        status: 'error',
        message: 'No image file provided'
      });
      return;
    }

    res.json({
      status: 'success',
      message: 'Image uploaded successfully',
      data: {
        id: path.parse(req.file.filename).name,
        filename: req.file.filename,
        originalName: req.file.originalname,
        size: req.file.size,
        path: req.file.path,
        url: `/uploads/${req.file.filename}`
      }
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Upload failed'
    });
  }
});

export default router;