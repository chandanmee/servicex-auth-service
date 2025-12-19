import multer from "multer";
import path from "path";
import fs from "fs";

const UPLOAD_DIR = process.env.LOCAL_UPLOAD_PATH || "uploads";
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const name = `${req.params.id || "anon"}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}${ext}`;
    cb(null, name);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = /jpeg|jpg|png|webp/;
    const ok = allowed.test(file.mimetype);
    if (ok) cb(null, true);
    else cb(new Error("Invalid file type"));
  }
});

export default upload;
