import { diskStorage } from 'multer';
import { existsSync, mkdirSync } from 'fs';
import { extname, join } from 'path';
import { Request } from 'express';
import { UnsupportedMediaTypeException } from '@nestjs/common';

const PROFILE_UPLOAD_DIR = join(process.cwd(), 'uploads', 'profile');

function ensureUploadDir() {
  if (!existsSync(PROFILE_UPLOAD_DIR)) {
    mkdirSync(PROFILE_UPLOAD_DIR, { recursive: true });
  }
}

export const profilePhotoStorage = diskStorage({
  destination: (_req, _file, cb) => {
    ensureUploadDir();
    cb(null, PROFILE_UPLOAD_DIR);
  },
  filename: (req: Request & { user?: any }, file, cb) => {
    const ext = extname(file.originalname) || '.jpg';
    const userId = req.user?.userId ?? 'profile';
    const uniqueSuffix = Date.now();
    cb(null, `${userId}-${uniqueSuffix}${ext}`);
  },
});

const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/webp'];

export function profilePhotoFileFilter(
  _req: Request,
  file: Express.Multer.File,
  cb: (error: Error | null, acceptFile: boolean) => void,
) {
  if (allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(
      new UnsupportedMediaTypeException(
        'Formato de imagen no permitido. Usa JPG, PNG o WEBP.',
      ),
      false,
    );
  }
}

export function getProfilePhotoPublicPath(filename: string) {
  return `/uploads/profile/${filename}`;
}
