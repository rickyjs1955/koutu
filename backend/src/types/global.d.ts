// src/types/global.d.ts
import 'express-session';

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
        [key: string]: any;
      };
      session?: any;
    }
  }
}

export {};