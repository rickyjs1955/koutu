// src/types/express.d.ts
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
        [key: string]: any;
      };
      resourceContext?: {
        [key: string]: any;
      };
    }
  }
}

export {};