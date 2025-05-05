// /backend/src/config/firebase.ts
import * as admin from 'firebase-admin';
import { config } from './index';

// Initialize Firebase Admin SDK if it hasn't been initialized yet
if (!admin.apps.length) {
  const privateKey = config.firebase.privateKey.replace(/\\n/g, '\n');
  
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: config.firebase.projectId,
      privateKey: privateKey,
      clientEmail: config.firebase.clientEmail,
    }),
    storageBucket: config.firebase.storageBucket
  });
}

// Export the Firebase Admin app and storage
export const firebaseAdmin = admin;
export const storage = admin.storage();
export const bucket = storage.bucket();