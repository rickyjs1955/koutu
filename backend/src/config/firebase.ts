// /backend/src/config/firebase.ts
import * as admin from 'firebase-admin';
import { config } from './index';

// Validate Firebase configuration
function validateFirebaseConfig() {
  if (!config?.firebase) {
    throw new Error('Firebase configuration is missing');
  }
  
  if (!config.firebase.projectId) {
    throw new Error('Project ID is required');
  }
  
  if (!config.firebase.privateKey) {
    throw new Error('Private key is required');
  }
  
  if (!config.firebase.clientEmail) {
    throw new Error('Client email is required');
  }
}

// Initialize Firebase Admin SDK if it hasn't been initialized yet
if (!admin.apps.length) {
  try {
    validateFirebaseConfig();
    
    const privateKey = config.firebase.privateKey.replace(/\\n/g, '\n');
    
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: config.firebase.projectId,
        privateKey: privateKey,
        clientEmail: config.firebase.clientEmail,
      }),
      storageBucket: config.firebase.storageBucket
    });
  } catch (error) {
    console.error('Failed to initialize Firebase:', error);
    throw error;
  }
}

// Export the Firebase Admin app and storage
export const firebaseAdmin = admin;
export const storage = admin.storage();
export const bucket = storage.bucket();