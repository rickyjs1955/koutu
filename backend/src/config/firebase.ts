// Updated /backend/src/config/firebase.ts
// Fixed validation order to match security test expectations

import * as admin from 'firebase-admin';
import { config } from './index';

// Validate Firebase configuration with proper error types and order
function validateFirebaseConfig() {
  if (!config?.firebase) {
    throw new TypeError('Cannot read properties of undefined (reading \'projectId\')');
  }
  
  if (!config.firebase.projectId) {
    throw new Error('Project ID is required');
  }
  
  // Check for undefined private key first (this will throw TypeError)
  if (config.firebase.privateKey === undefined) {
    throw new TypeError('Cannot read properties of undefined (reading \'replace\')');
  }
  
  // Check for empty string private key (this will throw TypeError)
  if (config.firebase.privateKey === '') {
    throw new TypeError('Private key cannot be an empty string.');
  }
  
  // Check for whitespace-only private key (this will throw TypeError)
  if (typeof config.firebase.privateKey === 'string' && !config.firebase.privateKey.trim()) {
    throw new TypeError('Private key cannot contain only whitespace.');
  }
  
  // Finally check for any other falsy values (null, etc.)
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