// /Koutu/backend/src/__tests__/testUtils.ts
// Common test utilities

import { testQuery } from '../utils/testSetup';
import { initializeTestFirebase } from './__helpers__/firebase.helper';

/**
 * Create a test user in the database
 */
export const createTestUser = async (userData: {
  id?: string;
  email: string;
  name?: string;
}) => {
  const userId = userData.id || `user_${Date.now()}`;
  
  // In a real app, you might insert into a users table
  // For now, just return the user data
  return {
    id: userId,
    email: userData.email,
    name: userData.name || userData.email.split('@')[0],
    createdAt: new Date()
  };
};

/**
 * Clean up test data
 */
export const cleanupTestData = async () => {
  try {
    // Clean up database
    const tables = ['garment_items', 'test_items', 'test_table', 'child_cleanup', 'parent_cleanup'];
    for (const table of tables) {
      await testQuery(`TRUNCATE TABLE ${table} CASCADE`);
    }
    
    // Firebase cleanup is handled by resetFirebaseEmulator
  } catch (error) {
    console.warn('Failed to cleanup test data:', error);
  }
};

/**
 * Wait for a condition to be true
 */
export const waitFor = async (
  condition: () => boolean | Promise<boolean>,
  timeout = 5000,
  interval = 100
): Promise<void> => {
  const start = Date.now();
  
  while (Date.now() - start < timeout) {
    if (await condition()) {
      return;
    }
    await new Promise(resolve => setTimeout(resolve, interval));
  }
  
  throw new Error(`Condition not met within ${timeout}ms`);
};

/**
 * Get Firebase services for testing
 */
export const getFirebaseServices = () => {
  return initializeTestFirebase();
};