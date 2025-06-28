// modelUtils.ts - Simple type-safe solution
declare const jest: any;
import { query } from '../models/db';
import type { QueryResult } from 'pg';

// Type definition for query function
type QueryFunction = (text: string, params?: any[]) => Promise<QueryResult<any>>;

export const getQueryFunction = (): QueryFunction => {
  // Check if we're in test environment and Jest is available
  if (process.env.NODE_ENV === 'test' && typeof jest !== 'undefined') {
    try {
      // Dynamic import of test utilities only in test environment
      const testSetup = require('./testSetup');
      
      if (testSetup && typeof testSetup.testQuery === 'function') {
        console.log('[MODEL_UTILS] Using test query function');
        return testSetup.testQuery;
      } else {
        console.warn('[MODEL_UTILS] testQuery not found in testSetup, falling back to regular query');
      }
    } catch (error) {
      console.warn('[MODEL_UTILS] Failed to load test utilities, falling back to regular query:', error);
    }
  }

  // Default to regular query function
  console.log('[MODEL_UTILS] Using production query function');
  return query;
};

// Helper function to check which query function is being used
export const getQueryFunctionType = (): 'test' | 'production' => {
  if (process.env.NODE_ENV === 'test' && typeof jest !== 'undefined') {
    try {
      const testSetup = require('./testSetup');
      if (testSetup && typeof testSetup.testQuery === 'function') {
        return 'test';
      }
    } catch {
      // Ignore errors when checking
    }
  }
  
  return 'production';
};