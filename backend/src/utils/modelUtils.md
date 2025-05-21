import { query } from '../models/db';
import { testQuery } from './testSetup';

// Use testQuery in test environment, regular query otherwise
export const getQueryFunction = () => {
  return process.env.NODE_ENV === 'test' ? testQuery : query;
};