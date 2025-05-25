// /Koutu/backend/src/tests/integrationSetup.ts
// Additional setup specifically for integration tests

import { resetFirebaseEmulator } from '@/tests/__helpers__/firebase.helper';
import { testQuery } from '../utils/testSetup';

beforeEach(async () => {
  // Reset Firebase emulator data before each integration test
  await resetFirebaseEmulator();
  
  // Clean up test database tables
  try {
    await testQuery('TRUNCATE TABLE garment_items CASCADE');
    await testQuery('TRUNCATE TABLE test_items CASCADE');
    await testQuery('TRUNCATE TABLE test_table CASCADE');
    await testQuery('TRUNCATE TABLE child_cleanup CASCADE');
    await testQuery('TRUNCATE TABLE parent_cleanup CASCADE');
    await testQuery('TRUNCATE TABLE exclude_test_table CASCADE');
  } catch (error) {
    // Tables might not exist yet, ignore
  }
});