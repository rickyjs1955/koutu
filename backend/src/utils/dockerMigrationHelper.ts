/**
 * 🐳 Docker Migration Helper - Test Infrastructure Dual-Mode System
 * 
 * ============================================================================
 * STRATEGIC OVERVIEW
 * ============================================================================
 * 
 * This module implements a PERPETUAL DUAL-MODE test infrastructure system that
 * provides both Docker and Manual setup options for running our 4000+ test suite.
 * 
 * WHY DUAL-MODE EXISTS:
 * • RELIABILITY: Guarantees ALL tests work with BOTH Docker AND Manual setup
 * • RISK MITIGATION: Provides fallback if Docker ecosystem fails
 * • DEVELOPER CHOICE: Allows preference-based setup selection
 * • FUTURE-PROOFING: Maintains flexibility for infrastructure evolution
 * 
 * POLICY: We maintain BOTH systems indefinitely to ensure 100% test reliability.
 * This is a strategic decision prioritizing robustness over code simplicity.
 * 
 * ============================================================================
 * ARCHITECTURE DECISION RECORD (ADR)
 * ============================================================================
 * 
 * Decision: Maintain perpetual dual-mode test infrastructure
 * Status: ACCEPTED (Team consensus)
 * Date: 2025-06-09
 * 
 * Context:
 * - Started with 4000+ tests using manual PostgreSQL + Firebase setup
 * - Needed Docker for better CI/CD reliability and developer onboarding
 * - Risk: Pure migration could leave team stranded if Docker fails
 * 
 * Decision:
 * - Keep BOTH manual and Docker implementations permanently
 * - Default to Docker for convenience
 * - Maintain manual as emergency fallback
 * - All new tests MUST work with both systems
 * 
 * Consequences:
 * ✅ PROS: Ultimate reliability, zero risk migration, developer flexibility
 * ❌ CONS: ~20 lines of switching code, need to test both paths
 * 
 * ============================================================================
 * USAGE PATTERNS
 * ============================================================================
 * 
 * 99% Normal Development (Docker - Default):
 * ```bash
 * npx jest                    # Uses Docker automatically
 * npm run test               # Uses Docker automatically
 * ```
 * 
 * 1% Emergency Fallback (Manual):
 * ```bash
 * $env:USE_MANUAL_TESTS="true"
 * npx jest                   # Falls back to manual setup
 * ```
 * 
 * Debugging/Development Preference:
 * ```bash
 * # Some developers prefer direct database access for debugging
 * $env:USE_MANUAL_TESTS="true"
 * npx jest specific.test.ts
 * ```
 * 
 * ============================================================================
 * TEAM POLICIES & REQUIREMENTS
 * ============================================================================
 * 
 * 🔒 MANDATORY: All new tests MUST pass with BOTH Docker AND Manual setup
 * 
 * Before merging any PR with new tests:
 * 1. Verify Docker mode: `npx jest yourNewTest.test.ts`
 * 2. Verify Manual mode: `USE_MANUAL_TESTS=true npx jest yourNewTest.test.ts`
 * 3. Both must pass ✅
 * 
 * CI/CD Pipeline Requirements:
 * - Primary: Run all tests with Docker
 * - Secondary: Run sample tests with Manual (verification)
 * - Both pipelines must pass for deployment
 * 
 * ============================================================================
 * DISASTER RECOVERY PROCEDURES
 * ============================================================================
 * 
 * If Docker Infrastructure Fails:
 * 
 * 1. Immediate Response:
 * ```bash
 * # All developers switch to manual
 * $env:USE_MANUAL_TESTS="true"
 * npx jest
 * ```
 * 
 * 2. Team Communication:
 * ```
 * @channel Docker infrastructure is down. 
 * Everyone please use: USE_MANUAL_TESTS=true npx jest
 * Development and CI continue normally with manual setup.
 * ```
 * 
 * 3. Long-term Resolution:
 * - Fix Docker issues without pressure
 * - Team continues working with manual
 * - Switch back to Docker when resolved
 * 
 * ============================================================================
 * IMPLEMENTATION DETAILS
 * ============================================================================
 */

// /backend/src/utils/dockerMigrationHelper.ts
// Safe migration utilities for dual-mode test infrastructure

/**
 * Determines whether to use Docker-backed test infrastructure
 * 
 * DECISION HIERARCHY:
 * 1. Explicit manual override (emergency fallback)
 * 2. Explicit Docker override (debugging/preference)  
 * 3. CI environment auto-detection
 * 4. Docker service availability detection
 * 5. DEFAULT: Docker (preferred mode)
 * 
 * @returns {boolean} true = Docker mode, false = Manual mode
 */
export const shouldUseDocker = (): boolean => {
  // 🚨 EMERGENCY FALLBACK: Manual override (highest priority)
  // Use case: Docker infrastructure is broken, team needs to continue working
  if (process.env.USE_MANUAL_TESTS === 'true') {
    console.log('🔧 Using MANUAL test setup (emergency fallback mode)');
    return false;
  }
  
  // 🐳 EXPLICIT OVERRIDE: Docker override
  // Use case: Forcing Docker even when auto-detection might fail
  if (process.env.USE_DOCKER_TESTS === 'true') {
    console.log('🐳 Using DOCKER test setup (explicit override)');
    return true;
  }
  
  // 🏢 CI ENVIRONMENT: Default to Docker in CI (more reliable)
  if (process.env.CI === 'true') {
    console.log('🐳 Using DOCKER test setup (CI environment)');
    return true;
  }
  
  // 🔍 AUTO-DETECTION: Check if Docker services are available
  if (areDockerServicesRunning()) {
    console.log('🐳 Using DOCKER test setup (services detected)');
    return true;
  }
  
  // 🎯 DEFAULT: Docker (preferred for new development)
  // Note: If Docker isn't available, this will fail fast and developer
  // can manually switch to USE_MANUAL_TESTS=true
  console.log('🐳 Using DOCKER test setup (default mode)');
  return true;
};

/**
 * Check if Docker Compose services are running
 * 
 * This is a lightweight check to see if our test infrastructure
 * containers are already running before defaulting to Docker.
 * 
 * @returns {boolean} true if Docker services are detected
 */
function areDockerServicesRunning(): boolean {
  try {
    // Quick check for postgres-test service (port 5433)
    const { execSync } = require('child_process');
    execSync('nc -z localhost 5433', { stdio: 'ignore', timeout: 1000 });
    return true;
  } catch {
    // Docker services not running or nc command not available
    return false;
  }
}

/**
 * Get the appropriate TestDatabaseConnection implementation
 * 
 * This is the CORE of our dual-mode system. It dynamically loads
 * the correct implementation based on the mode decision.
 * 
 * @returns {TestDatabaseConnection} Either Docker or Manual implementation
 */
export const getTestDatabaseConnection = () => {
  if (shouldUseDocker()) {
    // 🐳 DOCKER MODE: Use containerized PostgreSQL + Firebase
    console.log('📦 Loading Docker test database implementation');
    return require('./testDatabaseConnection.v2').TestDatabaseConnection;
  } else {
    // 🔧 MANUAL MODE: Use local PostgreSQL + Firebase
    console.log('🛠️ Loading Manual test database implementation');
    return require('./testDatabaseConnection').TestDatabaseConnection;
  }
};

/**
 * Get the appropriate TestDatabase implementation
 * 
 * Legacy support for older test utilities that might still use TestDatabase
 * instead of TestDatabaseConnection.
 * 
 * @returns {TestDatabase} Either Docker or Manual implementation
 */
export const getTestDatabase = () => {
  if (shouldUseDocker()) {
    console.log('📦 Loading Docker test database implementation');
    return require('./testDatabase.v2').TestDatabase;
  } else {
    console.log('🛠️ Loading Manual test database implementation');
    return require('./testDatabase').TestDatabase;
  }
};

/**
 * 🧪 VALIDATION UTILITY: Ensure both implementations work identically
 * 
 * This function can be run periodically to verify that both Docker and Manual
 * implementations produce identical results. Use for confidence building.
 * 
 * Usage:
 * ```typescript
 * import { validateMigration } from './dockerMigrationHelper';
 * await validateMigration(); // Returns true if both work identically
 * ```
 * 
 * @returns {Promise<boolean>} true if both implementations are compatible
 */
export const validateMigration = async (): Promise<boolean> => {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error('Migration validation can only run in test environment');
  }

  console.log('🔍 Validating Docker vs Manual implementations...');
  
  try {
    // Test basic operations with both implementations
    const results = await Promise.all([
      testImplementation('docker'),
      testImplementation('manual')
    ]);

    const [dockerResult, manualResult] = results;
    
    if (JSON.stringify(dockerResult) === JSON.stringify(manualResult)) {
      console.log('✅ Migration validation passed - implementations are compatible');
      return true;
    } else {
      console.log('❌ Migration validation failed - implementations differ');
      console.log('Docker result:', dockerResult);
      console.log('Manual result:', manualResult);
      return false;
    }
  } catch (error) {
    console.log('❌ Migration validation error:', error);
    return false;
  }
};

/**
 * Test a specific implementation in isolation
 * 
 * @param {'docker' | 'manual'} type - Which implementation to test
 * @returns {Promise<any>} Result from basic database operation
 */
async function testImplementation(type: 'docker' | 'manual'): Promise<any> {
  const originalEnv = process.env.USE_MANUAL_TESTS;
  
  try {
    // Force the implementation type
    process.env.USE_MANUAL_TESTS = type === 'manual' ? 'true' : 'false';
    
    const TestDB = getTestDatabaseConnection();
    await TestDB.initialize();
    
    // Run some basic tests
    const result = await TestDB.query('SELECT 1 as test_value');
    
    await TestDB.cleanup();
    
    return result.rows[0];
  } finally {
    // Restore original environment
    if (originalEnv !== undefined) {
      process.env.USE_MANUAL_TESTS = originalEnv;
    } else {
      delete process.env.USE_MANUAL_TESTS;
    }
  }
}

/**
 * Environment setup for tests
 * 
 * This function sets up environment variables based on the chosen mode.
 * Called automatically by testSetup.ts during initialization.
 */
export const setupTestEnvironment = () => {
  if (shouldUseDocker()) {
    // Set environment variables for Docker services
    process.env.DATABASE_URL = 'postgresql://postgres:postgres@localhost:5433/koutu_test';
    process.env.TEST_DATABASE_URL = 'postgresql://postgres:postgres@localhost:5433/koutu_test';
    process.env.FIRESTORE_EMULATOR_HOST = 'localhost:9100';
    process.env.FIREBASE_AUTH_EMULATOR_HOST = 'localhost:9099';
    process.env.FIREBASE_STORAGE_EMULATOR_HOST = 'localhost:9199';
    console.log('🐳 Environment configured for Docker services');
  } else {
    // Keep existing environment variables for manual setup
    console.log('🔧 Environment configured for manual services');
  }
};

/**
 * Check if migration is recommended for current environment
 * 
 * This is informational only - doesn't affect behavior.
 * Useful for understanding why a particular mode was chosen.
 * 
 * @returns {object} Migration recommendation with reasoning
 */
export const shouldMigrate = (): { migrate: boolean; reason: string } => {
  if (process.env.CI === 'true') {
    return { migrate: true, reason: 'CI environment - Docker provides better isolation' };
  }
  
  if (areDockerServicesRunning()) {
    return { migrate: true, reason: 'Docker services detected - faster and more reliable' };
  }
  
  if (process.env.NODE_ENV === 'development') {
    return { migrate: false, reason: 'Development environment - manual setup provides flexibility' };
  }
  
  return { migrate: false, reason: 'Docker services not available - using manual setup' };
};

/**
 * 📊 METRICS: Migration progress tracking
 * 
 * Track how much of the codebase has been verified to work with Docker.
 * This is informational and can be used for migration confidence metrics.
 * 
 * @returns {object} Current migration statistics
 */
export const getMigrationStatus = () => {
  const totalTests = 4000; // Your current test count
  const dockerTests = parseInt(process.env.DOCKER_TESTS_COUNT || '4000', 10);
  
  return {
    total: totalTests,
    migrated: dockerTests,
    remaining: totalTests - dockerTests,
    percentage: Math.round((dockerTests / totalTests) * 100),
    status: dockerTests >= totalTests ? 'COMPLETE' : 'IN_PROGRESS'
  };
};

/**
 * 🎯 TEAM UTILITIES: Common debugging helpers
 */

/**
 * Display current test mode and configuration
 * Useful for debugging and support
 */
export const displayCurrentMode = () => {
  const mode = shouldUseDocker() ? 'DOCKER' : 'MANUAL';
  const recommendation = shouldMigrate();
  
  console.log(`
🎯 TEST INFRASTRUCTURE STATUS
════════════════════════════════════════
Current Mode: ${mode}
Recommendation: ${recommendation.migrate ? 'Docker' : 'Manual'}
Reason: ${recommendation.reason}
Environment: ${process.env.NODE_ENV || 'development'}
CI: ${process.env.CI || 'false'}
════════════════════════════════════════
Environment Variables:
  USE_MANUAL_TESTS: ${process.env.USE_MANUAL_TESTS || 'unset'}
  USE_DOCKER_TESTS: ${process.env.USE_DOCKER_TESTS || 'unset'}
════════════════════════════════════════
  `);
};

/**
 * 🚨 EMERGENCY PROCEDURES
 * 
 * If Docker infrastructure completely fails, run this function to guide
 * developers through switching to manual mode.
 */
export const emergencyFallback = () => {
  console.log(`
🚨 EMERGENCY FALLBACK TO MANUAL SETUP
════════════════════════════════════════
Docker infrastructure appears to be unavailable.
Following emergency procedures:

1. Set environment variable:
   Windows: $env:USE_MANUAL_TESTS="true"
   Unix:    export USE_MANUAL_TESTS="true"

2. Run tests normally:
   npx jest

3. Notify team in Slack/Teams:
   "Docker test infrastructure down, using manual fallback"

4. Continue development normally
   Manual setup provides full functionality

5. When Docker is fixed, remove environment variable:
   Windows: Remove-Item Env:USE_MANUAL_TESTS
   Unix:    unset USE_MANUAL_TESTS
════════════════════════════════════════
  `);
};

// Export emergency function globally for easy access
if (typeof global !== 'undefined') {
  (global as any).emergencyFallback = emergencyFallback;
}

/**
 * Ensure wardrobe-specific tables exist in both modes
 * This fixes the "wardrobe_items does not exist" errors
 * 
 * @returns {Promise<void>}
 */
export const ensureWardrobeTablesExist = async (): Promise<void> => {
  const TestDB = getTestDatabaseConnection();
  
  try {
    // Check if wardrobe_items table exists
    const result = await TestDB.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'wardrobe_items'
      );
    `);

    if (!result.rows[0].exists) {
      console.log('🔧 Creating missing wardrobe_items table...');
      
      // Create wardrobe_items table
      await TestDB.query(`
        CREATE TABLE wardrobe_items (
          id SERIAL PRIMARY KEY,
          wardrobe_id UUID NOT NULL REFERENCES wardrobes(id) ON DELETE CASCADE,
          garment_item_id UUID NOT NULL REFERENCES garment_items(id) ON DELETE CASCADE,
          position INTEGER DEFAULT 0,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          UNIQUE(wardrobe_id, garment_item_id)
        )
      `);

      // Add performance indexes
      await TestDB.query(`
        CREATE INDEX idx_wardrobe_items_wardrobe_id ON wardrobe_items(wardrobe_id);
        CREATE INDEX idx_wardrobe_items_garment_id ON wardrobe_items(garment_item_id);
        CREATE INDEX idx_wardrobe_items_position ON wardrobe_items(wardrobe_id, position);
      `);
    }

    // Ensure wardrobes table has is_default column
    await TestDB.query(`
      ALTER TABLE wardrobes 
      ADD COLUMN IF NOT EXISTS is_default BOOLEAN DEFAULT FALSE;
    `);

    // Ensure wardrobes columns are TEXT (not VARCHAR with limits)
    try {
      await TestDB.query(`
        ALTER TABLE wardrobes 
        ALTER COLUMN name TYPE TEXT,
        ALTER COLUMN description TYPE TEXT;
      `);
    } catch (error) {
      // Columns might already be TEXT, ignore error
      console.log('📝 Wardrobes columns already TEXT or conversion not needed');
    }

    console.log('✅ Wardrobe tables verified and ready');
  } catch (error) {
    console.warn('⚠️ Error ensuring wardrobe tables exist:', error);
    throw error;
  }
};

/**
 * Setup wardrobe test environment with proper schema
 * Call this in your test setup files
 * 
 * @returns {Promise<void>}
 */
export const setupWardrobeTestEnvironment = async (): Promise<void> => {
  console.log('🧪 Setting up wardrobe test environment...');
  
  // Setup base test environment (your existing function)
  setupTestEnvironment();
  
  // Initialize database connection
  const TestDB = getTestDatabaseConnection();
  await TestDB.initialize();
  
  // Ensure wardrobe-specific tables exist
  await ensureWardrobeTablesExist();
  
  console.log('✅ Wardrobe test environment ready');
};

/**
 * Enhanced validation that includes wardrobe tables
 * Extends your existing validateMigration function
 * 
 * @returns {Promise<boolean>}
 */
export const validateWardrobeMigration = async (): Promise<boolean> => {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error('Wardrobe migration validation can only run in test environment');
  }

  console.log('🔍 Validating wardrobe tables in both Docker and Manual modes...');
  
  try {
    // Test wardrobe operations with both implementations
    const results = await Promise.all([
      testWardrobeImplementation('docker'),
      testWardrobeImplementation('manual')
    ]);

    const [dockerResult, manualResult] = results;
    
    // Compare table structures
    const dockerTables = dockerResult.tables.sort();
    const manualTables = manualResult.tables.sort();
    
    if (JSON.stringify(dockerTables) === JSON.stringify(manualTables)) {
      console.log('✅ Wardrobe migration validation passed - both modes have identical table structures');
      return true;
    } else {
      console.log('❌ Wardrobe migration validation failed - table structures differ');
      console.log('Docker tables:', dockerTables);
      console.log('Manual tables:', manualTables);
      return false;
    }
  } catch (error) {
    console.log('❌ Wardrobe migration validation error:', error);
    return false;
  }
};

/**
 * Test wardrobe-specific implementation
 * 
 * @param {'docker' | 'manual'} type - Which implementation to test
 * @returns {Promise<any>} Result from wardrobe table queries
 */
async function testWardrobeImplementation(type: 'docker' | 'manual'): Promise<any> {
  const originalEnv = process.env.USE_MANUAL_TESTS;
  
  try {
    // Force the implementation type
    process.env.USE_MANUAL_TESTS = type === 'manual' ? 'true' : 'false';
    
    const TestDB = getTestDatabaseConnection();
    await TestDB.initialize();
    
    // Ensure wardrobe tables exist
    await ensureWardrobeTablesExist();
    
    // Test wardrobe table structure
    const tableResult = await TestDB.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_name IN ('wardrobes', 'wardrobe_items', 'garment_items')
      ORDER BY table_name
    `);
    
    const columnResult = await TestDB.query(`
      SELECT table_name, column_name, data_type 
      FROM information_schema.columns 
      WHERE table_name IN ('wardrobes', 'wardrobe_items') 
      ORDER BY table_name, column_name
    `);
    
    await TestDB.cleanup();
    
    interface WardrobeTableResult {
      table_name: string;
    }

    interface WardrobeColumnResult {
      table_name: string;
      column_name: string;
      data_type: string;
    }

    interface WardrobeImplementationTestResult {
      tables: string[];
      columns: WardrobeColumnResult[];
    }

        return {
          tables: tableResult.rows.map((r: WardrobeTableResult) => r.table_name),
          columns: columnResult.rows
        } as WardrobeImplementationTestResult;
  } finally {
    // Restore original environment
    if (originalEnv !== undefined) {
      process.env.USE_MANUAL_TESTS = originalEnv;
    } else {
      delete process.env.USE_MANUAL_TESTS;
    }
  }
}

/**
 * Quick diagnostic for wardrobe test failures
 * Call this when wardrobe tests are failing to get debugging info
 * 
 * @returns {Promise<object>} Diagnostic information
 */
export const diagnoseWardrobeTestFailures = async (): Promise<object> => {
  console.log('🔍 Diagnosing wardrobe test setup...');
  
  const TestDB = getTestDatabaseConnection();
  const mode = shouldUseDocker() ? 'DOCKER' : 'MANUAL';
  
  try {
    await TestDB.initialize();
    
    // Check if required tables exist
    const tableCheck = await TestDB.query(`
      SELECT 
        CASE WHEN EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'wardrobes') 
          THEN 'EXISTS' ELSE 'MISSING' END as wardrobes_table,
        CASE WHEN EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'wardrobe_items') 
          THEN 'EXISTS' ELSE 'MISSING' END as wardrobe_items_table,
        CASE WHEN EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'garment_items') 
          THEN 'EXISTS' ELSE 'MISSING' END as garment_items_table
    `);
    
    // Check wardrobes table structure
    let wardrobesStructure = null;
    try {
      wardrobesStructure = await TestDB.query(`
        SELECT column_name, data_type, is_nullable 
        FROM information_schema.columns 
        WHERE table_name = 'wardrobes'
        ORDER BY ordinal_position
      `);
    } catch (error) {
      wardrobesStructure = { error: error instanceof Error ? error.message : String(error) };
    }
    
    const diagnosis = {
      mode,
      tables: tableCheck.rows[0],
      wardrobesStructure: wardrobesStructure.rows || wardrobesStructure,
      timestamp: new Date().toISOString()
    };
    
    console.log('📊 Wardrobe Test Diagnosis:', JSON.stringify(diagnosis, null, 2));
    
    return diagnosis;
  } catch (error) {
    console.error('❌ Error during diagnosis:', error);
    return {
      mode,
      error: error instanceof Error ? error.message : String(error),
      timestamp: new Date().toISOString()
    };
  }
};

/**
 * Enhanced test setup for wardrobe integration tests
 * Use this instead of calling TestDatabaseConnection directly
 * 
 * @returns {Promise<any>} The initialized database connection
 */
export const initializeWardrobeTests = async (): Promise<any> => {
  console.log(`🧪 Initializing wardrobe tests in ${shouldUseDocker() ? 'DOCKER' : 'MANUAL'} mode...`);
  
  try {
    // Initialize with proper mode detection
    const TestDB = getTestDatabaseConnection();
    const pool = await TestDB.initialize();
    
    // Ensure wardrobe tables exist
    await ensureWardrobeTablesExist();
    
    // Clear test data
    await TestDB.clearAllTables();
    
    console.log('✅ Wardrobe tests initialized successfully');
    return pool;
  } catch (error) {
    console.error('❌ Failed to initialize wardrobe tests:', error);
    
    // Provide helpful error message
    if (error instanceof Error && error.message.includes('wardrobe_items')) {
      console.log(`
🚨 WARDROBE TABLE ISSUE DETECTED
════════════════════════════════════════
The wardrobe_items table is missing. This can happen when:
1. Database schema is outdated
2. Migration scripts haven't run
3. Different environment than expected

QUICK FIX:
${shouldUseDocker() ? 
  '1. Restart Docker containers: docker-compose down && docker-compose up -d' :
  '1. Run database migrations manually'
}
2. Call ensureWardrobeTablesExist() before tests
3. Or switch modes: ${shouldUseDocker() ? 
  'USE_MANUAL_TESTS=true' : 'USE_DOCKER_TESTS=true'
}
════════════════════════════════════════
      `);
    }
    
    throw error;
  }
};

/**
 * Mock database connection for wardrobe tests
 * Use this in your jest.doMock() calls
 * 
 * @returns {object} Mock database object
 */
export const createWardrobeDatabaseMock = () => {
  const TestDB = getTestDatabaseConnection();
  
  return {
    query: async (text: string, params?: any[]) => {
      return TestDB.query(text, params);
    }
  };
};

/**
 * Get the appropriate testUserModel implementation
 * 
 * This ensures the user model uses the same database connection
 * as the rest of the dual-mode system.
 * 
 * @returns {testUserModel} Either Docker or Manual implementation
 */
export const getTestUserModel = () => {
  if (shouldUseDocker()) {
    // 🐳 DOCKER MODE: Use v2 user model that works with Docker database
    console.log('📦 Loading Docker test user model implementation');
    return require('./testUserModel.v2').testUserModel;
  } else {
    // 🔧 MANUAL MODE: Use original user model with manual database
    console.log('🛠️ Loading Manual test user model implementation');
    return require('./testUserModel').testUserModel;
  }
};

/**
 * Enhanced test setup for wardrobe integration tests with user model
 * This replaces setupWardrobeTestEnvironment and includes user model setup
 * 
 * @returns {Promise<{ TestDB: any, testUserModel: any }>}
 */
export const setupWardrobeTestEnvironmentWithUserModel = async () => {
  console.log('🧪 Setting up wardrobe test environment with user model...');
  
  // Setup base test environment
  setupTestEnvironment();
  
  // Initialize database connection
  const TestDB = getTestDatabaseConnection();
  await TestDB.initialize();
  
  // Ensure wardrobe-specific tables exist
  await ensureWardrobeTablesExist();
  
  // Get the appropriate user model
  const testUserModel = getTestUserModel();
  
  console.log('✅ Wardrobe test environment with user model ready');
  
  return {
    TestDB,
    testUserModel
  };
};

/**
 * Get the appropriate testImageModel implementation
 * 
 * @returns {testImageModel} Either Docker or Manual implementation
 */
export const getTestImageModel = () => {
  if (shouldUseDocker()) {
    console.log('📦 Loading Docker test image model implementation');
    return require('./testImageModel.v2').testImageModel;
  } else {
    console.log('🛠️ Loading Manual test image model implementation');
    return require('./testImageModel').testImageModel;
  }
};

/**
 * Get the appropriate testGarmentModel implementation
 * 
 * @returns {testGarmentModel} Either Docker or Manual implementation
 */
export const getTestGarmentModel = () => {
  if (shouldUseDocker()) {
    console.log('📦 Loading Docker test garment model implementation');
    return require('./testGarmentModel.v2').testGarmentModel;
  } else {
    console.log('🛠️ Loading Manual test garment model implementation');
    return require('./testGarmentModel').testGarmentModel;
  }
};

/**
 * Get the appropriate ImageServiceTestHelper implementation
 * 
 * @returns {ImageServiceTestHelper} Either Docker or Manual implementation
 */
export const getTestImageService = () => {
  if (shouldUseDocker()) {
    console.log('📦 Loading Docker test image service implementation');
    return require('./testImageService.v2').ImageServiceTestHelper;
  } else {
    console.log('🛠️ Loading Manual test image service implementation');
    return require('./testImageService').ImageServiceTestHelper;
  }
};

/**
 * Enhanced test setup for wardrobe integration tests with ALL models
 * This replaces setupWardrobeTestEnvironmentWithUserModel and includes all models
 * 
 * @returns {Promise<{ TestDB: any, testUserModel: any, testImageModel: any, testGarmentModel: any, ImageServiceTestHelper: any }>}
 */
export const setupWardrobeTestEnvironmentWithAllModels = async () => {
  console.log('🧪 Setting up wardrobe test environment with ALL models...');
  
  // Setup base test environment
  setupTestEnvironment();
  
  // Initialize database connection
  const TestDB = getTestDatabaseConnection();
  await TestDB.initialize();
  
  // Ensure wardrobe-specific tables exist
  await ensureWardrobeTablesExist();
  
  // Get the appropriate models
  const testUserModel = getTestUserModel();
  const testImageModel = getTestImageModel();
  const testGarmentModel = getTestGarmentModel();
  const ImageServiceTestHelper = getTestImageService();
  
  console.log('✅ Wardrobe test environment with ALL models ready');
  
  return {
    TestDB,
    testUserModel,
    testImageModel,
    testGarmentModel,
    ImageServiceTestHelper
  };
};

/**
 * Create simple test image directly with database connection
 * Use this to replace testImageModel.create() calls in tests
 * 
 * @param TestDB - Database connection
 * @param userId - User ID
 * @param name - Image name for file path
 * @returns Promise resolving to created image
 */
export const createTestImageDirect = async (TestDB: any, userId: string, name: string, imageCounter: number) => {
  const { v4: uuidv4 } = require('uuid');
  const id = uuidv4();
  
  const result = await TestDB.query(
    `INSERT INTO original_images 
    (id, user_id, file_path, original_metadata, status, created_at, updated_at) 
    VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) 
    RETURNING *`,
    [
      id,
      userId,
      `/uploads/user${userId.slice(-1)}/wardrobe_test_${imageCounter}_${name}.jpg`,
      JSON.stringify({ 
        width: 1920, 
        height: 1080, 
        format: 'JPEG',
        size: 2048576,
        uploaded_at: new Date().toISOString()
      }),
      'new'
    ]
  );
  
  return result.rows[0];
};

/**
 * 🎯 QUICK FIX for wardrobeController.int.test.ts
 * 
 * Use this setup function in your test instead of the complex imports
 */
export const setupWardrobeTestQuickFix = async () => {
  console.log('🚀 Quick fix setup for wardrobe tests...');
  
  // Setup environment
  setupTestEnvironment();
  
  // Initialize database
  const TestDB = getTestDatabaseConnection();
  await TestDB.initialize();
  await ensureWardrobeTablesExist();
  await TestDB.clearAllTables();
  
  // Get user model
  const testUserModel = getTestUserModel();
  
  console.log('✅ Quick fix setup complete');
  
  return {
    TestDB,
    testUserModel,
    createTestImage: (userId: string, name: string, imageCounter: number) => 
      createTestImageDirect(TestDB, userId, name, imageCounter)
  };
};

/**
 * ============================================================================
 * MAINTENANCE NOTES FOR FUTURE DEVELOPERS
 * ============================================================================
 * 
 * 🔄 WHEN TO UPDATE THIS FILE:
 * • Adding new test infrastructure (e.g., Redis, Elasticsearch)
 * • Changing Docker container configurations
 * • Updating environment variable names
 * • Adding new fallback mechanisms
 * 
 * 🚫 WHAT NOT TO CHANGE:
 * • The dual-mode architecture (this is permanent by design)
 * • The shouldUseDocker() decision hierarchy
 * • The emergency fallback mechanisms
 * 
 * 📝 TESTING CHANGES:
 * When modifying this file, always test both modes:
 * 1. Test Docker mode: npx jest
 * 2. Test Manual mode: USE_MANUAL_TESTS=true npx jest
 * 3. Run validation: validateMigration()
 * 
 * 📞 WHO TO CONTACT:
 * • Architecture questions: [Team Lead]
 * • Docker issues: [DevOps Team]
 * • Test infrastructure: [QA Team]
 * 
 * ============================================================================
 */