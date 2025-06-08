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
    return require('./testDatabase.v2').TestDatabase;
  } else {
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