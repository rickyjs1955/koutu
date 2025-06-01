#!/usr/bin/env node
// verify-test-setup.js - Verify that the integration test environment is properly configured

import { existsSync, mkdirSync, readFileSync } from 'fs';
import { join } from 'path';

// ANSI color codes
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m'
};

const log = (message, color = 'reset') => {
  console.log(`${colors[color]}${message}${colors.reset}`);
};

const checkMark = '✅';
const crossMark = '❌';
const warningMark = '⚠️';

class SetupVerifier {
  constructor() {
    this.checks = [];
    this.errors = [];
    this.warnings = [];
  }

  addCheck(name, checkFn, critical = true) {
    this.checks.push({ name, checkFn, critical });
  }

  async runChecks() {
    log('🔍 Verifying Integration Test Setup...', 'bright');
    log('━'.repeat(60), 'cyan');

    for (const check of this.checks) {
      try {
        const result = await check.checkFn();
        if (result === true || (typeof result === 'object' && result.success)) {
          log(`${checkMark} ${check.name}`, 'green');
          if (typeof result === 'object' && result.details) {
            log(`   ${result.details}`, 'blue');
          }
        } else {
          this.handleCheckFailure(check, result);
        }
      } catch (error) {
        this.handleCheckFailure(check, error.message);
      }
    }

    this.printSummary();
  }

  handleCheckFailure(check, error) {
    const message = typeof error === 'string' ? error : error.message || 'Unknown error';
    
    if (check.critical) {
      log(`${crossMark} ${check.name}: ${message}`, 'red');
      this.errors.push({ name: check.name, message });
    } else {
      log(`${warningMark} ${check.name}: ${message}`, 'yellow');
      this.warnings.push({ name: check.name, message });
    }
  }

  printSummary() {
    log('\n━'.repeat(60), 'cyan');
    log('📊 Setup Verification Summary', 'bright');
    
    const totalChecks = this.checks.length;
    const passed = totalChecks - this.errors.length - this.warnings.length;
    
    log(`${checkMark} Passed: ${passed}/${totalChecks}`, 'green');
    
    if (this.warnings.length > 0) {
      log(`${warningMark} Warnings: ${this.warnings.length}`, 'yellow');
    }
    
    if (this.errors.length > 0) {
      log(`${crossMark} Critical Errors: ${this.errors.length}`, 'red');
    }

    if (this.errors.length === 0) {
      log('\n🎉 Setup verification completed successfully!', 'green');
      log('✨ You can now run the debug integration tests.', 'green');
      log('\n🚀 Next steps:', 'bright');
      log('1. Run: node run-debug-tests.js health', 'cyan');
      log('2. Run: node run-debug-tests.js progressive', 'cyan');
      log('3. If all tests pass, proceed with full integration tests', 'cyan');
    } else {
      log('\n🚨 Critical issues found! Please fix before proceeding:', 'red');
      this.errors.forEach(error => {
        log(`   • ${error.name}: ${error.message}`, 'red');
      });
    }

    if (this.warnings.length > 0) {
      log('\n⚠️  Warnings (non-critical):', 'yellow');
      this.warnings.forEach(warning => {
        log(`   • ${warning.name}: ${warning.message}`, 'yellow');
      });
    }
  }
}

// Setup all verification checks
const setupVerificationChecks = (verifier) => {
  // 1. Environment Variables
  verifier.addCheck('Environment Variables', () => {
    const required = ['NODE_ENV', 'JWT_SECRET'];
    const optional = ['TEST_DATABASE_URL', 'DATABASE_URL'];
    
    const missing = required.filter(key => !process.env[key]);
    if (missing.length > 0) {
      throw new Error(`Missing required: ${missing.join(', ')}`);
    }

    const hasTestDb = process.env.TEST_DATABASE_URL || process.env.DATABASE_URL;
    if (!hasTestDb) {
      throw new Error('No database URL configured');
    }

    return {
      success: true,
      details: `NODE_ENV=${process.env.NODE_ENV}, JWT_SECRET set, DB configured`
    };
  }, true);

  // 2. Required Dependencies
  verifier.addCheck('Node Dependencies', () => {
    const required = [
      'express', 'jest', 'supertest', 'jsonwebtoken', 
      'multer', 'sharp', 'dotenv'
    ];

    const missing = [];
    for (const dep of required) {
      try {
        require.resolve(dep);
      } catch (error) {
        missing.push(dep);
      }
    }

    if (missing.length > 0) {
      throw new Error(`Missing packages: ${missing.join(', ')}`);
    }

    return { success: true, details: `All ${required.length} dependencies available` };
  }, true);

  // 3. TypeScript Configuration
  verifier.addCheck('TypeScript Configuration', () => {
    const tsconfigPath = join(process.cwd(), 'tsconfig.json');
    if (!existsSync(tsconfigPath)) {
      throw new Error('tsconfig.json not found');
    }

    const jestConfigPath = join(process.cwd(), 'jest.config.js');
    if (!existsSync(jestConfigPath)) {
      return { success: true, details: 'tsconfig.json found (jest.config.js missing but not critical)' };
    }

    return { success: true, details: 'TypeScript and Jest configurations found' };
  }, true);

  // 4. Source Code Structure
  verifier.addCheck('Source Code Structure', () => {
    const requiredPaths = [
      'src/config/index.ts',
      'src/controllers/imageController.ts',
      'src/middlewares/auth.ts',
      'src/utils/ApiError.ts',
      'src/utils/sanitize.ts'
    ];

    const missing = requiredPaths.filter(path => !existsSync(path));
    if (missing.length > 0) {
      throw new Error(`Missing files: ${missing.join(', ')}`);
    }

    return { success: true, details: `All ${requiredPaths.length} core files found` };
  }, true);

  // 5. Test Utilities
  verifier.addCheck('Test Utilities', () => {
    const testUtils = [
      'src/utils/testDatabaseConnection.ts',
      'src/utils/testUserModel.ts',
      'src/utils/testImageModel.ts'
    ];

    const missing = testUtils.filter(path => !existsSync(path));
    if (missing.length > 0) {
      throw new Error(`Missing test utilities: ${missing.join(', ')}`);
    }

    return { success: true, details: 'All test utilities found' };
  }, true);

  // 6. Test Directory Structure
  verifier.addCheck('Test Directory Structure', () => {
    const testDir = 'src/tests/integration/controllers';
    if (!existsSync(testDir)) {
      mkdirSync(testDir, { recursive: true });
      return { success: true, details: 'Test directory created' };
    }

    return { success: true, details: 'Test directory exists' };
  }, false);

  // 7. Middleware Dependencies
  verifier.addCheck('Middleware Dependencies', () => {
    const middlewares = [
      'src/middlewares/errorHandler.ts',
      'src/middlewares/validate.ts'
    ];

    const missing = middlewares.filter(path => !existsSync(path));
    if (missing.length > 0) {
      return `Missing middleware: ${missing.join(', ')} (tests may need mocking)`;
    }

    return { success: true, details: 'All middleware files found' };
  }, false);

  // 8. Service Layer
  verifier.addCheck('Service Layer', () => {
    const services = [
      'src/services/imageService.ts',
      'src/services/imageProcessingService.ts',
      'src/services/storageService.ts'
    ];

    const existing = services.filter(path => existsSync(path));
    if (existing.length === 0) {
      throw new Error('No service files found - imageController may fail');
    }

    const missing = services.filter(path => !existsSync(path));
    if (missing.length > 0) {
      return `Missing services: ${missing.join(', ')} (may need mocking)`;
    }

    return { success: true, details: 'All service files found' };
  }, true);

  // 9. Model Layer
  verifier.addCheck('Model Layer', () => {
    const models = [
      'src/models/imageModel.ts',
      'src/models/userModel.ts'
    ];

    const missing = models.filter(path => !existsSync(path));
    if (missing.length > 0) {
      throw new Error(`Missing models: ${missing.join(', ')}`);
    }

    return { success: true, details: 'All model files found' };
  }, true);

  // 10. Package.json Scripts
  verifier.addCheck('Package.json Scripts', () => {
    const packagePath = join(process.cwd(), 'package.json');
    if (!existsSync(packagePath)) {
      throw new Error('package.json not found');
    }

    const packageData = JSON.parse(readFileSync(packagePath, 'utf8'));
    const scripts = packageData.scripts || {};

    const hasTestScript = scripts.test || scripts['test:integration'];
    if (!hasTestScript) {
      return 'No test scripts defined in package.json';
    }

    return { success: true, details: 'Test scripts available' };
  }, false);
};

// Main execution
const main = async () => {
  log('🔧 Integration Test Setup Verifier', 'bright');
  log(`📁 Working Directory: ${process.cwd()}`, 'blue');
  log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`, 'blue');
  log('');

  const verifier = new SetupVerifier();
  setupVerificationChecks(verifier);
  
  await verifier.runChecks();

  // Exit with appropriate code
  process.exit(verifier.errors.length > 0 ? 1 : 0);
};

// Error handling
process.on('uncaughtException', (error) => {
  log(`💥 Uncaught Exception: ${error.message}`, 'red');
  console.error(error.stack);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  log(`💥 Unhandled Rejection at: ${promise}`, 'red');
  log(`Reason: ${reason}`, 'red');
  process.exit(1);
});

// Run verification
if (require.main === module) {
  main();
}

export default { SetupVerifier, setupVerificationChecks };