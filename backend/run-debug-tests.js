#!/usr/bin/env node
// run-debug-tests.js - Progressive test runner for debugging integration issues

import { execSync } from 'child_process';
import { join } from 'path';

// ANSI color codes for better output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

const log = (message, color = 'reset') => {
  console.log(`${colors[color]}${message}${colors.reset}`);
};

const runTest = (testPattern, description, options = {}) => {
  log(`\n${'='.repeat(60)}`, 'cyan');
  log(`🧪 Running: ${description}`, 'bright');
  log(`Pattern: ${testPattern}`, 'blue');
  log(`${'='.repeat(60)}`, 'cyan');
  
  try {
    const cmd = `npx jest "${testPattern}" ${options.args || ''}`;
    log(`Executing: ${cmd}`, 'yellow');
    
    const result = execSync(cmd, { 
      cwd: process.cwd(),
      stdio: 'inherit',
      timeout: options.timeout || 30000
    });
    
    log(`✅ ${description} - PASSED`, 'green');
    return true;
  } catch (error) {
    log(`❌ ${description} - FAILED`, 'red');
    if (options.showError && error.stdout) {
      log('Error output:', 'red');
      console.log(error.stdout.toString());
    }
    return false;
  }
};

const testSuites = [
  {
    pattern: 'debug.int.test.ts -t "Basic Server Setup"',
    description: 'Basic Server Setup',
    critical: true
  },
  {
    pattern: 'debug.int.test.ts -t "Database Connection"',
    description: 'Database Connection',
    critical: true
  },
  {
    pattern: 'debug.int.test.ts -t "Authentication Middleware"',
    description: 'Authentication Middleware',
    critical: true
  },
  {
    pattern: 'debug.int.test.ts -t "Image Controller Basic Functionality"',
    description: 'Image Controller Basic Functionality',
    critical: false
  },
  {
    pattern: 'debug.int.test.ts -t "Error Handling"',
    description: 'Error Handling',
    critical: false
  },
  {
    pattern: 'debug.int.test.ts -t "Database Model Operations"',
    description: 'Database Model Operations',
    critical: false
  },
  {
    pattern: 'debug.int.test.ts -t "JWT Token Validation"',
    description: 'JWT Token Validation',
    critical: false
  },
  {
    pattern: 'debug.int.test.ts -t "Configuration and Environment"',
    description: 'Configuration and Environment',
    critical: false
  },
  {
    pattern: 'debug.int.test.ts -t "Memory and Resource Management"',
    description: 'Memory and Resource Management',
    critical: false
  },
  {
    pattern: 'debug.int.test.ts -t "Response Format Consistency"',
    description: 'Response Format Consistency',
    critical: false
  }
];

const main = async () => {
  const args = process.argv.slice(2);
  const mode = args[0] || 'progressive';
  
  log('🚀 Debug Integration Test Runner', 'bright');
  log(`Mode: ${mode}`, 'cyan');
  
  switch (mode) {
    case 'progressive':
      await runProgressiveTests();
      break;
    case 'all':
      await runAllTests();
      break;
    case 'critical':
      await runCriticalTests();
      break;
    case 'single':
      await runSingleTest(args[1]);
      break;
    case 'health':
      await runHealthCheck();
      break;
    default:
      showUsage();
  }
};

const runProgressiveTests = async () => {
  log('\n🔄 Running Progressive Tests (stop on first failure)', 'yellow');
  
  let passed = 0;
  let failed = 0;
  
  for (const suite of testSuites) {
    const success = runTest(suite.pattern, suite.description, { 
      timeout: 15000,
      args: '--verbose --no-cache'
    });
    
    if (success) {
      passed++;
      log(`✅ Progress: ${passed}/${testSuites.length} suites passed`, 'green');
    } else {
      failed++;
      log(`❌ STOPPING: Failed at "${suite.description}"`, 'red');
      
      if (suite.critical) {
        log('💥 This is a critical test suite. Fix this before proceeding.', 'red');
      } else {
        log('⚠️  Non-critical failure. You may continue debugging.', 'yellow');
      }
      
      log('\n🔧 Debugging suggestions:', 'cyan');
      log('1. Check the error output above', 'white');
      log('2. Verify database connection and test data setup', 'white');
      log('3. Check if all required environment variables are set', 'white');
      log('4. Ensure all dependencies are installed', 'white');
      log('5. Run health check: node run-debug-tests.js health', 'white');
      
      break;
    }
    
    // Small delay between tests
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  
  log(`\n📊 Final Results: ${passed} passed, ${failed} failed`, failed > 0 ? 'red' : 'green');
};

const runAllTests = () => {
  log('\n🌟 Running All Debug Tests', 'yellow');
  return runTest('debug.int.test.ts', 'All Debug Tests', { 
    timeout: 60000,
    args: '--verbose --forceExit'
  });
};

const runCriticalTests = async () => {
  log('\n🎯 Running Critical Tests Only', 'yellow');
  
  const criticalSuites = testSuites.filter(suite => suite.critical);
  let allPassed = true;
  
  for (const suite of criticalSuites) {
    const success = runTest(suite.pattern, `[CRITICAL] ${suite.description}`, {
      timeout: 15000,
      args: '--verbose'
    });
    
    if (!success) {
      allPassed = false;
    }
  }
  
  if (allPassed) {
    log('\n✅ All critical tests passed! You can proceed with integration tests.', 'green');
  } else {
    log('\n❌ Critical test failures detected. Please fix before proceeding.', 'red');
  }
};

const runSingleTest = (testName) => {
  if (!testName) {
    log('❌ Please specify a test name', 'red');
    showUsage();
    return;
  }
  
  log(`\n🎯 Running Single Test: ${testName}`, 'yellow');
  return runTest(`debug.int.test.ts -t "${testName}"`, `Single Test: ${testName}`, {
    timeout: 30000,
    args: '--verbose'
  });
};

const runHealthCheck = () => {
  log('\n🏥 Running Health Check', 'yellow');
  
  const healthChecks = [
    {
      name: 'Environment Variables',
      check: () => {
        const required = ['NODE_ENV', 'JWT_SECRET', 'TEST_DATABASE_URL'];
        const missing = required.filter(key => !process.env[key]);
        if (missing.length > 0) {
          throw new Error(`Missing: ${missing.join(', ')}`);
        }
        return 'All required environment variables are set';
      }
    },
    {
      name: 'Node Modules',
      check: () => {
        try {
          require('express');
          require('jest');
          require('supertest');
          return 'All required dependencies are available';
        } catch (error) {
          throw new Error(`Missing dependency: ${error.message}`);
        }
      }
    },
    {
      name: 'Test Files',
      check: () => {
        const fs = require('fs');
        const testFile = join(process.cwd(), 'src/tests/integration/controllers/debug.int.test.ts');
        if (!fs.existsSync(testFile)) {
          throw new Error('debug.int.test.ts not found');
        }
        return 'Test files are present';
      }
    }
  ];
  
  let allHealthy = true;
  
  for (const check of healthChecks) {
    try {
      const result = check.check();
      log(`✅ ${check.name}: ${result}`, 'green');
    } catch (error) {
      log(`❌ ${check.name}: ${error.message}`, 'red');
      allHealthy = false;
    }
  }
  
  if (allHealthy) {
    log('\n🎉 System is healthy! Ready for testing.', 'green');
  } else {
    log('\n🚨 Health check failed. Please fix the issues above.', 'red');
  }
  
  return allHealthy;
};

const showUsage = () => {
  log('\n📖 Usage:', 'bright');
  log('  node run-debug-tests.js [mode] [options]', 'white');
  log('\n🔧 Modes:', 'bright');
  log('  progressive  - Run tests one by one, stop on first failure (default)', 'white');
  log('  all         - Run all tests at once', 'white');
  log('  critical    - Run only critical tests', 'white');
  log('  single      - Run a single test by name', 'white');
  log('  health      - Run system health check', 'white');
  log('\n📝 Examples:', 'bright');
  log('  node run-debug-tests.js', 'cyan');
  log('  node run-debug-tests.js progressive', 'cyan');
  log('  node run-debug-tests.js critical', 'cyan');
  log('  node run-debug-tests.js single "Basic Server Setup"', 'cyan');
  log('  node run-debug-tests.js health', 'cyan');
};

// Error handling
process.on('uncaughtException', (error) => {
  log(`💥 Uncaught Exception: ${error.message}`, 'red');
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  log(`💥 Unhandled Rejection: ${reason}`, 'red');
  process.exit(1);
});

// Run the main function
main().catch(error => {
  log(`💥 Fatal Error: ${error.message}`, 'red');
  process.exit(1);
});