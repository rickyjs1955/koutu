#!/usr/bin/env node

/**
 * Flutter Controller Migration Script
 * 
 * This script helps migrate existing controllers to use the new Flutter-friendly
 * response format by analyzing current patterns and suggesting replacements.
 */

const fs = require('fs');
const path = require('path');

// Controllers to migrate (in priority order)
const CONTROLLERS = [
  'authController.ts',
  'imageController.ts', 
  'garmentController.ts',
  'wardrobeController.ts',
  'exportController.ts',
  'oauthController.ts',
  'polygonController.ts'
];

// Path to controllers directory
const CONTROLLERS_DIR = path.join(__dirname, '../src/controllers');

// Migration patterns
const MIGRATION_PATTERNS = {
  // Import updates
  imports: {
    old: [
      "import { ApiError } from '../utils/ApiError';",
      "return next(ApiError.",
      "next(ApiError."
    ],
    new: [
      "import { EnhancedApiError } from '../middlewares/errorHandler';",
      "throw EnhancedApiError.",
      "throw EnhancedApiError."
    ]
  },
  
  // Response pattern updates
  responses: {
    // Success responses
    success200: {
      pattern: /res\.status\(200\)\.json\(\s*{\s*status:\s*['"]success['"],?\s*data:\s*(.+?),?\s*(?:message:\s*(.+?))?\s*}\s*\)/g,
      replacement: 'res.success($1, { message: $2 })'
    },
    
    // Created responses  
    success201: {
      pattern: /res\.status\(201\)\.json\(\s*{\s*status:\s*['"]success['"],?\s*data:\s*(.+?),?\s*(?:message:\s*(.+?))?\s*}\s*\)/g,
      replacement: 'res.created($1, { message: $2 })'
    },
    
    // Error responses
    errorResponse: {
      pattern: /res\.status\((\d+)\)\.json\(\s*{\s*status:\s*['"]error['"],?\s*message:\s*(.+?),?\s*(?:code:\s*(.+?))?\s*}\s*\)/g,
      replacement: 'throw EnhancedApiError.create($2, $1, $3)'
    }
  },

  // Error throwing patterns
  errors: {
    badRequest: {
      pattern: /next\(ApiError\.badRequest\((.+?)(?:,\s*(.+?))?\)\)/g,
      replacement: 'throw EnhancedApiError.validation($1, $2)'
    },
    
    unauthorized: {
      pattern: /next\(ApiError\.unauthorized\((.+?)\)\)/g,
      replacement: 'throw EnhancedApiError.authenticationRequired($1)'
    },
    
    forbidden: {
      pattern: /next\(ApiError\.forbidden\((.+?)\)\)/g,
      replacement: 'throw EnhancedApiError.authorizationDenied($1)'
    },
    
    notFound: {
      pattern: /next\(ApiError\.notFound\((.+?)\)\)/g,
      replacement: 'throw EnhancedApiError.notFound($1)'
    },
    
    conflict: {
      pattern: /next\(ApiError\.conflict\((.+?)\)\)/g,
      replacement: 'throw EnhancedApiError.conflict($1)'
    },
    
    internal: {
      pattern: /next\(ApiError\.internal\((.+?)\)\)/g,
      replacement: 'throw EnhancedApiError.internalError($1)'
    }
  }
};

/**
 * Analyze a controller file and suggest migrations
 */
function analyzeController(filePath) {
  if (!fs.existsSync(filePath)) {
    console.log(`❌ File not found: ${filePath}`);
    return null;
  }

  const content = fs.readFileSync(filePath, 'utf8');
  const analysis = {
    file: path.basename(filePath),
    patterns: {
      oldApiError: (content.match(/ApiError\./g) || []).length,
      oldResponses: (content.match(/res\.status\(\d+\)\.json/g) || []).length,
      nextCalls: (content.match(/next\(ApiError/g) || []).length,
      successPatterns: (content.match(/status:\s*['"]success['"]/g) || []).length,
      errorPatterns: (content.match(/status:\s*['"]error['"]/g) || []).length
    },
    suggestions: []
  };

  // Analyze patterns and suggest improvements
  if (analysis.patterns.oldApiError > 0) {
    analysis.suggestions.push(`Replace ${analysis.patterns.oldApiError} ApiError usages with EnhancedApiError`);
  }

  if (analysis.patterns.oldResponses > 0) {
    analysis.suggestions.push(`Modernize ${analysis.patterns.oldResponses} response patterns to use ResponseWrapper methods`);
  }

  if (analysis.patterns.nextCalls > 0) {
    analysis.suggestions.push(`Convert ${analysis.patterns.nextCalls} next(ApiError...) calls to throw statements`);
  }

  return analysis;
}

/**
 * Generate migration suggestions for a controller
 */
function generateMigrationSuggestions(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const suggestions = [];

  // Check for import updates needed
  if (content.includes("import { ApiError }")) {
    suggestions.push({
      type: 'import',
      description: 'Update imports to use EnhancedApiError',
      old: "import { ApiError } from '../utils/ApiError';",
      new: "import { EnhancedApiError } from '../middlewares/errorHandler';"
    });
  }

  // Find specific patterns that need updating
  const responseMatches = content.match(/res\.status\(\d+\)\.json\([^)]+\)/g);
  if (responseMatches) {
    responseMatches.forEach(match => {
      suggestions.push({
        type: 'response',
        description: 'Update response format',
        old: match,
        new: 'Use res.success(), res.created(), etc.'
      });
    });
  }

  const errorMatches = content.match(/next\(ApiError\.[^)]+\)/g);
  if (errorMatches) {
    errorMatches.forEach(match => {
      suggestions.push({
        type: 'error',
        description: 'Convert to throw statement',
        old: match,
        new: match.replace('next(ApiError.', 'throw EnhancedApiError.').replace(/\)$/, '')
      });
    });
  }

  return suggestions;
}

/**
 * Create a backup of the original file
 */
function createBackup(filePath) {
  const backupPath = filePath.replace('.ts', '.backup.ts');
  fs.copyFileSync(filePath, backupPath);
  console.log(`📋 Created backup: ${backupPath}`);
}

/**
 * Apply automatic migrations where safe
 */
function applyAutomaticMigrations(filePath) {
  console.log(`🔧 Applying automatic migrations to ${path.basename(filePath)}...`);
  
  let content = fs.readFileSync(filePath, 'utf8');
  let changes = 0;

  // Update imports
  if (content.includes("import { ApiError }")) {
    content = content.replace(
      "import { ApiError } from '../utils/ApiError';",
      "import { EnhancedApiError } from '../middlewares/errorHandler';"
    );
    changes++;
  }

  // Apply error pattern replacements
  Object.entries(MIGRATION_PATTERNS.errors).forEach(([errorType, pattern]) => {
    const matches = content.match(pattern.pattern);
    if (matches) {
      content = content.replace(pattern.pattern, pattern.replacement);
      changes += matches.length;
    }
  });

  if (changes > 0) {
    fs.writeFileSync(filePath, content);
    console.log(`✅ Applied ${changes} automatic changes to ${path.basename(filePath)}`);
  } else {
    console.log(`ℹ️ No automatic changes needed for ${path.basename(filePath)}`);
  }

  return changes;
}

/**
 * Main migration function
 */
function migrateController(controllerName, options = {}) {
  const filePath = path.join(CONTROLLERS_DIR, controllerName);
  
  console.log(`\n🔍 Analyzing ${controllerName}...`);
  
  const analysis = analyzeController(filePath);
  if (!analysis) {
    return;
  }

  // Show analysis results
  console.log(`📊 Analysis Results for ${analysis.file}:`);
  console.log(`   - Old ApiError usages: ${analysis.patterns.oldApiError}`);
  console.log(`   - Old response patterns: ${analysis.patterns.oldResponses}`);
  console.log(`   - Next calls: ${analysis.patterns.nextCalls}`);
  console.log(`   - Success patterns: ${analysis.patterns.successPatterns}`);
  console.log(`   - Error patterns: ${analysis.patterns.errorPatterns}`);

  if (analysis.suggestions.length > 0) {
    console.log(`💡 Suggestions:`);
    analysis.suggestions.forEach(suggestion => {
      console.log(`   - ${suggestion}`);
    });
  }

  // Generate detailed migration suggestions
  const suggestions = generateMigrationSuggestions(filePath);
  
  if (suggestions.length > 0) {
    console.log(`\n🔧 Migration Suggestions for ${controllerName}:`);
    suggestions.forEach((suggestion, index) => {
      console.log(`\n${index + 1}. ${suggestion.description} (${suggestion.type})`);
      console.log(`   Old: ${suggestion.old}`);
      console.log(`   New: ${suggestion.new}`);
    });
  }

  // Apply automatic migrations if requested
  if (options.autoMigrate) {
    createBackup(filePath);
    applyAutomaticMigrations(filePath);
  }

  return analysis;
}

/**
 * Generate migration report
 */
function generateMigrationReport() {
  console.log('📋 Flutter Controller Migration Report');
  console.log('=====================================\n');
  
  const results = [];
  
  CONTROLLERS.forEach(controller => {
    const result = migrateController(controller);
    if (result) {
      results.push(result);
    }
  });

  // Summary
  console.log('\n📈 Migration Summary:');
  console.log('====================');
  
  const totalFiles = results.length;
  const totalIssues = results.reduce((sum, result) => 
    sum + result.patterns.oldApiError + result.patterns.oldResponses + result.patterns.nextCalls, 0
  );
  
  console.log(`Total controllers analyzed: ${totalFiles}`);
  console.log(`Total migration points found: ${totalIssues}`);
  
  // Priority ranking
  const priorityList = results
    .map(result => ({
      file: result.file,
      priority: result.patterns.oldApiError + result.patterns.oldResponses + result.patterns.nextCalls,
      issues: result.patterns
    }))
    .sort((a, b) => b.priority - a.priority);

  console.log('\n🎯 Migration Priority (highest first):');
  priorityList.forEach((item, index) => {
    console.log(`${index + 1}. ${item.file} (${item.priority} changes needed)`);
  });

  return results;
}

// CLI Interface
const args = process.argv.slice(2);
const command = args[0];

switch (command) {
  case 'analyze':
    const controller = args[1];
    if (controller) {
      migrateController(controller);
    } else {
      generateMigrationReport();
    }
    break;
    
  case 'migrate':
    const targetController = args[1];
    if (targetController) {
      migrateController(targetController, { autoMigrate: true });
    } else {
      console.log('❌ Please specify a controller to migrate');
      console.log('Usage: node migrate-controllers.js migrate authController.ts');
    }
    break;
    
  case 'report':
    generateMigrationReport();
    break;
    
  default:
    console.log('Flutter Controller Migration Tool');
    console.log('=================================');
    console.log('');
    console.log('Commands:');
    console.log('  analyze [controller]  - Analyze controller(s) for migration needs');
    console.log('  migrate <controller>  - Apply automatic migrations to a controller');
    console.log('  report               - Generate full migration report');
    console.log('');
    console.log('Examples:');
    console.log('  node migrate-controllers.js analyze');
    console.log('  node migrate-controllers.js analyze authController.ts');
    console.log('  node migrate-controllers.js migrate authController.ts');
    console.log('  node migrate-controllers.js report');
    break;
}

// Export for programmatic usage
module.exports = {
  migrateController,
  generateMigrationReport,
  analyzeController,
  CONTROLLERS,
  MIGRATION_PATTERNS
};