#!/usr/bin/env node

/**
 * Helper script to run tests in a specific directory or matching a pattern
 * Usage:
 *   node scripts/run-tests.js [workspace] [pattern]
 * 
 * Examples:
 *   node scripts/run-tests.js backend controllers
 *   node scripts/run-tests.js frontend auth
 *   node scripts/run-tests.js shared garment
 */

const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

// Parse command-line arguments
const workspace = process.argv[2];
const pattern = process.argv[3] || '';

// Validate workspace
const validWorkspaces = ['backend', 'frontend', 'shared', 'all'];
if (!validWorkspaces.includes(workspace)) {
  console.error(`Error: Invalid workspace "${workspace}". Valid options are: ${validWorkspaces.join(', ')}`);
  process.exit(1);
}

// Build the test command
let command;

if (workspace === 'all') {
  // Run tests in all workspaces matching the pattern
  if (pattern) {
    command = `npm test -- --testPathPattern=${pattern}`;
  } else {
    command = 'npm test';
  }
} else {
  // Run tests in specific workspace
  const workspacePath = path.join(__dirname, '..', workspace);
  
  // Ensure workspace exists
  if (!fs.existsSync(workspacePath)) {
    console.error(`Error: Workspace directory "${workspacePath}" does not exist`);
    process.exit(1);
  }
  
  if (pattern) {
    command = `npm run test -w @koutu/${workspace} -- --testPathPattern=${pattern}`;
  } else {
    command = `npm run test -w @koutu/${workspace}`;
  }
}

console.log(`Running command: ${command}`);

try {
  // Execute the test command
  execSync(command, { stdio: 'inherit' });
} catch (error) {
  // The command itself will output errors, so we don't need to do anything special here
  process.exit(error.status);
}