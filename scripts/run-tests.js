#!/usr/bin/env node

const { spawn } = require('child_process');
const path = require('path');

// Get the test path from command line arguments
const testPath = process.argv[2];

if (!testPath) {
  console.error('Please provide a test path as an argument');
  process.exit(1);
}

// Determine which workspace to run tests in
let workspace;
if (testPath.includes('backend/')) {
  workspace = 'backend';
} else if (testPath.includes('frontend/')) {
  workspace = 'frontend';
} else if (testPath.includes('shared/')) {
  workspace = 'shared';
} else {
  console.error('Could not determine workspace from test path');
  process.exit(1);
}

// Run the test
const child = spawn('npm', ['run', `test:${workspace}`, '--', testPath], {
  cwd: path.resolve(__dirname, '..'),
  stdio: 'inherit',
  shell: true
});

child.on('exit', (code) => {
  process.exit(code);
});