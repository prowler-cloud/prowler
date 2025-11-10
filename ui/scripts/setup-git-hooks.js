#!/usr/bin/env node

/**
 * Setup Git Hooks for Prowler UI
 *
 * This script configures Git to use Husky hooks located in ui/.husky
 * It runs automatically after npm install via the postinstall script.
 */

const { execSync } = require('child_process');
const path = require('path');

try {
  // Get the git root directory
  const gitRoot = execSync('git rev-parse --show-toplevel', {
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe']
  }).trim();

  // Check if we're in a git repository
  if (!gitRoot) {
    console.log('⚠️  Not in a git repository. Skipping git hooks setup.');
    process.exit(0);
  }

  // Get current hooks path
  let currentHooksPath;
  try {
    currentHooksPath = execSync('git config --get core.hooksPath', {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    }).trim();
  } catch {
    // core.hooksPath not set yet
    currentHooksPath = null;
  }

  const expectedHooksPath = 'ui/.husky';

  // Only configure if not already set correctly
  if (currentHooksPath !== expectedHooksPath) {
    execSync(`git config core.hooksPath "${expectedHooksPath}"`, {
      stdio: 'inherit'
    });
    console.log('✅ Git hooks configured: core.hooksPath = ui/.husky');
  } else {
    console.log('✅ Git hooks already configured correctly');
  }

} catch (error) {
  // Don't fail the installation if git hooks setup fails
  console.warn('⚠️  Could not setup git hooks:', error.message);
  console.warn('   You may need to run manually: git config core.hooksPath "ui/.husky"');
}
