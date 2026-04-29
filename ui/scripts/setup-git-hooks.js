#!/usr/bin/env node

/**
 * Setup Git Hooks for Prowler UI
 *
 * This script checks if prek is managing git hooks.
 * If not, it runs the repository's setup script to install prek.
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

/**
 * Check if prek framework is managing git hooks
 */
function isPrekInstalled(gitRoot) {
  const hookPath = path.join(gitRoot, '.git', 'hooks', 'pre-commit');

  try {
    if (!fs.existsSync(hookPath)) return false;

    const content = fs.readFileSync(hookPath, 'utf8');
    return content.includes('prek') || content.includes('pre-commit') || content.includes('INSTALL_PYTHON');
  } catch {
    return false;
  }
}

/**
 * Get git repository root directory
 */
function getGitRoot() {
  try {
    return execSync('git rev-parse --show-toplevel', {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    }).trim();
  } catch {
    return null;
  }
}

/**
 * Run the repository setup script
 */
function runSetupScript(gitRoot) {
  const setupScript = path.join(gitRoot, 'scripts', 'setup-git-hooks.sh');

  if (!fs.existsSync(setupScript)) {
    throw new Error('Setup script not found');
  }

  execSync(`bash "${setupScript}"`, {
    cwd: gitRoot,
    stdio: 'inherit'
  });
}

// Main execution

// Skip in Docker/CI environments
if (process.env.DOCKER || process.env.CI || process.env.KUBERNETES_SERVICE_HOST) {
  console.log('⚠️  Running in containerized environment. Skipping git hooks setup.');
  process.exit(0);
}

const gitRoot = getGitRoot();

if (!gitRoot) {
  console.log('⚠️  Not in a git repository. Skipping git hooks setup.');
  process.exit(0);
}

if (isPrekInstalled(gitRoot)) {
  console.log('✅ Git hooks managed by prek framework');
  console.log('   UI hooks will be called automatically for UI files');
  process.exit(0);
}

// Prek not installed - set it up
console.log('⚠️  Prek hooks not installed');
console.log('📦 Installing prek hooks...');
console.log('');

try {
  runSetupScript(gitRoot);
  console.log('');
  console.log('✅ Prek hooks installed successfully');
} catch (error) {
  console.error('❌ Failed to setup git hooks');
  console.error('   Please run manually from repo root: ./scripts/setup-git-hooks.sh');
  console.error('   Or install prek manually: https://prek.j178.dev/installation/');
  process.exit(1);
}
