#!/usr/bin/env node

/**
 * Post-install script for Prowler UI
 *
 * This script runs after npm install to:
 * 1. Update dependency log (if the script exists)
 * 2. Setup git hooks (if the script exists)
 */

const fs = require("fs");
const path = require("path");

function runScriptIfExists(scriptPath, scriptName) {
  const fullPath = path.join(__dirname, scriptPath);

  if (fs.existsSync(fullPath)) {
    try {
      require(fullPath);
    } catch (error) {
      console.warn(`⚠️  Error running ${scriptName}:`, error.message);
    }
  } else {
    console.log(`Skip ${scriptName} (script missing)`);
  }
}

// Run dependency log update
runScriptIfExists("./update-dependency-log.js", "deps:log");

// Run git hooks setup
runScriptIfExists("./setup-git-hooks.js", "setup-git-hooks");
