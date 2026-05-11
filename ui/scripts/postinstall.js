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

function hardenMswServiceWorker() {
  const workerPath = path.join(
    __dirname,
    "..",
    "public",
    "mockServiceWorker.js",
  );

  if (!fs.existsSync(workerPath)) {
    console.log("Skip MSW service worker hardening (worker missing)");
    return;
  }

  const workerSource = fs.readFileSync(workerPath, "utf8");
  const originGuard = "event.origin !== self.location.origin";

  if (workerSource.includes(originGuard)) {
    return;
  }

  const messageHandlerStart =
    "addEventListener('message', async function (event) {\n  const clientId = Reflect.get(event.source || {}, 'id')\n";
  const hardenedMessageHandlerStart =
    "addEventListener('message', async function (event) {\n" +
    "  // Only accept messages from pages served from the same origin as this worker.\n" +
    "  if (event.origin !== self.location.origin) {\n" +
    "    return\n" +
    "  }\n\n" +
    "  const clientId = Reflect.get(event.source || {}, 'id')\n";

  if (!workerSource.includes(messageHandlerStart)) {
    console.warn(
      "⚠️  Unable to harden MSW service worker: message handler changed",
    );
    return;
  }

  const workerStats = fs.statSync(workerPath);
  const hardenedWorkerSource = workerSource.replace(
    messageHandlerStart,
    hardenedMessageHandlerStart,
  );

  if (fs.statSync(workerPath).mtimeMs !== workerStats.mtimeMs) {
    throw new Error("MSW service worker changed while applying hardening");
  }

  fs.writeFileSync(workerPath, hardenedWorkerSource);
  console.log("Hardened MSW service worker message origin handling");
}

// Run dependency log update
runScriptIfExists("./update-dependency-log.js", "deps:log");

// Re-apply local hardening after MSW regenerates the worker during install.
// Keep this before setup-git-hooks because that script can exit the process.
hardenMswServiceWorker();

// Run git hooks setup
runScriptIfExists("./setup-git-hooks.js", "setup-git-hooks");
