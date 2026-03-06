import { defineConfig, devices } from "@playwright/test";
import fs from "fs";
import path from "path";

const localEnvPath = path.resolve(__dirname, ".env.local");
if (fs.existsSync(localEnvPath)) {
  process.loadEnvFile(localEnvPath);
}

export default defineConfig({
  testDir: "./tests",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [["list"]],
  outputDir: "/tmp/playwright-tests",
  expect: {
    timeout: 20000,
  },

  use: {
    baseURL: process.env.AUTH_URL
      ? process.env.AUTH_URL
      : "http://localhost:3000",
    trace: "off",
    screenshot: "off",
    video: "off",
  },

  projects: [
    // ===========================================
    // Authentication Setup Projects
    // ===========================================
    // These projects handle user authentication for different permission levels
    // Each setup creates authenticated state files that can be reused by test suites

    // Admin user authentication setup
    // Creates authenticated state for admin users with full system permissions
    {
      name: "admin.auth.setup",
      testMatch: "admin.auth.setup.ts",
    },

    // Scans management user authentication setup
    // Creates authenticated state for users with scan management permissions
    {
      name: "manage-scans.auth.setup",
      testMatch: "manage-scans.auth.setup.ts",
    },

    // Integrations management user authentication setup
    // Creates authenticated state for users with integration management permissions
    {
      name: "manage-integrations.auth.setup",
      testMatch: "manage-integrations.auth.setup.ts",
    },

    // Account management user authentication setup
    // Creates authenticated state for users with account management permissions
    {
      name: "manage-account.auth.setup",
      testMatch: "manage-account.auth.setup.ts",
    },

    // Cloud providers management user authentication setup
    // Creates authenticated state for users with cloud provider management permissions
    {
      name: "manage-cloud-providers.auth.setup",
      testMatch: "manage-cloud-providers.auth.setup.ts",
    },

    // Unlimited visibility user authentication setup
    // Creates authenticated state for users with unlimited visibility permissions
    {
      name: "unlimited-visibility.auth.setup",
      testMatch: "unlimited-visibility.auth.setup.ts",
    },

    // Invite and manage users authentication setup
    // Creates authenticated state for users with user invitation and management permissions
    {
      name: "invite-and-manage-users.auth.setup",
      testMatch: "invite-and-manage-users.auth.setup.ts",
    },

    // All authentication setups combined
    // Runs all authentication setup files to create all user states
    {
      name: "all.auth.setup",
      testMatch: "**/*.auth.setup.ts",
    },

    // ===========================================
    // Test Suite Projects
    // ===========================================
    // These projects run the actual test suites

    // This project runs the sign-in-base test suite (form, navigation, accessibility)
    {
      name: "sign-in-base",
      use: { ...devices["Desktop Chrome"] },
      testMatch: /sign-in-base\/.*\.spec\.ts/,
    },
    // This project runs the auth test suite (middleware, session, token refresh)
    {
      name: "auth",
      use: { ...devices["Desktop Chrome"] },
      testMatch: /auth\/.*\.spec\.ts/,
    },
    // This project runs the sign-up test suite
    {
      name: "sign-up",
      testMatch: "sign-up.spec.ts",
    },
    // This project runs the scans test suite
    {
      name: "scans",
      testMatch: "scans.spec.ts",
      dependencies: ["admin.auth.setup"],
    },
    // This project runs the providers test suite
    {
      name: "providers",
      testMatch: "providers.spec.ts",
      dependencies: ["admin.auth.setup"],
    },
    // This project runs the invitations test suite
    {
      name: "invitations",
      testMatch: "invitations.spec.ts",
      dependencies: ["admin.auth.setup"],
    },
  ],

  webServer: {
    command: process.env.CI ? "pnpm run start" : "pnpm run dev",
    url: "http://localhost:3000",
    reuseExistingServer: !process.env.CI,
    timeout: 120 * 1000,
    env: {
      NEXT_PUBLIC_API_BASE_URL:
        process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8080/api/v1",
      AUTH_SECRET: process.env.AUTH_SECRET || "fallback-ci-secret-for-testing",
      AUTH_TRUST_HOST: process.env.AUTH_TRUST_HOST || "true",
      NEXTAUTH_URL: process.env.NEXTAUTH_URL || "http://localhost:3000",
      E2E_ADMIN_USER: process.env.E2E_ADMIN_USER || "e2e@prowler.com",
      E2E_ADMIN_PASSWORD:
        process.env.E2E_ADMIN_PASSWORD || "Thisisapassword123@",
    },
  },
});
