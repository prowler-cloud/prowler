import { defineConfig, devices } from "@playwright/test";

import { getBaseConfig } from "./playwright.base";

const registryFixtureApiUrl = "http://127.0.0.1:4300/api/v1";
const registryFixtureServer = {
  command:
    "node --experimental-strip-types tests/registry/controlled-registry-api.mts",
  reuseExistingServer: false,
  timeout: 120 * 1000,
  url: "http://127.0.0.1:4300/health",
};

const registryFixtureUiServer = (
  port: number,
  cloudEnabled: boolean,
  registryEnabled: boolean,
) => ({
  command: `pnpm exec next start --port ${port}`,
  env: {
    AUTH_SECRET: "fixture-next-auth-secret-not-a-secret",
    AUTH_TRUST_HOST: "true",
    AUTH_URL: `http://127.0.0.1:${port}`,
    NEXTAUTH_URL: `http://127.0.0.1:${port}`,
    UI_API_BASE_URL: registryFixtureApiUrl,
    UI_CLOUD_ENABLED: String(cloudEnabled),
    UI_REGISTRY_ENABLED: String(registryEnabled),
    UI_REGISTRY_URL: "https://registry.dev.prowler.com",
    UI_REGISTRY_MEDIA_URL: "https://media.registry.dev.prowler.com",
    CLOUD_BILLING_ENABLED: "false",
  },
  reuseExistingServer: false,
  timeout: 120 * 1000,
  url: `http://127.0.0.1:${port}`,
});

export default defineConfig({
  ...getBaseConfig(),
  workers: 1,
  projects: [
    // Registry manager authentication setup
    // Creates authenticated state for a user with current MANAGE_REGISTRY access
    {
      name: "manage-registry.auth.setup",
      use: { baseURL: "http://127.0.0.1:4301" },
      testMatch: "manage-registry.auth.setup.ts",
    },

    // Registry acceptance uses only the self-contained test fixture profile.
    {
      name: "registry",
      use: {
        ...devices["Desktop Chrome"],
        baseURL: "http://127.0.0.1:4301",
      },
      testMatch: /registry\/.*\.spec\.ts/,
      dependencies: ["manage-registry.auth.setup"],
    },
    {
      name: "registry-flag-off",
      use: {
        ...devices["Desktop Chrome"],
        baseURL: "http://127.0.0.1:4302",
      },
      testMatch: /registry\/.*\.spec\.ts/,
      dependencies: ["manage-registry.auth.setup"],
    },
    {
      name: "registry-local",
      use: {
        ...devices["Desktop Chrome"],
        baseURL: "http://127.0.0.1:4303",
      },
      testMatch: /registry\/.*\.spec\.ts/,
      dependencies: ["manage-registry.auth.setup"],
    },
    {
      name: "registry-mobile",
      use: {
        ...devices["Pixel 5"],
        baseURL: "http://127.0.0.1:4301",
      },
      testMatch: /registry\/.*\.spec\.ts/,
      dependencies: ["manage-registry.auth.setup"],
    },
  ],
  webServer: [
    registryFixtureServer,
    registryFixtureUiServer(4301, true, true),
    registryFixtureUiServer(4302, true, false),
    registryFixtureUiServer(4303, false, true),
  ],
});
