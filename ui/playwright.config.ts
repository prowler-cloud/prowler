import { defineConfig, devices } from "@playwright/test";

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
    baseURL: "http://localhost:3000",
    trace: "off",
    screenshot: "off",
    video: "off",
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],

  webServer: {
    command: process.env.CI ? "npm run start" : "npm run dev",
    url: "http://localhost:3000",
    reuseExistingServer: !process.env.CI,
    timeout: 120 * 1000,
    env: {
      NEXT_PUBLIC_API_BASE_URL:
        process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8080/api/v1",
      AUTH_SECRET: process.env.AUTH_SECRET || "fallback-ci-secret-for-testing",
      AUTH_TRUST_HOST: process.env.AUTH_TRUST_HOST || "true",
      NEXTAUTH_URL: process.env.NEXTAUTH_URL || "http://localhost:3000",
      E2E_USER: process.env.E2E_USER || "e2e@prowler.com",
      E2E_PASSWORD: process.env.E2E_PASSWORD || "Thisisapassword123@",
    },
  },
});
