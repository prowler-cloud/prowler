import { defineConfig, devices } from "@playwright/test";
import * as dotenv from "dotenv";
dotenv.config();

const isLocal = process.env.LOCAL === "true";

export default defineConfig({
  timeout: 90 * 1000,
  testDir: "./tests/e2e",
  fullyParallel: false,
  forbidOnly: !isLocal,
  retries: isLocal ? 0 : 2,
  workers: isLocal ? undefined : 1,
  reporter: "html",
  use: {
    baseURL: "http://localhost:3000",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    navigationTimeout: 60 * 1000,
  },

  /* Configure projects for major browsers */
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },

    // {
    //     name: 'firefox',
    //     use: { ...devices['Desktop Firefox'] },
    // },

    // {
    //     name: 'webkit',
    //     use: { ...devices['Desktop Safari'] },
    // },

    /* Test against mobile viewports. */
    // {
    //   name: 'Mobile Chrome',
    //   use: { ...devices['Pixel 5'] },
    // },
    // {
    //   name: 'Mobile Safari',
    //   use: { ...devices['iPhone 12'] },
    // },

    /* Test against branded browsers. */
    // {
    //   name: 'Microsoft Edge',
    //   use: { ...devices['Desktop Edge'], channel: 'msedge' },
    // },
    // {
    //   name: 'Google Chrome',
    //   use: { ...devices['Desktop Chrome'], channel: 'chrome' },
    // },
  ],

  /* Run your local dev server before starting the tests */
  webServer: isLocal
    ? undefined // Skip web server in local runs
    : {
        command: "npm run dev",
        url: "http://localhost:3000",
        reuseExistingServer: true,
        timeout: 120 * 1000, // wait up to 2 minutes for frontend to boot
      },
});
