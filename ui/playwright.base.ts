import { defineConfig } from "@playwright/test";

export const getBaseConfig = () =>
  defineConfig({
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
  });
