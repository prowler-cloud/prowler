import react from "@vitejs/plugin-react";
import { playwright } from "@vitest/browser-playwright";
import path from "path";
import { defineConfig } from "vitest/config";

const aliases = {
  "@": path.resolve(__dirname, "./"),
  "next/cache": path.resolve(__dirname, "./__mocks__/next-cache.ts"),
  "next/server": path.resolve(__dirname, "./__mocks__/next-server.ts"),
  "next/router": path.resolve(__dirname, "./__mocks__/next-router.ts"),
  "@stripe/stripe-js": path.resolve(__dirname, "./__mocks__/stripe-js.ts"),
};

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
    restoreMocks: true,
    mockReset: true,
    unstubEnvs: true,
    unstubGlobals: true,
    exclude: [
      "node_modules",
      ".next",
      "tests/**/*", // Playwright E2E tests
    ],
    projects: [
      {
        extends: true,
        test: {
          name: "unit",
          environment: "jsdom",
          include: ["**/*.test.{ts,tsx}"],
          exclude: ["**/*.browser.test.{ts,tsx}"],
        },
      },
      {
        extends: true,
        define: {
          "process.env.NEXT_PUBLIC_API_BASE_URL": JSON.stringify(
            "https://some-api-server/api/v1",
          ),
          "process.env": JSON.stringify({
            NEXT_PUBLIC_API_BASE_URL: "https://some-api-server/api/v1",
            NODE_ENV: "test",
          }),
          "process.version": JSON.stringify(""),
        },
        test: {
          name: "browser",
          include: ["**/*.browser.test.{ts,tsx}"],
          browser: {
            enabled: true,
            provider: playwright(),
            headless: true,
            instances: [{ browser: "chromium" }],
          },
        },
      },
    ],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      exclude: [
        "node_modules",
        ".next",
        "tests/**/*",
        "**/*.test.{ts,tsx}",
        "**/*.browser.test.{ts,tsx}",
        "vitest.config.ts",
        "vitest.setup.ts",
      ],
    },
  },
  optimizeDeps: {
    include: ["vitest-browser-react", "next-auth/react", "@sentry/nextjs"],
  },
  resolve: {
    alias: aliases,
  },
});
