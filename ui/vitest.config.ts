import react from "@vitejs/plugin-react";
import { playwright } from "@vitest/browser-playwright";
import path from "path";
import type { TestProjectConfiguration } from "vitest/config";
import { defineConfig } from "vitest/config";

export default defineConfig(() => {
  const apiBaseUrl = process.env.UI_API_BASE_URL ?? "http://localhost/api/v1";

  return {
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./"),
      },
    },
    test: {
      globals: true,
      restoreMocks: true,
      mockReset: true,
      unstubEnvs: true,
      unstubGlobals: true,
      coverage: {
        provider: "v8" as const,
        reporter: ["text", "json", "html"],
        exclude: [
          "node_modules",
          ".next",
          "tests/**/*",
          "**/*.test.{ts,tsx}",
          "**/*.integration.test.{ts,tsx}",
          "vitest.config.ts",
          "vitest.setup.ts",
          "vitest.integration.setup.ts",
          "__tests__/**/*",
        ],
      },
      projects: [
        {
          extends: true,
          // Unit (jsdom) suite runs without the React Compiler: enabling it
          // breaks async Server Components (`useMemoCache` on a null
          // dispatcher) and some form-validation renders. Only the browser
          // suite below needs it.
          plugins: [react()],
          test: {
            name: "unit",
            environment: "jsdom",
            setupFiles: ["./vitest.setup.ts"],
            include: ["**/*.test.{ts,tsx}"],
            exclude: [
              "node_modules",
              ".next",
              "tests/**/*",
              "**/*.integration.test.{ts,tsx}",
            ],
          },
        },
        {
          extends: true,
          plugins: [
            react({
              babel: {
                plugins: [["babel-plugin-react-compiler", { target: "19" }]],
              },
            }),
          ],
          test: {
            name: "integration",
            setupFiles: ["./vitest.integration.setup.ts"],
            include: ["**/*.integration.test.{ts,tsx}"],
            exclude: ["node_modules", ".next", "tests/**/*"],
            browser: {
              enabled: true,
              // Vitest's browser default viewport is 414×896 (phone-sized),
              // which collapses the responsive layout: the legend stacks
              // vertically and ends up overlapping the graph, so Playwright
              // can't click nodes. Use a standard desktop viewport.
              viewport: { width: 1280, height: 800 },
              provider: playwright(),
              headless: true,
              instances: [{ browser: "chromium" }],
            },
          },
        },
      ] as TestProjectConfiguration[],
    },
    define: {
      "process.env.UI_API_BASE_URL": JSON.stringify(apiBaseUrl),
      // `next/dist/server/web/spec-extension/user-agent.js` references
      // `__dirname` directly and is pulled in transitively via `next-auth`.
      // Vite serves it to the browser where that global doesn't exist, so we
      // replace it at bundle time. `optimizeDeps` alone doesn't help —
      // pre-bundling doesn't patch the identifier.
      __dirname: JSON.stringify("/"),
      __filename: JSON.stringify("/__browser_test__.js"),
    },
    optimizeDeps: {
      // Pre-bundle every dep that the attack-paths page transitively imports.
      // Without this, Vite optimizes them on demand at the first request and
      // reloads the page, killing the test run. Keep this list aligned with
      // imports through the page's render tree.
      // Kept identical to the prowler-cloud overlay's list so it stops
      // re-conflicting on sync; an entry with no importer here is deliberate.
      include: [
        // Test stack
        "vitest-browser-react",
        "msw/browser",

        // React runtime (pre-bundle so a cold run doesn't re-optimize and
        // reload mid-test — see the on-demand-reload note above).
        "react-dom/client",

        // Next runtime
        "next/headers",
        "next/navigation",
        "next/link",
        "next/image",
        "next/cache",
        "next/server",
        "next/dynamic",
        "next-auth",
        "next-auth/react",
        "next-auth/providers/credentials",
        "next-themes",

        // App component lib
        "@iconify/react",

        // Radix
        "@radix-ui/react-alert-dialog",
        "@radix-ui/react-avatar",
        "@radix-ui/react-checkbox",
        "@radix-ui/react-collapsible",
        "@radix-ui/react-dialog",
        "@radix-ui/react-dropdown-menu",
        "@radix-ui/react-icons",
        "@radix-ui/react-label",
        "@radix-ui/react-popover",
        "@radix-ui/react-progress",
        "@radix-ui/react-radio-group",
        "@radix-ui/react-scroll-area",
        "@radix-ui/react-select",
        "@radix-ui/react-separator",
        "@radix-ui/react-switch",
        "@radix-ui/react-tabs",
        "@radix-ui/react-toast",
        "@radix-ui/react-tooltip",
        "@radix-ui/react-slot",
        "@radix-ui/react-use-controllable-state",

        // Graph
        "@xyflow/react",
        "@dagrejs/dagre",

        // Forms / state
        "react-hook-form",
        "@hookform/resolvers/zod",
        "zod",
        "zustand",
        "zustand/middleware",
        "zustand/vanilla",

        // Styling helpers
        "lucide-react",
        "clsx",
        "tailwind-merge",
        "class-variance-authority",

        // App-level deps the page (or its children) pull in
        "@tanstack/react-table",
        "@react-aria/ssr",
        "@react-aria/visually-hidden",
        "framer-motion",
        "cmdk",
        "driver.js",
        "react-markdown",
        "streamdown",
        "jwt-decode",
        "date-fns",
        "js-yaml",
        "@codemirror/language",
        "@codemirror/state",
        "@lezer/highlight",
        "@uiw/react-codemirror",
        "@sentry/nextjs",
        "@extractus/feed-extractor",
        "@stripe/stripe-js",
      ],
    },
  };
});
