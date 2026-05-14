import type { KnipConfig } from "knip";

// Baseline: the `lint:knip` script runs with `--max-issues 504` so CI only
// fails on regressions beyond the current inventory of unused code. Reduce the
// threshold as issues are cleaned up (tracked for the dead-code removal step
// in the knip rollout roadmap).
const config: KnipConfig = {
  entry: [
    // Next.js app conventions (pages, layouts, errors, route handlers)
    "app/**/page.{ts,tsx}",
    "app/**/layout.{ts,tsx}",
    "app/**/error.{ts,tsx}",
    "app/**/route.ts",

    // Auth.js configuration
    "auth.config.ts",

    // Sentry runtime configs (dynamically imported by instrumentation.ts)
    "sentry/sentry.server.config.ts",
    "sentry/sentry.edge.config.ts",

    // Note: Next.js auto-loaded entries (instrumentation.ts, instrumentation-client.ts,
    // proxy.ts — the renamed middleware) are detected by knip's built-in Next.js plugin
    // and do not need explicit entries here.

    // Build/postinstall scripts
    "scripts/*.js",
  ],
  project: ["**/*.{ts,tsx,js,jsx}"],
  ignoreDependencies: [
    // Next.js image optimization — loaded at build time, no static import
    "sharp",
    // Sentry instrumentation hooks — loaded via require() by the runtime
    "import-in-the-middle",
    "require-in-the-middle",
    // @heroui/react re-exports all sub-packages; imports like @heroui/skeleton
    // resolve to transitive deps of @heroui/react, not direct dependencies
    "@heroui/*",
  ],
  ignoreExportsUsedInFile: {
    interface: true,
    type: true,
  },
};

export default config;
