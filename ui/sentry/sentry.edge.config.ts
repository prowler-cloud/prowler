import * as Sentry from "@sentry/nextjs";

import { readGatedEnv } from "@/lib/integrations";

import { applySentryEventPolicy, SENTRY_EVENT_SOURCE } from "./event-policy";

const sentryDsn = readGatedEnv(
  "UI_SENTRY_ENABLED",
  "UI_SENTRY_DSN",
  "NEXT_PUBLIC_SENTRY_DSN",
);
const sentryEnvironment = readGatedEnv(
  "UI_SENTRY_ENABLED",
  "UI_SENTRY_ENVIRONMENT",
  "NEXT_PUBLIC_SENTRY_ENVIRONMENT",
);

// Only initialize Sentry if DSN is configured
if (sentryDsn) {
  // Default to a non-dev environment so an unset UI_SENTRY_ENVIRONMENT never
  // runs in dev mode; only an explicit "local" enables it. Mirrors the browser
  // SDK (instrumentation-client.ts) so all runtimes resolve the env identically.
  const environment = sentryEnvironment ?? "production";
  const isDevelopment = environment === "local";

  /**
   * Edge runtime Sentry configuration
   *
   * Edge runtime has stricter constraints than Node.js:
   * - Limited execution time (~10-30 seconds)
   * - Lower memory availability
   * - Reduced sample rates to minimize overhead
   * - No complex integrations
   */
  Sentry.init({
    // 📍 DSN - Data Source Name (identifies your Sentry project)
    dsn: sentryDsn,

    // 🌍 Environment configuration
    environment,

    // 📦 Release tracking
    release: process.env.SENTRY_RELEASE,

    // 📊 Sample Rates - Reduced for edge runtime constraints
    // 50% in dev, 25% in production (edge has lower overhead limits than server)
    tracesSampleRate: isDevelopment ? 0.5 : 0.25,

    // 🔌 Integrations - Edge runtime doesn't support all integrations
    integrations: [],

    // 🎣 Filter expected framework control-flow - Don't send noise to Sentry.
    // HTTP status-based suppression belongs in applySentryEventPolicy, where
    // structured event context prevents broad numeric matches from hiding crashes.
    ignoreErrors: [
      // NextAuth redirect errors - Expected behavior in auth flow
      "NEXT_REDIRECT",
      "NEXT_NOT_FOUND",
    ],

    beforeSend(event, hint) {
      // Add edge runtime context for debugging
      event.tags = {
        ...event.tags,
        runtime: "edge",
      };

      return applySentryEventPolicy(event, hint, {
        source: SENTRY_EVENT_SOURCE.EDGE,
      });
    },
  });
}
