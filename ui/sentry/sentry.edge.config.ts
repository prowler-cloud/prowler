import * as Sentry from "@sentry/nextjs";

import { readEnv } from "@/lib/runtime-env";

const sentryDsn = readEnv("UI_SENTRY_DSN", "NEXT_PUBLIC_SENTRY_DSN");
const sentryEnvironment = readEnv(
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

    // 🎣 Filter expected errors - Don't send noise to Sentry
    ignoreErrors: [
      // NextAuth redirect errors - Expected behavior in auth flow
      "NEXT_REDIRECT",
      "NEXT_NOT_FOUND",
      // Expected HTTP errors - Expected when users lack permissions
      "401", // Unauthorized - expected when token expires
      "403", // Forbidden - expected when no permissions
      "404", // Not Found - expected for missing resources
    ],

    beforeSend(event, hint) {
      // Add edge runtime context for debugging
      event.tags = {
        ...event.tags,
        runtime: "edge",
      };

      const error = hint.originalException;

      // Don't send NextAuth expected errors
      if (
        error &&
        typeof error === "object" &&
        "message" in error &&
        typeof error.message === "string" &&
        error.message.includes("NEXT_REDIRECT")
      ) {
        return null;
      }

      return event;
    },
  });
}
