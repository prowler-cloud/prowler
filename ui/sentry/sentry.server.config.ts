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
  // runs in dev mode (100% sampling); only an explicit "local" enables it.
  // Mirrors the browser SDK (instrumentation-client.ts) so all runtimes resolve
  // the env identically.
  const environment = sentryEnvironment ?? "production";
  const isDevelopment = environment === "local";

  /**
   * Server-side Sentry configuration
   *
   * This setup includes:
   * - Performance monitoring for server-side operations
   * - Error tracking for API routes and server actions
   * - beforeSend hook to filter noise and add context
   */
  Sentry.init({
    // 📍 DSN - Data Source Name (identifies your Sentry project)
    dsn: sentryDsn,

    // 🌍 Environment configuration
    environment,

    // 📦 Release tracking
    release: process.env.SENTRY_RELEASE,

    // 📊 Sample Rates - Performance monitoring
    // 100% in dev (test everything), 50% in production (balance visibility with costs)
    tracesSampleRate: isDevelopment ? 1.0 : 0.5,
    profilesSampleRate: isDevelopment ? 1.0 : 0.5,

    // 🔌 Integrations
    integrations: [
      Sentry.extraErrorDataIntegration({
        depth: 5, // Include up to 5 levels of nested objects
      }),
    ],

    // 🎣 Filter expected errors - Don't send noise to Sentry
    ignoreErrors: [
      // NextAuth redirect errors - Expected behavior
      "NEXT_REDIRECT",
      "NEXT_NOT_FOUND",
      // Expected HTTP errors - Expected when users lack permissions
      "401", // Unauthorized
      "403", // Forbidden
      "404", // Not Found
    ],

    beforeSend(event, hint) {
      // Add server context and tag errors appropriately
      if (event.exception) {
        const error = hint.originalException;

        // Tag API errors for better filtering in Sentry dashboard
        if (
          error &&
          typeof error === "object" &&
          "message" in error &&
          typeof error.message === "string"
        ) {
          if (error.message.includes("Server error")) {
            event.tags = {
              ...event.tags,
              error_type: "server_error",
              severity: "high",
            };
          } else if (error.message.includes("Request failed")) {
            event.tags = {
              ...event.tags,
              error_type: "api_error",
            };
          }

          // Don't send NextAuth expected errors
          if (error.message.includes("NEXT_REDIRECT")) {
            return null;
          }
        }
      }

      return event;
    },
  });
}
