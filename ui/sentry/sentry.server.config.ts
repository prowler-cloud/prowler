import * as Sentry from "@sentry/nextjs";

Sentry.init({
  dsn: process.env.SENTRY_DSN || process.env.NEXT_PUBLIC_SENTRY_DSN,

  // Environment configuration
  environment:
    process.env.SENTRY_ENVIRONMENT || process.env.NODE_ENV || "development",

  // Performance Monitoring
  tracesSampleRate: process.env.NODE_ENV === "production" ? 0.1 : 1.0,

  // Release tracking
  release: process.env.SENTRY_RELEASE || process.env.NEXT_PUBLIC_SENTRY_RELEASE,

  // Integrations
  integrations: [
    Sentry.extraErrorDataIntegration({
      depth: 5,
    }),
  ],

  // Filtering - Ignore expected errors
  ignoreErrors: [
    // NextAuth redirect errors - Expected NextAuth errors
    "NEXT_REDIRECT",
    "NEXT_NOT_FOUND",
    // Expected API errors - Expected HTTP errors
    "401", // Unauthorized - Expected
    "403", // Forbidden - Expected
    "404", // Not Found - Expected
  ],

  beforeSend(event, hint) {
    // Add server context
    if (event.exception) {
      const error = hint.originalException;

      // Tag API errors
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
