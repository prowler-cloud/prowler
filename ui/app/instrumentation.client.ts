import * as Sentry from "@sentry/nextjs";

Sentry.init({
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,

  // Environment configuration
  environment: process.env.NEXT_PUBLIC_SENTRY_ENVIRONMENT || "development",

  // Performance Monitoring
  tracesSampleRate: process.env.NODE_ENV === "production" ? 0.1 : 1.0,

  // Session Replay
  replaysSessionSampleRate: 0.1, // 10% of sessions will be recorded
  replaysOnErrorSampleRate: 1.0, // 100% of sessions with errors will be recorded

  // Release tracking
  release: process.env.NEXT_PUBLIC_PROWLER_RELEASE_VERSION,

  // Integrations
  integrations: [
    Sentry.replayIntegration({
      maskAllText: false,
      blockAllMedia: false,
    }),
    Sentry.browserTracingIntegration(),
  ],

  // Filtering
  ignoreErrors: [
    // Browser extensions
    "top.GLOBALS",
    // Random network errors
    "Network request failed",
    "NetworkError",
    "Failed to fetch",
    // User canceled actions
    "AbortError",
    "Non-Error promise rejection captured",
    // NextAuth expected errors
    "NEXT_REDIRECT",
  ],

  beforeSend(event, hint) {
    // Filter out non-actionable errors
    if (event.exception) {
      const error = hint.originalException;

      // Don't send cancelled requests
      if (
        error &&
        typeof error === "object" &&
        "name" in error &&
        error.name === "AbortError"
      ) {
        return null;
      }

      // Add additional context for API errors
      if (
        error &&
        typeof error === "object" &&
        "message" in error &&
        typeof error.message === "string" &&
        error.message.includes("Request failed")
      ) {
        event.tags = {
          ...event.tags,
          error_type: "api_error",
        };
      }
    }

    return event;
  },
});
