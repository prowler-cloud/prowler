import * as Sentry from "@sentry/nextjs";

Sentry.init({
  dsn: process.env.SENTRY_DSN || process.env.NEXT_PUBLIC_SENTRY_DSN,

  // Environment configuration
  environment:
    process.env.SENTRY_ENVIRONMENT || process.env.NODE_ENV || "development",

  // Performance Monitoring (reduced for edge runtime)
  tracesSampleRate: process.env.NODE_ENV === "production" ? 0.05 : 0.5,

  // Release tracking
  release: process.env.SENTRY_RELEASE || process.env.NEXT_PUBLIC_SENTRY_RELEASE,

  // Edge runtime doesn't support all integrations
  integrations: [],

  // Filtering - Ignoramos errores esperados
  ignoreErrors: [
    // NextAuth redirect errors - Son parte del flujo normal
    "NEXT_REDIRECT",
    "NEXT_NOT_FOUND",
    // Expected API errors - No requieren intervención
    "401", // Unauthorized - esperado cuando el token expira
    "403", // Forbidden - esperado cuando no hay permisos
    "404", // Not Found - esperado para recursos inexistentes
  ],

  beforeSend(event, hint) {
    // Add edge runtime context
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
