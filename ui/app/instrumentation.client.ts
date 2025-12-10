"use client";

/**
 * Client-side Sentry instrumentation
 *
 * This file is automatically loaded by Next.js in the browser via the instrumentation hook.
 * It configures Sentry for client-side error tracking and performance monitoring.
 *
 * For server-side configuration, see: instrumentation.ts
 * For runtime-specific configs, see: sentry/sentry.server.config.ts and sentry/sentry.edge.config.ts
 */

import * as Sentry from "@sentry/nextjs";

const SENTRY_DSN = process.env.NEXT_PUBLIC_SENTRY_DSN;

// Only initialize Sentry in the browser (not during SSR)
if (typeof window !== "undefined" && SENTRY_DSN) {
  const isDevelopment = process.env.NEXT_PUBLIC_SENTRY_ENVIRONMENT === "local";

  /**
   * Initialize Sentry error tracking and performance monitoring
   *
   * This setup includes:
   * - Performance monitoring with Web Vitals tracking (LCP, FID, CLS, INP)
   * - Long task detection for UI-blocking operations
   * - beforeSend hook to filter noise
   */
  Sentry.init({
    // 📍 DSN - Data Source Name (identifies your Sentry project)
    dsn: SENTRY_DSN,

    // 🌍 Environment - Separate dev errors from production
    environment: process.env.NEXT_PUBLIC_SENTRY_ENVIRONMENT || "local",

    // 📦 Release - Track which version has the error
    release: process.env.NEXT_PUBLIC_PROWLER_RELEASE_VERSION,

    // 🐛 Debug - Detailed logs in development console
    debug: isDevelopment,

    // 📊 Sample Rates - Performance monitoring
    // 100% in dev (test everything), 50% in production (balance visibility with costs)
    tracesSampleRate: isDevelopment ? 1.0 : 0.5,
    profilesSampleRate: isDevelopment ? 1.0 : 0.5,

    // 🔌 Integrations - browserTracingIntegration is client-only
    integrations: [
      // 📊 Performance Monitoring: Core Web Vitals + RUM
      // Tracks LCP, FID, CLS, INP
      // Real User Monitoring captures actual user experience, not synthetic tests
      Sentry.browserTracingIntegration({
        enableLongTask: true, // Detect tasks that block UI (>50ms)
        enableInp: true, // Interaction to Next Paint (Core Web Vital)
      }),
    ],

    // 🎣 beforeSend Hook - Filter or modify events before sending to Sentry
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
      // ResizeObserver errors (common browser quirk, not real bugs)
      "ResizeObserver",
    ],

    beforeSend(event, hint) {
      // Filter out noise: ResizeObserver errors (common browser quirk, not real bugs)
      if (event.message?.includes("ResizeObserver")) {
        return null; // Don't send to Sentry
      }

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

      return event; // Send to Sentry
    },
  });

  // 👤 Set user context (identifies who experienced the error)
  // In production, this will be updated after authentication
  if (isDevelopment) {
    Sentry.setUser({
      id: "dev-user",
    });
  }
}
