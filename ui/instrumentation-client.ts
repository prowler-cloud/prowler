/**
 * Next.js Client Instrumentation
 *
 * This file runs on the client BEFORE React hydration. It is responsible for:
 * - Initializing browser Sentry from the runtime data island, so a single
 *   prebuilt image enables/disables Sentry per deployment via `UI_SENTRY_DSN`
 *   (unset DSN ⇒ `Sentry.init` is never called ⇒ zero egress).
 * - Driving the navigation progress bar on router transitions.
 *
 * Running here (rather than in a React effect) means Sentry is configured
 * before hydration, so browserTracing's performance observers attach early and
 * the error boundary in `global-error.tsx` is covered.
 *
 * @see https://nextjs.org/docs/app/api-reference/file-conventions/instrumentation-client
 */

import * as Sentry from "@sentry/nextjs";

import {
  cancelProgress,
  startProgress,
} from "@/components/ui/navigation-progress/use-navigation-progress";
import { getRuntimeConfigClient } from "@/lib/get-runtime-config.client";

export const NAVIGATION_TYPE = {
  PUSH: "push",
  REPLACE: "replace",
  TRAVERSE: "traverse",
} as const;

type NavigationType = (typeof NAVIGATION_TYPE)[keyof typeof NAVIGATION_TYPE];

const { sentryDsn, sentryEnvironment } = getRuntimeConfigClient();

// Only initialize Sentry in the browser when a runtime DSN is configured.
if (typeof window !== "undefined" && sentryDsn) {
  // Default to a non-dev environment so an unset UI_SENTRY_ENVIRONMENT never
  // runs the browser SDK in dev mode (debug logging, 100% sampling, synthetic
  // dev user); only an explicit "local" enables it.
  const environment = sentryEnvironment ?? "production";
  const isDevelopment = environment === "local";

  /**
   * Initialize Sentry error tracking and performance monitoring.
   *
   * This setup includes:
   * - Performance monitoring with Web Vitals tracking (LCP, FID, CLS, INP)
   * - Long task detection for UI-blocking operations
   * - beforeSend hook to filter noise
   */
  Sentry.init({
    // 📍 DSN - resolved at runtime from the data island
    dsn: sentryDsn,

    // 🌍 Environment - separate dev errors from production
    environment,

    // 📦 Release - the browser can only read the build-time public release
    // version; SENTRY_RELEASE is non-public and never reaches the client. The
    // server/edge SDKs read SENTRY_RELEASE for parity (D10). No new release var.
    release: process.env.NEXT_PUBLIC_PROWLER_RELEASE_VERSION,

    // 🐛 Debug - detailed logs in development console
    debug: isDevelopment,

    // 📊 Sample Rates - Performance monitoring
    // 100% in dev (test everything), 50% in production (balance visibility with costs)
    tracesSampleRate: isDevelopment ? 1.0 : 0.5,
    profilesSampleRate: isDevelopment ? 1.0 : 0.5,

    // 🔌 Integrations - browserTracingIntegration is client-only
    integrations: [
      // 📊 Performance Monitoring: Core Web Vitals + RUM
      // Tracks LCP, FID, CLS, INP
      Sentry.browserTracingIntegration({
        enableLongTask: true, // Detect tasks that block UI (>50ms)
        enableInp: true, // Interaction to Next Paint (Core Web Vital)
      }),
    ],

    // 🎣 Filter expected errors / noise before sending to Sentry
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

function getCurrentUrl(): string {
  return window.location.pathname + window.location.search;
}

/**
 * Called by Next.js when router navigation begins.
 *
 * Triggers the navigation progress bar AND forwards the transition to Sentry
 * (`captureRouterTransitionStart` is a safe no-op when Sentry is
 * uninitialized).
 */
export function onRouterTransitionStart(
  url: string,
  navigationType: NavigationType,
) {
  const currentUrl = getCurrentUrl();

  if (url === currentUrl) {
    // Same URL - cancel any ongoing progress
    cancelProgress();
  } else {
    // Different URL - start progress
    startProgress();
  }

  Sentry.captureRouterTransitionStart(url, navigationType);
}
