/**
 * Next.js Instrumentation Hook
 *
 * This file is automatically executed by Next.js at startup to initialize server-side SDKs.
 *
 * Configuration Flow:
 * 1. This file (instrumentation.ts) - Server-side initialization
 * 2. Runtime-specific configs:
 *    - sentry/sentry.server.config.ts (Node.js runtime)
 *    - sentry/sentry.edge.config.ts (Edge runtime)
 * 3. Client-side init:
 *    - app/instrumentation.client.ts (Browser/Client)
 *
 * @see https://nextjs.org/docs/app/building-your-application/optimizing/instrumentation
 */

import * as Sentry from "@sentry/nextjs";

const SENTRY_DSN = process.env.SENTRY_DSN;
const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? "";

/**
 * Patches globalThis.fetch to log all outgoing requests to the Prowler API.
 * Only active in development. Logs method, path, status, and duration.
 */
function patchFetchForLogging() {
  if (process.env.NODE_ENV !== "development" || !API_BASE_URL) return;

  const originalFetch = globalThis.fetch;

  globalThis.fetch = async function patchedFetch(
    input: RequestInfo | URL,
    init?: RequestInit,
  ) {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

    if (!url.startsWith(API_BASE_URL)) {
      return originalFetch(input, init);
    }

    const method = init?.method?.toUpperCase() ?? "GET";
    const path = url.replace(API_BASE_URL, "");
    const start = performance.now();

    const response = await originalFetch(input, init);

    const duration = Math.round(performance.now() - start);
    const ok = response.ok ? "✓" : "✗";
    console.log(`[API] ${ok} ${method} ${response.status} ${path} (${duration}ms)`);

    return response;
  } as typeof fetch;
}

export async function register() {
  patchFetchForLogging();

  // Skip Sentry initialization if DSN is not configured
  if (!SENTRY_DSN) {
    return;
  }

  // The Sentry SDK automatically loads the appropriate config based on runtime
  if (process.env.NEXT_RUNTIME === "nodejs") {
    await import("./sentry/sentry.server.config");
  }

  if (process.env.NEXT_RUNTIME === "edge") {
    await import("./sentry/sentry.edge.config");
  }
}

// Only capture request errors if Sentry is configured
export const onRequestError = SENTRY_DSN
  ? Sentry.captureRequestError
  : undefined;
