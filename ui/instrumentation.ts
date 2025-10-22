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

export async function register() {
  // The Sentry SDK automatically loads the appropriate config based on runtime
  if (process.env.NEXT_RUNTIME === "nodejs") {
    await import("./sentry/sentry.server.config");
  }

  if (process.env.NEXT_RUNTIME === "edge") {
    await import("./sentry/sentry.edge.config");
  }
}

export const onRequestError = Sentry.captureRequestError;
