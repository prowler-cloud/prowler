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
 *    - instrumentation-client.ts (Browser/Client; reads the runtime data island)
 *
 * @see https://nextjs.org/docs/app/building-your-application/optimizing/instrumentation
 */

// Fail fast at server boot if required runtime env is missing.
import "@/lib/env";

import * as Sentry from "@sentry/nextjs";

import { readEnv } from "@/lib/runtime-env";

const sentryDsn = readEnv("UI_SENTRY_DSN", "NEXT_PUBLIC_SENTRY_DSN");

export async function register() {
  // Skip Sentry initialization if DSN is not configured
  if (!sentryDsn) {
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
export const onRequestError = sentryDsn
  ? Sentry.captureRequestError
  : undefined;
