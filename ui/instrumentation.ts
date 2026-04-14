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

const SENTRY_DSN = process.env.SENTRY_DSN;

export async function register() {
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

// Only capture request errors if Sentry is configured — use dynamic import to
// prevent Turbopack from externalising require-in-the-middle at build time
// when SENTRY_DSN is absent (e.g. Cloud.gov deployments).
export async function onRequestError(
  ...args: Parameters<
    Awaited<typeof import("@sentry/nextjs")>["captureRequestError"]
  >
): Promise<void> {
  if (!SENTRY_DSN) return;
  const { captureRequestError } = await import("@sentry/nextjs");
  return captureRequestError(...args);
}
