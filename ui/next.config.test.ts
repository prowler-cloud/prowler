import { createRequire } from "node:module";

import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);
const config = require("./next.config.js") as {
  headers: () => Promise<
    Array<{ headers: Array<{ key: string; value: string }> }>
  >;
};

const POSTHOG_WILDCARD = "https://*.posthog.com";

const BASELINE_CSP = {
  "default-src": ["'self'"],
  "script-src": [
    "'self'",
    "'unsafe-inline'",
    "'unsafe-eval'",
    "https://js.stripe.com",
    "https://www.googletagmanager.com",
    "https://browser.sentry-cdn.com",
    POSTHOG_WILDCARD,
  ],
  "connect-src": [
    "'self'",
    "https://api.iconify.design",
    "https://api.simplesvg.com",
    "https://api.unisvg.com",
    "https://js.stripe.com",
    "https://www.googletagmanager.com",
    "https://*.sentry.io",
    "https://*.ingest.sentry.io",
    POSTHOG_WILDCARD,
  ],
  "img-src": [
    "'self'",
    "https://www.google-analytics.com",
    "https://www.googletagmanager.com",
    POSTHOG_WILDCARD,
  ],
  "font-src": ["'self'"],
  "style-src": ["'self'", "'unsafe-inline'"],
  "frame-src": [
    "'self'",
    "https://js.stripe.com",
    "https://www.googletagmanager.com",
    POSTHOG_WILDCARD,
  ],
  "frame-ancestors": ["'none'"],
} as const;

const getRawCsp = async () => {
  const rules = await config.headers();
  const value = rules[0]?.headers.find(
    ({ key }) => key === "Content-Security-Policy",
  )?.value;
  if (!value) throw new Error("CSP header is missing");
  return value;
};

const getCsp = async () => {
  const value = await getRawCsp();
  return Object.fromEntries(
    value
      .split(";")
      .map((entry) => entry.trim().split(/\s+/))
      .filter(([name]) => name)
      .map(([name, ...sources]) => [name, sources]),
  ) as Record<string, string[]>;
};

describe("PostHog Content Security Policy", () => {
  it("keeps the PostHog wildcard in the exact baseline CSP", async () => {
    // Given - CSP grants permission, while runtime guards decide whether the
    // browser ever initializes PostHog or makes a request.
    // When
    const csp = await getCsp();

    // Then - exactly the four required directives contain the wildcard.
    expect(csp).toEqual(BASELINE_CSP);
    expect(csp["font-src"]).not.toContain(POSTHOG_WILDCARD);
    expect(csp["default-src"]).not.toContain(POSTHOG_WILDCARD);
  });
});
