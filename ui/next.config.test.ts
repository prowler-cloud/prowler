import { createRequire } from "node:module";

import { describe, expect, it } from "vitest";

import { getCspHeader } from "@/lib/csp";

const require = createRequire(import.meta.url);
const config = require("./next.config.js") as {
  headers: () => Promise<
    Array<{ headers: Array<{ key: string; value: string }> }>
  >;
};

const POSTHOG_WILDCARD = "https://*.posthog.com";
const ENABLED_POSTHOG_CONFIG = {
  cloudEnabled: true,
  posthogEnabled: true,
  posthogKey: "phc_key",
  posthogHost: "https://eu.posthog.com",
};

const BASELINE_CSP = {
  "default-src": ["'self'"],
  "script-src": [
    "'self'",
    "'unsafe-inline'",
    "'unsafe-eval'",
    "https://js.stripe.com",
    "https://www.googletagmanager.com",
    "https://browser.sentry-cdn.com",
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
  ],
  "img-src": [
    "'self'",
    "https://www.google-analytics.com",
    "https://www.googletagmanager.com",
  ],
  "font-src": ["'self'"],
  "style-src": ["'self'", "'unsafe-inline'"],
  "frame-src": [
    "'self'",
    "https://js.stripe.com",
    "https://www.googletagmanager.com",
  ],
  "frame-ancestors": ["'none'"],
} as const;

const getStaticCsp = async () => {
  const rules = await config.headers();
  return rules[0]?.headers.find(({ key }) => key === "Content-Security-Policy");
};

const parseCsp = (value: string) => {
  return Object.fromEntries(
    value
      .split(";")
      .map((entry) => entry.trim().split(/\s+/))
      .filter(([name]) => name)
      .map(([name, ...sources]) => [name, sources]),
  ) as Record<string, string[]>;
};

describe("PostHog Content Security Policy", () => {
  it("does not configure CSP through static Next headers", async () => {
    // When
    const staticCsp = await getStaticCsp();

    // Then
    expect(staticCsp).toBeUndefined();
  });

  it("omits PostHog permissions from the baseline request CSP", () => {
    // When
    const csp = parseCsp(
      getCspHeader({
        cloudEnabled: false,
        posthogEnabled: false,
        posthogKey: null,
        posthogHost: null,
      }),
    );

    // Then
    expect(csp).toEqual(BASELINE_CSP);
    expect(Object.values(csp).flat()).not.toContain(POSTHOG_WILDCARD);
  });

  it("adds PostHog permissions only for a fully enabled Cloud request", () => {
    // When
    const csp = parseCsp(getCspHeader(ENABLED_POSTHOG_CONFIG));

    // Then
    expect(csp["script-src"]).toContain(POSTHOG_WILDCARD);
    expect(csp["connect-src"]).toContain(POSTHOG_WILDCARD);
    expect(csp["img-src"]).toContain(POSTHOG_WILDCARD);
    expect(csp["frame-src"]).toContain(POSTHOG_WILDCARD);
    expect(csp["font-src"]).not.toContain(POSTHOG_WILDCARD);
    expect(csp["default-src"]).not.toContain(POSTHOG_WILDCARD);
  });

  it.each([
    ["Cloud is disabled", { cloudEnabled: false }],
    ["PostHog is disabled", { posthogEnabled: false }],
    ["the key is missing", { posthogKey: null }],
    ["the host is missing", { posthogHost: null }],
  ])("omits PostHog permissions when %s", (_case, override) => {
    // Given
    const config = { ...ENABLED_POSTHOG_CONFIG, ...override };

    // When
    const csp = parseCsp(getCspHeader(config));

    // Then
    expect(Object.values(csp).flat()).not.toContain(POSTHOG_WILDCARD);
  });
});
