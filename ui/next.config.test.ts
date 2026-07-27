import { createRequire } from "node:module";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const require = createRequire(import.meta.url);
const config = require("./next.config.js") as {
  headers: () => Promise<
    Array<{ headers: Array<{ key: string; value: string }> }>
  >;
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

// The SDK reaches config, capture, surveys, and assets across the PostHog
// wildcard host, matching Prowler Cloud's CSP.
const POSTHOG_WILDCARD = "https://*.posthog.com";
// Directives that must gain the wildcard when PostHog is enabled.
const POSTHOG_DIRECTIVES = [
  "script-src",
  "connect-src",
  "img-src",
  "frame-src",
] as const;

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
  beforeEach(() => {
    vi.stubEnv("UI_CLOUD_ENABLED", undefined);
  });

  afterEach(() => vi.unstubAllEnvs());

  it.each([
    ["unset", undefined],
    ["not 'true' (\"false\")", "false"],
  ])(
    "keeps the exact baseline CSP and no PostHog source when UI_CLOUD_ENABLED is %s",
    async (_case, cloud) => {
      // Given - PostHog is Cloud-gated; a non-Cloud deployment adds nothing.
      vi.stubEnv("UI_CLOUD_ENABLED", cloud);

      // When
      const csp = await getCsp();
      const raw = await getRawCsp();

      // Then - baseline unchanged; the wildcard appears in no directive.
      expect(csp).toEqual(BASELINE_CSP);
      expect(raw).not.toContain(POSTHOG_WILDCARD);
    },
  );

  it("adds the PostHog wildcard to script-src, connect-src, img-src, and frame-src when UI_CLOUD_ENABLED is 'true'", async () => {
    // Given - a Prowler Cloud deployment. NEXT_PUBLIC_* is inlined and not
    // readable by next.config at load time, so the CSP is gated on the plain
    // UI_CLOUD_ENABLED runtime flag instead.
    vi.stubEnv("UI_CLOUD_ENABLED", "true");

    // When
    const csp = await getCsp();

    // Then - exactly the four Cloud directives gain the wildcard; nothing else.
    expect(csp).toEqual({
      ...BASELINE_CSP,
      "script-src": [...BASELINE_CSP["script-src"], POSTHOG_WILDCARD],
      "connect-src": [...BASELINE_CSP["connect-src"], POSTHOG_WILDCARD],
      "img-src": [...BASELINE_CSP["img-src"], POSTHOG_WILDCARD],
      "frame-src": [...BASELINE_CSP["frame-src"], POSTHOG_WILDCARD],
    });
    for (const directive of POSTHOG_DIRECTIVES) {
      expect(csp[directive]).toContain(POSTHOG_WILDCARD);
    }
    // Directives Cloud does not extend stay wildcard-free.
    expect(csp["font-src"]).not.toContain(POSTHOG_WILDCARD);
    expect(csp["default-src"]).not.toContain(POSTHOG_WILDCARD);
  });
});
