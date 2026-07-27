const dotenv = require("dotenv");
const dotenvExpand = require("dotenv-expand");
dotenvExpand.expand(dotenv.config({ path: "../.env", quiet: true }));
const { withSentryConfig } = require("@sentry/nextjs");

/** @type {import('next').NextConfig} */

const POSTHOG_CSP_SOURCE = " https://*.posthog.com";

// HTTP Security Headers
// 'unsafe-eval' is configured under `script-src` because it is required by NextJS for development mode.
//
// The JSON config island is inert (no nonce needed). A runtime Sentry DSN must
// be in `connect-src` below — `*.sentry.io` covers Sentry Cloud, but a
// self-hosted/region host is blocked until per-request CSP (middleware) lands.
const getCspHeader = () => {
  // PostHog backs the in-app, Cloud-only feedback survey. Its wildcard host is
  // allowed only on cloud deployments (UI_CLOUD_ENABLED) — the same gate as the
  // widget itself — so self-hosted OSS omits it entirely and keeps zero
  // third-party egress by default. When enabled, the SDK loads its
  // config/surveys bundle, captures events, and fetches survey definitions
  // across *.posthog.com, so that wildcard goes in script-src, connect-src,
  // img-src, and frame-src (same placement as Prowler Cloud). NEXT_PUBLIC_* vars
  // are not visible to next.config at load time, so the plain UI_CLOUD_ENABLED
  // runtime flag is used here rather than NEXT_PUBLIC_POSTHOG_KEY.
  const posthog =
    process.env.UI_CLOUD_ENABLED === "true" ? POSTHOG_CSP_SOURCE : "";

  return `
  default-src 'self';
  script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com https://www.googletagmanager.com https://browser.sentry-cdn.com${posthog};
  connect-src 'self' https://api.iconify.design https://api.simplesvg.com https://api.unisvg.com https://js.stripe.com https://www.googletagmanager.com https://*.sentry.io https://*.ingest.sentry.io${posthog};
  img-src 'self' https://www.google-analytics.com https://www.googletagmanager.com${posthog};
  font-src 'self';
  style-src 'self' 'unsafe-inline';
  frame-src 'self' https://js.stripe.com https://www.googletagmanager.com${posthog};
  frame-ancestors 'none';
`;
};

const nextConfig = {
  poweredByHeader: false,
  // Use standalone only in production deployments, not for CI/testing
  ...(process.env.NODE_ENV === "production" &&
    !process.env.CI && {
      output: "standalone",
      outputFileTracingRoot: __dirname,
    }),
  // React Compiler is now stable in Next.js 16
  reactCompiler: true,
  turbopack: {
    root: __dirname,
  },
  async headers() {
    const headers = [
      {
        key: "Content-Security-Policy",
        value: getCspHeader().replace(/\n/g, ""),
      },
      {
        key: "X-Content-Type-Options",
        value: "nosniff",
      },
      {
        key: "Referrer-Policy",
        value: "strict-origin-when-cross-origin",
      },
    ];

    return [
      {
        source: "/(.*)",
        headers,
      },
    ];
  },
};

// Sentry configuration options
const sentryWebpackPluginOptions = {
  org: process.env.SENTRY_ORG,
  project: process.env.SENTRY_PROJECT,
  authToken: process.env.SENTRY_AUTH_TOKEN,
  silent: true, // Suppresses all logs
  hideSourceMaps: true, // Hides source maps from generated client bundles
  disableLogger: true, // Automatically tree-shake Sentry logger statements to reduce bundle size
  widenClientFileUpload: true, // Upload a larger set of source maps for prettier stack traces
};

// Export with Sentry only if configuration is available
const hasSentryBuildCredentials = Boolean(
  process.env.SENTRY_AUTH_TOKEN &&
    process.env.SENTRY_ORG &&
    process.env.SENTRY_PROJECT,
);

module.exports = hasSentryBuildCredentials
  ? withSentryConfig(nextConfig, sentryWebpackPluginOptions)
  : nextConfig;
