const dotenv = require("dotenv");
const dotenvExpand = require("dotenv-expand");
dotenvExpand.expand(dotenv.config({ path: "../.env", quiet: true }));
const { withSentryConfig } = require("@sentry/nextjs");

/** @type {import('next').NextConfig} */

// HTTP Security Headers
// 'unsafe-eval' is configured under `script-src` because it is required by NextJS for development mode
const cspHeader = `
  default-src 'self';
  script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com https://www.googletagmanager.com https://browser.sentry-cdn.com;
  connect-src 'self' https://api.iconify.design https://api.simplesvg.com https://api.unisvg.com https://js.stripe.com https://www.googletagmanager.com https://*.sentry.io https://*.ingest.sentry.io;
  img-src 'self' https://www.google-analytics.com https://www.googletagmanager.com;
  font-src 'self';
  style-src 'self' 'unsafe-inline';
  frame-src 'self' https://js.stripe.com https://www.googletagmanager.com;
  frame-ancestors 'none';
  report-to csp-endpoint;
`;

// Get Sentry CSP report endpoint if DSN is configured
const getSentryReportEndpoint = () => {
  if (!process.env.NEXT_PUBLIC_SENTRY_DSN) return null;
  try {
    const sentryKey =
      process.env.NEXT_PUBLIC_SENTRY_DSN.split("@")[0]?.split("//")[1];
    return sentryKey
      ? `https://o0.ingest.sentry.io/api/0/security/?sentry_key=${sentryKey}`
      : null;
  } catch {
    return null;
  }
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
    const sentryEndpoint = getSentryReportEndpoint();
    const headers = [
      {
        key: "Content-Security-Policy",
        value: cspHeader.replace(/\n/g, ""),
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

    // Add Reporting-Endpoints header if Sentry is configured
    if (sentryEndpoint) {
      headers.push({
        key: "Reporting-Endpoints",
        value: `csp-endpoint="${sentryEndpoint}"`,
      });
    }

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
module.exports = process.env.SENTRY_DSN
  ? withSentryConfig(nextConfig, sentryWebpackPluginOptions)
  : nextConfig;
