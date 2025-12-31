/**
 * @fileoverview Next.js Configuration for Prowler UI
 *
 * This configuration file defines the Next.js settings for the Prowler UI application,
 * including security headers, Sentry integration, and experimental features.
 *
 * @module next.config
 * @see {@link https://nextjs.org/docs/app/api-reference/next-config-js} Next.js Configuration Reference
 *
 * ## Features Configured
 *
 * - **Security Headers**: Content Security Policy (CSP), X-Content-Type-Options, Referrer-Policy
 * - **Sentry Integration**: Error tracking and monitoring with source map uploads
 * - **Server Actions**: Extended body size limit (1GB) for scan file imports
 * - **Standalone Output**: Production builds use standalone mode for containerized deployments
 * - **React Compiler**: Experimental React compiler for optimized builds
 * - **Turbopack**: Fast bundler configuration for development
 *
 * ## Environment Variables
 *
 * | Variable | Required | Description |
 * |----------|----------|-------------|
 * | `NEXT_PUBLIC_SENTRY_DSN` | No | Sentry DSN for client-side error reporting |
 * | `SENTRY_DSN` | No | Sentry DSN for server-side error reporting |
 * | `SENTRY_ORG` | No | Sentry organization slug |
 * | `SENTRY_PROJECT` | No | Sentry project slug |
 * | `SENTRY_AUTH_TOKEN` | No | Sentry auth token for source map uploads |
 * | `NODE_ENV` | No | Environment mode (development/production) |
 * | `CI` | No | Set in CI environments to disable standalone output |
 *
 * ## Usage
 *
 * This file is automatically loaded by Next.js. No manual import is required.
 *
 * @example
 * // The config is used automatically by Next.js CLI commands:
 * // Development: pnpm run dev
 * // Production build: pnpm run build
 * // Production start: pnpm start
 */

const dotenv = require("dotenv");
const dotenvExpand = require("dotenv-expand");
dotenvExpand.expand(dotenv.config({ path: "../.env", quiet: true }));
const { withSentryConfig } = require("@sentry/nextjs");

/** @type {import('next').NextConfig} */

/**
 * Content Security Policy (CSP) header configuration.
 *
 * Defines allowed sources for various resource types to prevent XSS attacks
 * and other code injection vulnerabilities.
 *
 * @constant {string}
 *
 * @description
 * CSP Directives configured:
 * - `default-src 'self'`: Default fallback for all resource types
 * - `script-src`: Allows scripts from self, inline, eval (dev), Stripe, GTM, Sentry
 * - `connect-src`: Allows connections to Iconify APIs, Stripe, GTM, Sentry
 * - `img-src`: Allows images from self, Google Analytics, GTM
 * - `font-src`: Allows fonts from self only
 * - `style-src`: Allows styles from self and inline styles
 * - `frame-src`: Allows frames from self, Stripe, GTM
 * - `frame-ancestors 'none'`: Prevents embedding in iframes (clickjacking protection)
 * - `report-to csp-endpoint`: Reports violations to Sentry (if configured)
 *
 * @note 'unsafe-eval' is required by Next.js in development mode for hot reloading
 *
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP} MDN CSP Reference
 */
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

/**
 * Extracts the Sentry CSP report endpoint URL from the DSN.
 *
 * Parses the Sentry DSN to construct the security report endpoint URL,
 * which is used for CSP violation reporting via the Reporting API.
 *
 * @function getSentryReportEndpoint
 * @returns {string|null} The Sentry CSP report endpoint URL, or null if DSN is not configured
 *
 * @example
 * // With NEXT_PUBLIC_SENTRY_DSN="https://abc123@o123456.ingest.sentry.io/789"
 * getSentryReportEndpoint();
 * // Returns: "https://o0.ingest.sentry.io/api/0/security/?sentry_key=abc123"
 *
 * @example
 * // Without NEXT_PUBLIC_SENTRY_DSN configured
 * getSentryReportEndpoint();
 * // Returns: null
 */
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

/**
 * Main Next.js configuration object.
 *
 * @type {import('next').NextConfig}
 *
 * @property {boolean} poweredByHeader - Disabled to hide X-Powered-By header (security)
 * @property {string} [output] - Set to "standalone" in production for Docker deployments
 * @property {string} [outputFileTracingRoot] - Root directory for file tracing in standalone mode
 * @property {Object} experimental - Experimental Next.js features
 * @property {boolean} experimental.reactCompiler - Enables React compiler for optimizations
 * @property {Object} experimental.serverActions - Server actions configuration
 * @property {string} experimental.serverActions.bodySizeLimit - Max request body size (50MB for scan imports)
 * @property {Object} turbopack - Turbopack bundler configuration
 * @property {string} turbopack.root - Root directory for Turbopack
 * @property {Function} headers - Async function returning security headers configuration
 */
const nextConfig = {
  poweredByHeader: false,
  // Use standalone only in production deployments, not for CI/testing
  ...(process.env.NODE_ENV === "production" &&
    !process.env.CI && {
      output: "standalone",
      outputFileTracingRoot: __dirname,
    }),
  experimental: {
    reactCompiler: true,
    /**
     * Server Actions configuration for handling large file uploads.
     *
     * The default Next.js body size limit for server actions is 1MB, which is
     * insufficient for importing scan result files (OCSF JSON or CSV format).
     * This limit is increased to 1GB to match the backend API's file size
     * validation limit, allowing users to import large scan files containing
     * thousands of findings.
     *
     * @see ui/actions/scans/import-scan.ts - Server action that handles scan imports
     * @see api/src/backend/api/v1/serializers.py - Backend validation (max 1GB)
     */
    serverActions: {
      bodySizeLimit: "1gb",
    },
  },
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
