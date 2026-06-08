# Sentry Error Tracking Configuration

This folder contains all Sentry-related configuration and utilities for the Prowler UI.

## Files

- `sentry.server.config.ts` - Server-side error tracking configuration
- `sentry.edge.config.ts` - Edge runtime error tracking configuration
- `utils.ts` - Enums for standardized error types and sources
- `index.ts` - Main export file

## Client Configuration

The client-side configuration lives in the Next.js convention file
`instrumentation-client.ts` (repo root). It runs before hydration and reads the
DSN/environment from the runtime data island injected into `<head>` (see
`lib/runtime-config.ts`), so the browser SDK is configured per deployment from
the container environment rather than from build-time `NEXT_PUBLIC_*` vars.

## Usage

```typescript
// Import Sentry enums for error categorization
import { SentryErrorType, SentryErrorSource } from "@/sentry";

// Use in error handling
Sentry.captureException(error, {
  tags: {
    error_type: SentryErrorType.SERVER_ERROR,
    error_source: SentryErrorSource.API_ROUTE,
  },
});
```

## Environment Variables

Runtime environment variables (supplied to the running container; a single
`UI_SENTRY_DSN` / `UI_SENTRY_ENVIRONMENT` now serves both server and
browser):

```env
UI_SENTRY_DSN=https://YOUR_KEY@o0.ingest.sentry.io/0
UI_SENTRY_ENVIRONMENT=production
```

Build-time only (for source-map upload via `withSentryConfig`):

```env
SENTRY_ORG=your-org-slug
SENTRY_PROJECT=your-project-slug
SENTRY_AUTH_TOKEN=sntrys_YOUR_AUTH_TOKEN
```

## Ignored Errors

The following errors are intentionally ignored as they are expected behavior:

- `NEXT_REDIRECT` - Next.js redirect mechanism
- `NEXT_NOT_FOUND` - Next.js 404 handling
- `401` - Unauthorized (expected when token expires)
- `403` - Forbidden (expected for permission checks)
- `404` - Not Found (expected for missing resources)
