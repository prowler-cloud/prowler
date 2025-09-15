# Sentry Error Tracking Configuration

This folder contains all Sentry-related configuration and utilities for the Prowler UI.

## Files

- `sentry.server.config.ts` - Server-side error tracking configuration
- `sentry.edge.config.ts` - Edge runtime error tracking configuration  
- `utils.ts` - Utility functions for Sentry integration
- `index.ts` - Main export file

## Client Configuration

The client-side configuration is located in `app/instrumentation.client.ts` following Next.js conventions.

## Usage

```typescript
// Import Sentry utilities
import { setSentryUser, addBreadcrumb, withSentry } from "@/sentry";

// Set user context after login
await setSentryUser();

// Add breadcrumbs for user actions
addBreadcrumb("User clicked button", "ui.click");

// Wrap server actions with error tracking
const trackedAction = await withSentry(myServerAction, "myServerAction");
```

## Environment Variables

Required environment variables (add to `.env`):

```env
SENTRY_DSN=https://YOUR_KEY@o0.ingest.sentry.io/0
NEXT_PUBLIC_SENTRY_DSN=https://YOUR_KEY@o0.ingest.sentry.io/0
SENTRY_ORG=your-org-slug
SENTRY_PROJECT=your-project-slug
SENTRY_AUTH_TOKEN=sntrys_YOUR_AUTH_TOKEN
SENTRY_ENVIRONMENT=development
NEXT_PUBLIC_SENTRY_ENVIRONMENT=development
```

## Ignored Errors

The following errors are intentionally ignored as they are expected behavior:
- `NEXT_REDIRECT` - Next.js redirect mechanism
- `NEXT_NOT_FOUND` - Next.js 404 handling
- `401` - Unauthorized (expected when token expires)
- `403` - Forbidden (expected for permission checks)
- `404` - Not Found (expected for missing resources)