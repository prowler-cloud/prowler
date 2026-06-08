### E2E Tests: Runtime Public-Config Data Island

**Suite ID:** `RUNTIME-CONFIG-E2E`
**Feature:** Runtime resolution of public client config via an inert JSON data
island injected into `<head>` (Sentry, GTM, API base/docs URL, reserved keys).

---

## Test Case: `RUNTIME-CONFIG-E2E-001` - Island rendered in `<head>` before the client bundle

**Priority:** `critical`
**Tags:** @e2e, @runtime-config

**Preconditions:**

- UI server running with `UI_API_BASE_URL` set (the playwright `webServer` provides it).

### Flow Steps:

1. Navigate to `/sign-in` (unauthenticated; the island renders on every route).
2. Locate `script#__PROWLER_RUNTIME_CONFIG__`.

### Expected Result:

- The island exists, is `type="application/json"` (inert), and lives in `<head>`.
- The island appears before the first external bundle `<script src>`.
- It parses as JSON exposing exactly the allowlisted keys and a truthy `apiBaseUrl`.

### Key Verification Points:

- In-`<head>`-before-bundle ordering guarantee (not provable in jsdom).
- Only the allowlisted shape is exposed (no other env leaks).

---

## Test Case: `RUNTIME-CONFIG-E2E-002` - Browser Sentry init matches the island DSN

**Priority:** `high`
**Tags:** @e2e, @runtime-config

**Preconditions:**

- UI server running. `UI_SENTRY_DSN` may be set or unset.

### Flow Steps:

1. Navigate to `/sign-in`.
2. Read `sentryDsn` from the island.
3. Read the DSN the browser Sentry client initialized with.

### Expected Result:

- If the island carries a DSN, the browser Sentry client initialized with that
  exact runtime DSN (proving the island feeds `Sentry.init` race-free).
- If the island has no DSN, Sentry is not initialized (zero egress — the default).

### Key Verification Points:

- The runtime DSN reaches module-load Sentry init via the island.
- Unset DSN ⇒ no Sentry initialization (privacy guarantee).

---

## Test Case: `RUNTIME-CONFIG-E2E-003` - Zero third-party telemetry when Sentry and GTM are unset

**Priority:** `critical`
**Tags:** @e2e, @runtime-config

**Preconditions:**

- UI server running with `UI_SENTRY_DSN` and `UI_GOOGLE_TAG_MANAGER_ID` unset (the Enterprise default; the test skips when either is configured).

### Flow Steps:

1. Navigate to `/sign-in` and read the island config.
2. Reload while recording requests to `googletagmanager.com`, `google-analytics.com`, and `sentry.io`.
3. Inspect the DOM for a Google Tag Manager script.

### Expected Result:

- No request is sent to any Google or Sentry host.
- The `GoogleTagManager` component is not rendered (no `gtm.js` script).

### Key Verification Points:

- Enterprise default sends zero error/analytics telemetry to any third party.
- Empty/unset GTM id ⇒ component not mounted (an empty id is NOT inert).
