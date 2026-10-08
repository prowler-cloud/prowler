// Durable "this browser already went through the first-run redirect" memory.
// Self-hosted deployments run no tour, so no completion record would ever be
// written there; without this marker an empty tenant would be redirected on
// every page load.
//
// The first run is resolved when the add-provider wizard actually opens, not
// when the redirect is issued: a navigation cut short (a second login, a tab
// closed mid-flight) must be retried on the next load. Each redirect counts as
// an attempt; after a few attempts that never reached the wizard the marker
// resolves anyway, so a browser can never be trapped in the redirect.
//
// Scoped per tenant, like the other onboarding markers: going through the first
// run in one tenant must not silence it for another one on the same browser.
// The bare key is a browser-wide opt-out: written before markers were scoped,
// by e2e storage state, or when no usable tenant id exists.
const FIRST_RUN_MARKER_KEY = "prowler.onboarding.first-run";
const HANDLED_VALUE = "true";

export const FIRST_RUN_MAX_ATTEMPTS = 3;

// Tenant ids are UUIDs; anything else is refused rather than concatenated
// into a storage key.
const TENANT_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function firstRunMarkerKey(tenantId?: string | null): string {
  if (!tenantId || !TENANT_ID_PATTERN.test(tenantId)) {
    return FIRST_RUN_MARKER_KEY;
  }
  return `${FIRST_RUN_MARKER_KEY}.${tenantId.toLowerCase()}`;
}

// A stored value is either an attempt count (digits only) or `HANDLED_VALUE`;
// anything else (a legacy or hand-written marker) is read as resolved.
const ATTEMPT_COUNT_PATTERN = /^\d+$/;

function readAttempts(value: string | null): number | null {
  if (value === null) return 0;
  return ATTEMPT_COUNT_PATTERN.test(value) ? Number(value) : null;
}

export function isFirstRunHandled(tenantId?: string | null): boolean {
  if (typeof window === "undefined") return true;
  try {
    // The bare key opts the whole browser out, unless it merely holds the
    // attempt count of a deployment that mounts the gate without a tenant id.
    const bareAttempts = readAttempts(
      window.localStorage.getItem(FIRST_RUN_MARKER_KEY),
    );
    if (bareAttempts === null) return true;
    const attempts = readAttempts(
      window.localStorage.getItem(firstRunMarkerKey(tenantId)),
    );
    return attempts === null || attempts >= FIRST_RUN_MAX_ATTEMPTS;
  } catch {
    // Unreadable storage must not redirect forever: treat as handled.
    return true;
  }
}

export function recordFirstRunAttempt(tenantId?: string | null): void {
  if (typeof window === "undefined") return;
  try {
    const key = firstRunMarkerKey(tenantId);
    const attempts = readAttempts(window.localStorage.getItem(key));
    if (attempts === null) return;
    window.localStorage.setItem(key, String(attempts + 1));
  } catch {
    // Non-fatal: a repeated redirect beats a thrown render.
  }
}

export function markFirstRunHandled(tenantId?: string | null): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(firstRunMarkerKey(tenantId), HANDLED_VALUE);
  } catch {
    // Non-fatal: a repeated redirect beats a thrown render.
  }
}
