// Durable "this browser already went through the first-run redirect" memory.
// Self-hosted deployments run no tour, so no completion record would ever be
// written there; without this marker an empty tenant would be redirected on
// every page load.
//
// Scoped per tenant, like the other onboarding markers: going through the first
// run in one tenant must not silence it for another one on the same browser.
// The bare key is a browser-wide opt-out: written before markers were scoped,
// by e2e storage state, or when no usable tenant id exists.
const FIRST_RUN_MARKER_KEY = "prowler.onboarding.first-run";

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

export function isFirstRunHandled(tenantId?: string | null): boolean {
  if (typeof window === "undefined") return true;
  try {
    return (
      window.localStorage.getItem(FIRST_RUN_MARKER_KEY) !== null ||
      window.localStorage.getItem(firstRunMarkerKey(tenantId)) !== null
    );
  } catch {
    // Unreadable storage must not redirect forever: treat as handled.
    return true;
  }
}

export function markFirstRunHandled(tenantId?: string | null): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(firstRunMarkerKey(tenantId), "true");
  } catch {
    // Non-fatal: a repeated redirect beats a thrown render.
  }
}
