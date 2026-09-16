// Durable "this browser already resolved the profile step" memory, mirroring
// the checkpoint marker. The API row is the system of record; the marker only
// spares a flash of the modal before the server answer catches up.
//
// The key carries the tenant because eligibility is tenant-scoped: a user who
// answered for one tenant must still be asked when they switch to a new one.
const ONBOARDING_PROFILE_MARKER_PREFIX = "prowler.onboarding.profile";

const listeners = new Set<() => void>();

// Tenant ids are UUIDs; anything else is refused rather than concatenated
// into a storage key.
const TENANT_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function onboardingProfileMarkerKey(
  tenantId: string | null | undefined,
): string | null {
  if (!tenantId || !TENANT_ID_PATTERN.test(tenantId)) return null;
  return `${ONBOARDING_PROFILE_MARKER_PREFIX}.${tenantId.toLowerCase()}`;
}

export function isOnboardingProfileHandled(
  tenantId: string | null | undefined,
): boolean {
  if (typeof window === "undefined") return true;
  const key = onboardingProfileMarkerKey(tenantId);
  // Without a usable tenant the local memory cannot be trusted; the
  // server-side answer decides on its own.
  if (!key) return false;
  try {
    return window.localStorage.getItem(key) !== null;
  } catch {
    // Unreadable storage must not re-open the step forever: treat as handled.
    return true;
  }
}

export function markOnboardingProfileHandled(
  tenantId: string | null | undefined,
): void {
  if (typeof window === "undefined") return;
  const key = onboardingProfileMarkerKey(tenantId);
  if (key) {
    try {
      window.localStorage.setItem(key, "true");
    } catch {
      // Non-fatal: a re-shown step beats a thrown render.
    }
  }
  listeners.forEach((listener) => listener());
}

// For `useSyncExternalStore`: the marker only changes through
// `markOnboardingProfileHandled`, so that is the only notification source.
export function subscribeOnboardingProfileMarker(
  listener: () => void,
): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

// Server render and the hydration pass see the step as handled so the modal
// never flashes before the client can read storage.
export const getServerOnboardingProfileHandled = () => true;
