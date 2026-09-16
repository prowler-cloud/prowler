// Durable "this browser already saw the invite step" memory, mirroring the
// checkpoint marker: the step is offered once per tenant onboarding.
//
// The key carries the tenant, like the profile marker, because the offer is
// tenant-scoped: a user who saw it for one tenant must still see it when they
// onboard another.
const ONBOARDING_INVITE_MARKER_PREFIX = "prowler.onboarding.invite";

// Tenant ids are UUIDs; anything else is refused rather than concatenated
// into a storage key.
const TENANT_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function onboardingInviteMarkerKey(
  tenantId: string | null | undefined,
): string | null {
  if (!tenantId || !TENANT_ID_PATTERN.test(tenantId)) return null;
  return `${ONBOARDING_INVITE_MARKER_PREFIX}.${tenantId.toLowerCase()}`;
}

export function isOnboardingInviteHandled(
  tenantId: string | null | undefined,
): boolean {
  if (typeof window === "undefined") return true;
  const key = onboardingInviteMarkerKey(tenantId);
  // Without a usable tenant the step cannot be attributed to an onboarding,
  // so it is not offered rather than offered to everyone.
  if (!key) return true;
  try {
    return window.localStorage.getItem(key) !== null;
  } catch {
    // Unreadable storage must not re-open the step forever: treat as handled.
    return true;
  }
}

export function markOnboardingInviteHandled(
  tenantId: string | null | undefined,
): void {
  if (typeof window === "undefined") return;
  const key = onboardingInviteMarkerKey(tenantId);
  if (!key) return;
  try {
    window.localStorage.setItem(key, "true");
  } catch {
    // Non-fatal: a re-shown step beats a thrown render.
  }
}
