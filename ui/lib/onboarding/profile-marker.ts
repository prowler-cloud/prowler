// Durable "this browser already resolved the profile step" memory, mirroring
// the checkpoint marker. The API row is the system of record; the marker
// only spares a request and a flash of the modal on the next render.
export const ONBOARDING_PROFILE_MARKER = "prowler.onboarding.profile";

const listeners = new Set<() => void>();

export function isOnboardingProfileHandled(): boolean {
  if (typeof window === "undefined") return true;
  try {
    return window.localStorage.getItem(ONBOARDING_PROFILE_MARKER) !== null;
  } catch {
    // Unreadable storage must not re-open the step forever: treat as handled.
    return true;
  }
}

export function markOnboardingProfileHandled(): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(ONBOARDING_PROFILE_MARKER, "true");
  } catch {
    // Non-fatal: a re-shown step beats a thrown render.
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
