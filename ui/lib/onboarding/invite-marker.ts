// Durable "this browser already saw the invite step" memory, mirroring the
// checkpoint marker: the step is offered once per tenant onboarding.
export const ONBOARDING_INVITE_MARKER = "prowler.onboarding.invite";

export function isOnboardingInviteHandled(): boolean {
  if (typeof window === "undefined") return true;
  try {
    return window.localStorage.getItem(ONBOARDING_INVITE_MARKER) !== null;
  } catch {
    // Unreadable storage must not re-open the step forever: treat as handled.
    return true;
  }
}

export function markOnboardingInviteHandled(): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(ONBOARDING_INVITE_MARKER, "true");
  } catch {
    // Non-fatal: a re-shown step beats a thrown render.
  }
}
