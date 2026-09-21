// Durable "this browser already went through the first-run redirect" memory.
// Self-hosted deployments run no tour, so no completion record would ever be
// written there; without this marker an empty tenant would be redirected on
// every page load.
const FIRST_RUN_MARKER_KEY = "prowler.onboarding.first-run";

export function isFirstRunHandled(): boolean {
  if (typeof window === "undefined") return true;
  try {
    return window.localStorage.getItem(FIRST_RUN_MARKER_KEY) !== null;
  } catch {
    // Unreadable storage must not redirect forever: treat as handled.
    return true;
  }
}

export function markFirstRunHandled(): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(FIRST_RUN_MARKER_KEY, "true");
  } catch {
    // Non-fatal: a repeated redirect beats a thrown render.
  }
}
