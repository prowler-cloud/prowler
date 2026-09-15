export interface ProfileGateDecisionInput {
  // `undefined` allowed; the strict `=== false` checks below fail open on
  // ambiguous signals, like the tour gate does.
  hasProviders: boolean | undefined;
  // Whether the API already holds a profile row for the tenant (answered or
  // skipped on any device). `undefined` means the read failed.
  profileRecorded: boolean | undefined;
  // Local marker: this browser already resolved the step.
  handledLocally: boolean;
}

// Shows the profile step only for a provably new tenant that has neither a
// recorded profile nor a local marker. Any doubt keeps the step closed.
export function shouldStartOnboardingProfile({
  hasProviders,
  profileRecorded,
  handledLocally,
}: ProfileGateDecisionInput): boolean {
  return hasProviders === false && profileRecorded === false && !handledLocally;
}
