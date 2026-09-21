// Window events the onboarding steps dispatch when they resolve. They carry
// no listener of their own: a deployment that wants to observe the steps
// (product analytics, for instance) subscribes from outside, so the steps
// stay free of any tracking dependency.
export const ONBOARDING_INVITE_STEP_EVENT = "prowler:onboarding-invite-step";

export const ONBOARDING_STEP_OUTCOME = {
  SHOWN: "shown",
  SUBMITTED: "submitted",
  SKIPPED: "skipped",
} as const;

export type OnboardingStepOutcome =
  (typeof ONBOARDING_STEP_OUTCOME)[keyof typeof ONBOARDING_STEP_OUTCOME];

export interface OnboardingInviteStepDetail {
  outcome: OnboardingStepOutcome;
}

function dispatch<Detail>(name: string, detail: Detail): void {
  if (typeof window === "undefined") return;
  try {
    window.dispatchEvent(new CustomEvent<Detail>(name, { detail }));
  } catch {
    // A listener that throws must never break the step that resolved.
  }
}

export function dispatchOnboardingInviteStep(
  detail: OnboardingInviteStepDetail,
): void {
  dispatch(ONBOARDING_INVITE_STEP_EVENT, detail);
}
