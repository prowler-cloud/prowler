import type { OnboardingProfileAnswers } from "@/types/onboarding-profile";

// Window events the onboarding steps dispatch when they resolve. They carry
// no listener of their own: a deployment that wants to observe the steps
// (product analytics, for instance) subscribes from outside, so the steps
// stay free of any tracking dependency.
export const ONBOARDING_PROFILE_STEP_EVENT = "prowler:onboarding-profile-step";
export const ONBOARDING_INVITE_STEP_EVENT = "prowler:onboarding-invite-step";

export const ONBOARDING_STEP_OUTCOME = {
  SHOWN: "shown",
  SUBMITTED: "submitted",
  SKIPPED: "skipped",
} as const;

export type OnboardingStepOutcome =
  (typeof ONBOARDING_STEP_OUTCOME)[keyof typeof ONBOARDING_STEP_OUTCOME];

interface OnboardingProfileStepSubmitted {
  outcome: typeof ONBOARDING_STEP_OUTCOME.SUBMITTED;
  // The stored answers, so a listener never has to read them back.
  answers: OnboardingProfileAnswers;
}

interface OnboardingProfileStepResolved {
  outcome:
    | typeof ONBOARDING_STEP_OUTCOME.SHOWN
    | typeof ONBOARDING_STEP_OUTCOME.SKIPPED;
  answers?: never;
}

// A union rather than an optional field: only a submitted step carries the
// answers, so a listener that narrows on `outcome` gets them without a check.
export type OnboardingProfileStepDetail =
  | OnboardingProfileStepSubmitted
  | OnboardingProfileStepResolved;

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

export function dispatchOnboardingProfileStep(
  detail: OnboardingProfileStepDetail,
): void {
  dispatch(ONBOARDING_PROFILE_STEP_EVENT, detail);
}

export function dispatchOnboardingInviteStep(
  detail: OnboardingInviteStepDetail,
): void {
  dispatch(ONBOARDING_INVITE_STEP_EVENT, detail);
}
