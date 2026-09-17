// Public barrel — import from `@/lib/onboarding`, not individual modules.

export type { GateDecisionInput } from "./gate-decision";
export { shouldStartOnboarding } from "./gate-decision";
export { isOnFlowRoute } from "./flow-route";
export type { OnboardingContext, OnboardingFlow } from "./onboarding-types";
export { getFlowById, getOrderedFlows, onboardingFlows } from "./registry";
export type {
  OnboardingInviteStepDetail,
  OnboardingProfileStepDetail,
  OnboardingStepOutcome,
} from "./onboarding-events";
export {
  dispatchOnboardingInviteStep,
  dispatchOnboardingProfileStep,
  ONBOARDING_INVITE_STEP_EVENT,
  ONBOARDING_PROFILE_STEP_EVENT,
  ONBOARDING_STEP_OUTCOME,
} from "./onboarding-events";
export type { ProfileGateDecisionInput } from "./profile-gate-decision";
export { shouldStartOnboardingProfile } from "./profile-gate-decision";
