// Public barrel — import from `@/lib/onboarding`, not individual modules.

export type { GateDecisionInput } from "./gate-decision";
export { shouldStartOnboarding } from "./gate-decision";
export { isOnFlowRoute } from "./flow-route";
export type { OnboardingContext, OnboardingFlow } from "./onboarding-types";
export { getFlowById, getOrderedFlows, onboardingFlows } from "./registry";
