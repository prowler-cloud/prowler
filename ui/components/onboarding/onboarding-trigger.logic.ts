import type { TourCompletionRecord } from "@/lib/tours/tour-types";
import type { OnboardingSequenceMode } from "@/store/onboarding-sequence";

// Inputs the generalized `OnboardingTrigger` reads to decide whether THIS
// route's flow should force-start. Flat args keep the decision framework-free
// and unit-testable in isolation from the React component.
export interface TriggerRequestInput {
  // The `?onboarding=<id>` query param value, or null when absent.
  param: string | null;
  sliceActive: boolean;
  // The flow id the active sequence points at, or null.
  currentFlowId: string | null;
  // The id of the flow THIS route owns.
  flowId: string;
}

// The resolved start request, or null when this route's flow should not start.
export interface TriggerRequest {
  start: true;
  mode: OnboardingSequenceMode;
}

// Decides whether (and how) to force-start this route's flow. Replay (the
// param) takes documented precedence over the sequence so a manual list replay
// never gets hijacked by an in-flight sequence. Returns null when neither
// source names this flow.
export function resolveTriggerRequest({
  param,
  sliceActive,
  currentFlowId,
  flowId,
}: TriggerRequestInput): TriggerRequest | null {
  if (param === flowId) {
    return { start: true, mode: "replay" };
  }
  if (sliceActive && currentFlowId === flowId) {
    return { start: true, mode: "sequence" };
  }
  return null;
}

// The action a sequence-driven trigger takes once its tour closes. Last-step
// completion advances the sequence; any user-close (skip/dismiss) ends it.
export type SequenceCloseAction = "advance" | "stop";

export function mapCloseToSequenceAction(
  state: TourCompletionRecord["state"],
): SequenceCloseAction {
  return state === "completed" ? "advance" : "stop";
}
