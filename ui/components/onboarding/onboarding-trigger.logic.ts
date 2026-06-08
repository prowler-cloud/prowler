import type { TourCompletionRecord } from "@/lib/tours/tour-types";
import type { OnboardingSequenceMode } from "@/store/onboarding-sequence";

// Flat, framework-free inputs for `resolveTriggerRequest` — unit-testable without React.
export interface TriggerRequestInput {
  param: string | null; // `?onboarding=<id>` value, or null
  sliceActive: boolean;
  currentFlowId: string | null; // flow the active sequence points at
  flowId: string; // flow this route owns
}

// Resolved start request, or null when this route's flow should not start.
export interface TriggerRequest {
  start: true;
  mode: OnboardingSequenceMode;
}

// Replay param takes precedence over the sequence so manual replay is never hijacked.
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

// completed → advance the sequence; anything else → stop.
export type SequenceCloseAction = "advance" | "stop";

export function mapCloseToSequenceAction(
  state: TourCompletionRecord["state"],
): SequenceCloseAction {
  return state === "completed" ? "advance" : "stop";
}
