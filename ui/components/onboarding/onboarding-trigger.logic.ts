import type { TourCompletionRecord } from "@/lib/tours/tour-types";
import type { OnboardingSequenceMode } from "@/store/onboarding-sequence";

// Flat, framework-free inputs for `resolveTriggerRequest` — unit-testable without React.
export interface TriggerRequestInput {
  param: string | null; // `?onboarding=<id>` value, or null
  replayRequestFlowId: string | null; // in-memory replay request (same-route navbar), or null
  sliceActive: boolean;
  currentFlowId: string | null; // flow the active sequence points at
  flowId: string; // flow this route owns
}

// Resolved start request, or null when this route's flow should not start.
export interface TriggerRequest {
  start: true;
  mode: OnboardingSequenceMode;
}

// Replay (param or in-memory request) takes precedence over the sequence so a
// manual replay is never hijacked. The in-memory request is how the navbar starts
// a same-route replay without a `?onboarding=` URL param (which would force an RSC refetch).
export function resolveTriggerRequest({
  param,
  replayRequestFlowId,
  sliceActive,
  currentFlowId,
  flowId,
}: TriggerRequestInput): TriggerRequest | null {
  if (param === flowId) {
    return { start: true, mode: "replay" };
  }
  if (replayRequestFlowId === flowId) {
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
