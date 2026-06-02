import { getOrderedFlows, type OnboardingFlow } from "@/lib/onboarding";

// Pure projection of the active sequence's position, derived entirely from the
// registry. Keeping this framework-free makes the banner's progress + advance
// logic unit-testable without React or the Zustand store.
export interface SequenceProgress {
  // 0-based index of the current flow within the ordered registry.
  index: number;
  // Total number of ordered flows in the sequence.
  total: number;
  // The flow the sequence currently points at.
  flow: OnboardingFlow;
  // The next ordered flow, or null when the current flow is the last step.
  nextFlow: OnboardingFlow | null;
}

// Resolves the sequence position for `currentFlowId` against the ordered
// registry. Returns null when there is no active flow id or the id is unknown,
// so callers can render nothing without special-casing.
export function getSequenceProgress(
  currentFlowId: string | null,
  flows: readonly OnboardingFlow[] = getOrderedFlows(),
): SequenceProgress | null {
  if (!currentFlowId) return null;

  const ordered = getOrderedFlows(flows);
  const index = ordered.findIndex((flow) => flow.id === currentFlowId);
  if (index < 0) return null;

  return {
    index,
    total: ordered.length,
    flow: ordered[index],
    nextFlow: ordered[index + 1] ?? null,
  };
}
