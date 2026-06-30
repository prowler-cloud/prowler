import {
  getOrderedFlows,
  type OnboardingFlow,
  onboardingFlows,
} from "@/lib/onboarding";

// Framework-free projection of the active sequence position — unit-testable without React.
export interface SequenceProgress {
  index: number; // 0-based
  total: number;
  flow: OnboardingFlow;
  nextFlow: OnboardingFlow | null; // null when on the last step
}

// Returns null when `currentFlowId` is absent or not in the registry.
export function getSequenceProgress(
  currentFlowId: string | null,
  flows: readonly OnboardingFlow[] = onboardingFlows,
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
