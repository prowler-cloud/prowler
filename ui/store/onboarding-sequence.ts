import { create } from "zustand";

import { getFlowById, getOrderedFlows } from "@/lib/onboarding";

// "sequence" = slice-driven; "replay" = single-flow replay from ?onboarding= param.
export const ONBOARDING_SEQUENCE_MODES = {
  SEQUENCE: "sequence",
  REPLAY: "replay",
} as const;

export type OnboardingSequenceMode =
  (typeof ONBOARDING_SEQUENCE_MODES)[keyof typeof ONBOARDING_SEQUENCE_MODES];

interface OnboardingSequenceState {
  active: boolean;
  currentFlowId: string | null;
  mode: OnboardingSequenceMode | null;

  startSequence: (startFlowId?: string) => void;
  // Advances to next flow; clears state when the current flow is last.
  advance: () => void;
  // Jumps to a known flow. No-op for unknown ids.
  goToFlow: (flowId: string) => void;
  stop: () => void;
}

// Ephemeral, NOT persisted: persisting would resurrect sequences after refresh.
// Durable completion memory stays in the per-tour localStorage TourCompletionRecord.
export const useOnboardingSequenceStore = create<OnboardingSequenceState>(
  (set, get) => ({
    active: false,
    currentFlowId: null,
    mode: null,

    startSequence: (startFlowId) => {
      const ordered = getOrderedFlows();
      const start = startFlowId
        ? (getFlowById(startFlowId) ?? ordered[0])
        : ordered[0];
      if (!start) return;
      set({
        active: true,
        currentFlowId: start.id,
        mode: ONBOARDING_SEQUENCE_MODES.SEQUENCE,
      });
    },

    advance: () => {
      const { currentFlowId } = get();
      const ordered = getOrderedFlows();
      const idx = ordered.findIndex((flow) => flow.id === currentFlowId);
      const next = idx >= 0 ? ordered[idx + 1] : undefined;
      if (!next) {
        set({ active: false, currentFlowId: null, mode: null });
        return;
      }
      set({ currentFlowId: next.id });
    },

    goToFlow: (flowId) => {
      if (!getFlowById(flowId)) return;
      set({
        active: true,
        currentFlowId: flowId,
        mode: ONBOARDING_SEQUENCE_MODES.SEQUENCE,
      });
    },

    stop: () => set({ active: false, currentFlowId: null, mode: null }),
  }),
);
