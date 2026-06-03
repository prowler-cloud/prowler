import { create } from "zustand";

import { getFlowById, getOrderedFlows } from "@/lib/onboarding";

// Distinguishes a slice-driven start ("sequence") from a param-driven replay
// ("replay"). The trigger sets "replay" when it processes a `?onboarding=` param
// so a single flow is replayed without touching the sequence.
export type OnboardingSequenceMode = "sequence" | "replay";

interface OnboardingSequenceState {
  active: boolean;
  currentFlowId: string | null;
  mode: OnboardingSequenceMode | null;

  // Begin a guided sequence at `startFlowId` (defaults to the first ordered
  // flow). Falls back to the first ordered flow when the id is unknown.
  startSequence: (startFlowId?: string) => void;
  // Move to the next ordered flow after the current one. Clears state when the
  // current flow is the last (sequence finished).
  advance: () => void;
  // End the sequence immediately (user closed a tour, or finished). Resets all.
  stop: () => void;
}

// Ephemeral, NOT persisted: persisting `active`/`currentFlowId` would resurrect
// a sequence after a hard refresh, violating "refresh mid-sequence must not
// re-fire". The slice is the transient hand-off carrier across `router.push`
// navigations within a single SPA session; durable "already saw this" memory
// stays in the per-tour localStorage `TourCompletionRecord` (untouched here).
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
      set({ active: true, currentFlowId: start.id, mode: "sequence" });
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

    stop: () => set({ active: false, currentFlowId: null, mode: null }),
  }),
);
