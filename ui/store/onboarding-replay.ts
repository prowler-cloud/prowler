import { create } from "zustand";

import { getFlowById } from "@/lib/onboarding";

interface OnboardingReplayState {
  // Flow whose replay was requested in-memory (navbar, same route), or null.
  flowId: string | null;
  // Monotonic counter bumped on every request so re-clicking the same flow
  // produces a fresh signal and the OnboardingTrigger re-mounts its runner.
  token: number;

  // Requests a replay for the given flow. No-op for unknown ids.
  requestReplay: (flowId: string) => void;
  // Clears flowId once the runner has started. Keeps token so the next request
  // still advances it.
  consume: () => void;
}

// Ephemeral, NOT persisted: a replay request must never survive a refresh.
// Same-route replays use this in-memory signal instead of a `?onboarding=` URL
// param, which would force a Next.js RSC refetch of the whole page.
export const useOnboardingReplayStore = create<OnboardingReplayState>(
  (set) => ({
    flowId: null,
    token: 0,

    requestReplay: (flowId) => {
      if (!getFlowById(flowId)) return;
      set((state) => ({ flowId, token: state.token + 1 }));
    },

    consume: () => set({ flowId: null }),
  }),
);
