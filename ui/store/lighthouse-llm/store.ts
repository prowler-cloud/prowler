import { create } from "zustand";

interface LighthouseLlmStoreState {
  // Last answer this page load (null: never checked), shown at once on reopen.
  hasConnectedLlm: boolean | null;
  // Id of the newest check: an older check that answers late is ignored.
  latestCheck: number;
  startCheck: () => number;
  settleCheck: (check: number, hasConnectedLlm: boolean) => void;
}

export const useLighthouseLlmStore = create<LighthouseLlmStoreState>(
  (set, get) => ({
    hasConnectedLlm: null,
    latestCheck: 0,
    startCheck: () => {
      const check = get().latestCheck + 1;
      set({ latestCheck: check });
      return check;
    },
    settleCheck: (check, hasConnectedLlm) => {
      if (check === get().latestCheck) set({ hasConnectedLlm });
    },
  }),
);
