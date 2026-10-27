import { create } from "zustand";

interface LighthouseLlmStoreState {
  // Last answer this page load (null: never checked), shown at once on reopen.
  hasConnectedLlm: boolean | null;
  setHasConnectedLlm: (hasConnectedLlm: boolean) => void;
}

export const useLighthouseLlmStore = create<LighthouseLlmStoreState>((set) => ({
  hasConnectedLlm: null,
  setHasConnectedLlm: (hasConnectedLlm) => set({ hasConnectedLlm }),
}));
