import { create } from "zustand";

import type { LighthouseContextItem } from "@/types/lighthouse-context";

export interface LighthouseContextStoreState {
  contributions: Record<string, LighthouseContextItem>;
  registerContribution: (
    contributorId: string,
    item: LighthouseContextItem,
  ) => void;
  removeContribution: (contributorId: string) => void;
  resetContributions: () => void;
}

export const useLighthouseContextStore = create<LighthouseContextStoreState>(
  (set) => ({
    contributions: {},
    registerContribution: (contributorId, item) =>
      set((state) => ({
        contributions: {
          ...state.contributions,
          [contributorId]: item,
        },
      })),
    removeContribution: (contributorId) =>
      set((state) => ({
        contributions: Object.fromEntries(
          Object.entries(state.contributions).filter(
            ([id]) => id !== contributorId,
          ),
        ),
      })),
    resetContributions: () => set({ contributions: {} }),
  }),
);

export function selectLighthouseContextItems(
  state: LighthouseContextStoreState,
  scopeKey: string,
): LighthouseContextItem[] {
  return Object.values(state.contributions).filter(
    (item) => item.scopeKey === scopeKey,
  );
}
