import { create } from "zustand";

import type { LighthouseContextItem } from "@/types/lighthouse-context";

export interface LighthouseContextStoreState {
  contributions: Record<string, LighthouseContextItem>;
  focused: LighthouseContextItem | null;
  focusedOwnerToken: number;
  registerContribution: (
    contributorId: string,
    item: LighthouseContextItem,
  ) => void;
  removeContribution: (contributorId: string) => void;
  setFocusedContext: (
    ownerToken: number,
    item: LighthouseContextItem | null,
  ) => void;
  clearFocusedContext: (ownerToken: number) => void;
  resetContributions: () => void;
}

export const useLighthouseContextStore = create<LighthouseContextStoreState>(
  (set) => ({
    contributions: {},
    focused: null,
    focusedOwnerToken: 0,
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
    setFocusedContext: (ownerToken, focused) =>
      set({ focused, focusedOwnerToken: ownerToken }),
    clearFocusedContext: (ownerToken) =>
      set((state) =>
        state.focusedOwnerToken === ownerToken
          ? { focused: null, focusedOwnerToken: 0 }
          : state,
      ),
    resetContributions: () =>
      set({ contributions: {}, focused: null, focusedOwnerToken: 0 }),
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
