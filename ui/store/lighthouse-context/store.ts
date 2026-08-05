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
      set((state) =>
        ownerToken >= state.focusedOwnerToken
          ? { focused, focusedOwnerToken: ownerToken }
          : state,
      ),
    clearFocusedContext: (ownerToken) =>
      set((state) =>
        state.focusedOwnerToken === ownerToken ? { focused: null } : state,
      ),
  }),
);
