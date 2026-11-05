import { create } from "zustand";

import { isSampleId } from "@/lib/sample-preview/sample-guards";
import type { LighthouseContextItem } from "@/types/lighthouse-context";

// Sample records exist only in the UI; Lighthouse would look them up in vain.
const withoutSample = (item: LighthouseContextItem | null) =>
  item && isSampleId(item.id) ? null : item;

const omitContribution = (
  contributions: Record<string, LighthouseContextItem>,
  contributorId: string,
) =>
  Object.fromEntries(
    Object.entries(contributions).filter(([id]) => id !== contributorId),
  );

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
        contributions: isSampleId(item.id)
          ? omitContribution(state.contributions, contributorId)
          : { ...state.contributions, [contributorId]: item },
      })),
    removeContribution: (contributorId) =>
      set((state) => ({
        contributions: omitContribution(state.contributions, contributorId),
      })),
    setFocusedContext: (ownerToken, focused) =>
      set((state) =>
        ownerToken >= state.focusedOwnerToken
          ? { focused: withoutSample(focused), focusedOwnerToken: ownerToken }
          : state,
      ),
    clearFocusedContext: (ownerToken) =>
      set((state) =>
        state.focusedOwnerToken === ownerToken ? { focused: null } : state,
      ),
  }),
);
