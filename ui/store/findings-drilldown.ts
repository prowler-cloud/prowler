import { create } from "zustand";

import { FindingGroupRow, FindingResourceRow } from "@/types";

interface FindingsDrillDownState {
  expandedCheckId: string | null;
  expandedGroup: FindingGroupRow | null;
  resources: FindingResourceRow[];
  resourcesPage: number;
  hasMoreResources: boolean;
  isLoadingResources: boolean;
  drillDown: (checkId: string, group: FindingGroupRow) => void;
  collapse: () => void;
  setResources: (resources: FindingResourceRow[], hasMore: boolean) => void;
  appendResources: (resources: FindingResourceRow[], hasMore: boolean) => void;
  setLoadingResources: (loading: boolean) => void;
  incrementPage: () => void;
}

const initialState = {
  expandedCheckId: null,
  expandedGroup: null,
  resources: [],
  resourcesPage: 1,
  hasMoreResources: false,
  isLoadingResources: false,
};

export const useFindingsDrillDownStore = create<FindingsDrillDownState>()(
  (set) => ({
    ...initialState,
    drillDown: (checkId, group) =>
      set({
        expandedCheckId: checkId,
        expandedGroup: group,
        resources: [],
        resourcesPage: 1,
        hasMoreResources: false,
        isLoadingResources: true,
      }),
    collapse: () => set(initialState),
    setResources: (resources, hasMore) =>
      set({
        resources,
        hasMoreResources: hasMore,
        isLoadingResources: false,
      }),
    appendResources: (newResources, hasMore) =>
      set((state) => ({
        resources: [...state.resources, ...newResources],
        hasMoreResources: hasMore,
        isLoadingResources: false,
      })),
    setLoadingResources: (loading) => set({ isLoadingResources: loading }),
    incrementPage: () =>
      set((state) => ({ resourcesPage: state.resourcesPage + 1 })),
  }),
);
