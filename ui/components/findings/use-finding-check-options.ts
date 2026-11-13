"use client";

import { useState } from "react";

import { getFindingGroupCheckOptions } from "@/actions/finding-groups";
import { excludeFindingGroupOwnFilters } from "@/lib/finding-group-filter-options";

import type { FindingCheckFilterOption } from "./findings-filters.utils";

const LOAD_STATUS = {
  IDLE: "idle",
  LOADING: "loading",
  LOADED: "loaded",
} as const;

type LoadStatus = (typeof LOAD_STATUS)[keyof typeof LOAD_STATUS];

export interface FindingCheckOptionsSource {
  /** Applied filters; the check filter itself is ignored when loading options. */
  filters: Record<string, string>;
  hasHistoricalData: boolean;
  /** Titles of the checks already selected, so their chips read well before the list loads. */
  initialOptions: FindingCheckFilterOption[];
}

interface LoadState {
  /** The filters the options were loaded for; a mismatch means they are stale. */
  key: string;
  status: LoadStatus;
  options: FindingCheckFilterOption[];
}

interface UseFindingCheckOptionsParams {
  /** Undefined disables lazy loading. */
  source?: FindingCheckOptionsSource;
}

const idleState = (key: string): LoadState => ({
  key,
  status: LOAD_STATUS.IDLE,
  options: [],
});

const toFiltersKey = (filters: Record<string, string>) =>
  JSON.stringify(Object.entries(excludeFindingGroupOwnFilters(filters)).sort());

function mergeOptions(
  current: FindingCheckFilterOption[],
  incoming: FindingCheckFilterOption[],
): FindingCheckFilterOption[] {
  const byId = new Map(current.map((option) => [option.checkId, option]));
  for (const option of incoming) byId.set(option.checkId, option);
  return Array.from(byId.values());
}

/** Loads the check filter options the first time the dropdown opens. */
export function useFindingCheckOptions({
  source,
}: UseFindingCheckOptionsParams) {
  const filtersKey = source ? toFiltersKey(source.filters) : "";
  // Local state needed: options load on demand, after the first open.
  const [load, setLoad] = useState<LoadState>(() => idleState(filtersKey));
  // Derived: a load for other filters counts as nothing loaded.
  const current = load.key === filtersKey ? load : idleState(filtersKey);

  const loadAll = () => {
    if (!source || current.status !== LOAD_STATUS.IDLE) return;

    const requestKey = filtersKey;
    setLoad({ key: requestKey, status: LOAD_STATUS.LOADING, options: [] });
    getFindingGroupCheckOptions({
      filters: source.filters,
      hasHistoricalData: source.hasHistoricalData,
    })
      .then((options) => {
        setLoad((previous) =>
          previous.key === requestKey
            ? { key: requestKey, status: LOAD_STATUS.LOADED, options }
            : previous,
        );
      })
      .catch((error) => {
        console.error("Error fetching finding group filter options:", error);
        setLoad((previous) =>
          previous.key === requestKey ? idleState(requestKey) : previous,
        );
      });
  };

  return {
    options: mergeOptions(source?.initialOptions ?? [], current.options),
    isLoading: current.status === LOAD_STATUS.LOADING,
    loadAll,
  };
}
