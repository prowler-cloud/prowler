"use client";

import { useRef, useState } from "react";

import {
  getFindingGroups,
  getLatestFindingGroups,
} from "@/actions/finding-groups";
import {
  excludeFindingGroupOwnFilters,
  getFindingGroupFilterOptions,
} from "@/lib/finding-group-filter-options";

import type { FindingCheckFilterOption } from "./findings-filters.utils";

const LOAD_STATUS = {
  IDLE: "idle",
  LOADING: "loading",
  LOADED: "loaded",
} as const;

type LoadStatus = (typeof LOAD_STATUS)[keyof typeof LOAD_STATUS];

export interface FindingCheckOptionsSource {
  filters: Record<string, string | string[] | undefined>;
  hasHistoricalData: boolean;
  /** Titles of the checks already selected, so their chips read well before the list loads. */
  initialOptions: FindingCheckFilterOption[];
}

interface UseFindingCheckOptionsParams {
  /** Undefined disables lazy loading. */
  source?: FindingCheckOptionsSource;
}

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
  const filtersKey = source
    ? JSON.stringify(excludeFindingGroupOwnFilters(source.filters))
    : "";
  const filtersKeyRef = useRef(filtersKey);
  filtersKeyRef.current = filtersKey;

  const [loadedOptions, setLoadedOptions] = useState<
    FindingCheckFilterOption[]
  >([]);
  const [status, setStatus] = useState<LoadStatus>(LOAD_STATUS.IDLE);
  const [loadedFor, setLoadedFor] = useState(filtersKey);

  if (loadedFor !== filtersKey) {
    setLoadedFor(filtersKey);
    setLoadedOptions([]);
    setStatus(LOAD_STATUS.IDLE);
  }

  const loadAll = () => {
    if (!source || status !== LOAD_STATUS.IDLE) return;

    const requestKey = filtersKey;
    setStatus(LOAD_STATUS.LOADING);
    getFindingGroupFilterOptions({
      fetchFindingGroups: source.hasHistoricalData
        ? getFindingGroups
        : getLatestFindingGroups,
      filters: source.filters,
    })
      .then((options) => {
        if (requestKey !== filtersKeyRef.current) return;
        setLoadedOptions(options);
        setStatus(LOAD_STATUS.LOADED);
      })
      .catch((error) => {
        if (requestKey !== filtersKeyRef.current) return;
        console.error("Error fetching finding group filter options:", error);
        setStatus(LOAD_STATUS.IDLE);
      });
  };

  return {
    options: mergeOptions(source?.initialOptions ?? [], loadedOptions),
    isLoading: status === LOAD_STATUS.LOADING,
    loadAll,
  };
}
