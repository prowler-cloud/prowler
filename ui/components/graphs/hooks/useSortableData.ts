import { useState } from "react";

import { SORT_OPTIONS } from "../shared/chart-constants";

type SortOption = (typeof SORT_OPTIONS)[keyof typeof SORT_OPTIONS];

interface SortableItem {
  name: string;
  value: number;
}

export function useSortableData<T extends SortableItem>(data: T[]) {
  const [sortBy, setSortBy] = useState<SortOption>(SORT_OPTIONS["high-low"]);

  const sortedData = [...data].sort((a, b) => {
    switch (sortBy) {
      case SORT_OPTIONS["high-low"]:
        return b.value - a.value;
      case SORT_OPTIONS["low-high"]:
        return a.value - b.value;
      case SORT_OPTIONS.alphabetical:
        return a.name.localeCompare(b.name);
      default:
        return 0;
    }
  });

  return {
    sortBy,
    setSortBy,
    sortedData,
  };
}
