import { useState } from "react";

import { DEFAULT_SORT_OPTION, SORT_OPTIONS } from "../shared/constants";

type SortOption = (typeof SORT_OPTIONS)[keyof typeof SORT_OPTIONS];

interface SortableItem {
  name: string;
  value: number;
}

export function useSortableData<T extends SortableItem>(data: T[]) {
  const [sortBy, setSortBy] = useState<SortOption>(DEFAULT_SORT_OPTION);

  const sortedData = [...data].sort((a, b) => {
    switch (sortBy) {
      case SORT_OPTIONS.highLow:
        return b.value - a.value;
      case SORT_OPTIONS.lowHigh:
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
