"use client";

import React, { useState } from "react";
import { useCallback, useMemo } from "react";

import { CustomFilterIcon } from "@/components/icons";
import { CustomButton, CustomDropdownFilter } from "@/components/ui/custom";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { FilterOption } from "@/types";

export interface DataTableFilterCustomProps {
  filters: FilterOption[];
  defaultOpen?: boolean;
}

export const DataTableFilterCustom = ({
  filters,
  defaultOpen = false,
}: DataTableFilterCustomProps) => {
  const { updateFilter } = useUrlFilters();
  const [showFilters, setShowFilters] = useState(defaultOpen);

  // Sort filters by index property, with fallback to original order for filters without index
  const sortedFilters = useMemo(() => {
    return [...filters].sort((a, b) => {
      // If both have index, sort by index
      if (a.index !== undefined && b.index !== undefined) {
        return a.index - b.index;
      }
      // If only one has index, prioritize the one with index
      if (a.index !== undefined) return -1;
      if (b.index !== undefined) return 1;
      // If neither has index, maintain original order
      return 0;
    });
  }, [filters]);

  const pushDropdownFilter = useCallback(
    (key: string, values: string[]) => {
      updateFilter(key, values.length > 0 ? values : null);
    },
    [updateFilter],
  );

  return (
    <div
      className={`flex ${
        sortedFilters.length > 4 ? "flex-col" : "flex-col md:flex-row"
      } gap-4`}
    >
      <CustomButton
        ariaLabel={showFilters ? "Hide Filters" : "Show Filters"}
        variant="flat"
        color={showFilters ? "action" : "primary"}
        size="md"
        startContent={<CustomFilterIcon size={16} />}
        onPress={() => setShowFilters(!showFilters)}
        className="w-full max-w-fit"
      >
        <h3 className="text-small">
          {showFilters ? "Hide Filters" : "Show Filters"}
        </h3>
      </CustomButton>

      <div
        className={`transition-all duration-700 ease-in-out ${
          showFilters
            ? "max-h-96 w-full translate-x-0 overflow-visible opacity-100"
            : "max-h-0 -translate-x-full overflow-hidden opacity-0"
        }`}
      >
        <div
          className={`grid gap-4 ${
            sortedFilters.length >= 4
              ? "grid-cols-1 md:grid-cols-4"
              : "grid-cols-1 md:grid-cols-3"
          }`}
        >
          {sortedFilters.map((filter) => (
            <CustomDropdownFilter
              key={filter.key}
              filter={{
                ...filter,
                labelCheckboxGroup: filter.labelCheckboxGroup,
              }}
              onFilterChange={pushDropdownFilter}
            />
          ))}
        </div>
      </div>
    </div>
  );
};
