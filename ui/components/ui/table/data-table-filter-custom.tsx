"use client";

import { useSearchParams } from "next/navigation";
import React from "react";
import { useCallback, useMemo } from "react";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { FilterOption } from "@/types";

export interface DataTableFilterCustomProps {
  filters: FilterOption[];
}

export const DataTableFilterCustom = ({
  filters,
}: DataTableFilterCustomProps) => {
  const { updateFilter } = useUrlFilters();
  const searchParams = useSearchParams();

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

  const getSelectedValues = useCallback(
    (key: string): string[] => {
      const filterKey = key.startsWith("filter[") ? key : `filter[${key}]`;
      const paramValue = searchParams.get(filterKey);
      return paramValue ? paramValue.split(",") : [];
    },
    [searchParams],
  );

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
      {sortedFilters.map((filter) => {
        const selectedValues = getSelectedValues(filter.key);
        return (
          <Select
            key={filter.key}
            multiple
            selectedValues={selectedValues}
            onMultiValueChange={(values) =>
              pushDropdownFilter(filter.key, values)
            }
            ariaLabel={filter.labelCheckboxGroup}
          >
            <SelectTrigger size="sm">
              <SelectValue placeholder={filter.labelCheckboxGroup}>
                {selectedValues.length > 0 && (
                  <span className="truncate">
                    {selectedValues.length === 1
                      ? selectedValues[0]
                      : `${selectedValues.length} selected`}
                  </span>
                )}
              </SelectValue>
            </SelectTrigger>
            <SelectContent>
              {filter.values.map((value) => (
                <SelectItem key={value} value={value}>
                  {value}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        );
      })}
    </div>
  );
};
