"use client";

import { useSearchParams } from "next/navigation";

import {
  Select,
  SelectAllItem,
  SelectContent,
  SelectItem,
  SelectSeparator,
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
  const sortedFilters = () => {
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
  };

  const pushDropdownFilter = (filter: FilterOption, values: string[]) => {
    // If this filter defaults to "all selected" and the user selected all items,
    // clear the URL param to represent "no specific filter" (i.e., all).
    const allSelected =
      filter.values.length > 0 && values.length === filter.values.length;

    if (filter.defaultToSelectAll && allSelected) {
      updateFilter(filter.key, null);
      return;
    }

    updateFilter(filter.key, values.length > 0 ? values : null);
  };

  const getSelectedValues = (key: string): string[] => {
    const filterKey = key.startsWith("filter[") ? key : `filter[${key}]`;
    const paramValue = searchParams.get(filterKey);
    return paramValue ? paramValue.split(",") : [];
  };

  return (
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5">
      {sortedFilters()
        .filter((filter) => filter.values.length > 1)
        .map((filter) => {
          const selectedValues = getSelectedValues(filter.key);

          return (
            <Select
              key={filter.key}
              multiple
              selectedValues={selectedValues}
              onMultiValueChange={(values) =>
                pushDropdownFilter(filter, values)
              }
              ariaLabel={filter.labelCheckboxGroup}
            >
              <SelectTrigger size="default">
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
                <SelectAllItem allValues={filter.values}>
                  Select All
                </SelectAllItem>
                <SelectSeparator />
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
