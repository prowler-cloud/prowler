"use client";

import { useRouter, useSearchParams } from "next/navigation";
import React, { useState } from "react";
import { useCallback } from "react";

import { CustomFilterIcon } from "@/components/icons";
import { CustomButton, CustomDropdownFilter } from "@/components/ui/custom";
import { FilterOption } from "@/types";

export interface DataTableFilterCustomProps {
  filters: FilterOption[];
}

export const DataTableFilterCustom = ({
  filters,
}: DataTableFilterCustomProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [showFilters, setShowFilters] = useState(false);

  const pushDropdownFilter = useCallback(
    (key: string, values: string[]) => {
      const params = new URLSearchParams(searchParams);
      const filterKey = `filter[${key}]`;

      if (values.length === 0) {
        params.delete(filterKey);
      } else {
        params.set(filterKey, values.join(","));
      }

      router.push(`?${params.toString()}`);
    },
    [router, searchParams],
  );

  return (
    <div className="flex flex-col gap-4 md:flex-row md:items-start">
      <CustomButton
        ariaLabel={showFilters ? "Hide Filters" : "Show Filters"}
        variant="flat"
        color={showFilters ? "action" : "primary"}
        size="sm"
        startContent={<CustomFilterIcon size={16} />}
        onPress={() => setShowFilters(!showFilters)}
      >
        <h3 className="text-small">
          {showFilters ? "Hide Filters" : "Show Filters"}
        </h3>
      </CustomButton>

      <div
        className={`transition-all duration-700 ease-in-out ${
          showFilters
            ? "max-h-96 w-full translate-x-0 overflow-visible opacity-100 md:max-w-80"
            : "max-h-0 -translate-x-full overflow-hidden opacity-0"
        }`}
      >
        <div className="flex flex-col gap-4 md:flex-row">
          {filters.map((filter) => (
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
