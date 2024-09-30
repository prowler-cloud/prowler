"use client";

import { Divider } from "@nextui-org/react";
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
    <div className="flex flex-row items-center gap-4">
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
        className={`transition-all duration-500 ease-in-out ${
          showFilters
            ? "opacity-100 max-h-96 overflow-visible"
            : "opacity-0 max-h-0 overflow-hidden"
        }`}
      >
        <div className="flex flex-row gap-4">
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
          <div className="flex flex-row items-center gap-2">
            <Divider className="text-default-800 h-5" orientation="vertical" />
            <span className="text-sm text-default-800">Selected</span>
          </div>
        </div>
      </div>
    </div>
  );
};
