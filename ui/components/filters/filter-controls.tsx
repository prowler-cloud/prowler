"use client";

import { Spacer } from "@nextui-org/react";
import { useSearchParams } from "next/navigation";
import React, { useEffect, useState } from "react";

import { FilterOption } from "@/types";

import { DataTableFilterCustom } from "../ui/table";
import { ClearFiltersButton } from "./clear-filters-button";
import { CustomAccountSelection } from "./custom-account-selection";
import { CustomCheckboxMutedFindings } from "./custom-checkbox-muted-findings";
import { CustomDatePicker } from "./custom-date-picker";
import { CustomRegionSelection } from "./custom-region-selection";
import { CustomSearchInput } from "./custom-search-input";
import { CustomSelectProvider } from "./custom-select-provider";

export interface FilterControlsProps {
  search?: boolean;
  providers?: boolean;
  date?: boolean;
  regions?: boolean;
  accounts?: boolean;
  mutedFindings?: boolean;
  customFilters?: FilterOption[];
  showClearButton?: boolean;
}

export const FilterControls: React.FC<FilterControlsProps> = ({
  search = false,
  providers = false,
  date = false,
  regions = false,
  accounts = false,
  mutedFindings = false,
  showClearButton = true,
  customFilters,
}) => {
  const searchParams = useSearchParams();
  const [hasFilters, setHasFilters] = useState(false);

  useEffect(() => {
    const hasFilters = Array.from(searchParams.keys()).some(
      (key) => key.startsWith("filter[") || key === "sort",
    );
    setHasFilters(hasFilters);
  }, [searchParams]);

  return (
    <div className="flex flex-col">
      <div className="grid grid-cols-1 items-center gap-x-4 gap-y-4 md:grid-cols-2 xl:grid-cols-4">
        {search && <CustomSearchInput />}
        {providers && <CustomSelectProvider />}
        {date && <CustomDatePicker />}
        {regions && <CustomRegionSelection />}
        {accounts && <CustomAccountSelection />}
        {mutedFindings && <CustomCheckboxMutedFindings />}
        {!customFilters && hasFilters && showClearButton && (
          <ClearFiltersButton />
        )}
      </div>
      <Spacer y={8} />
      {customFilters && (
        <DataTableFilterCustom
          filters={customFilters}
          showClearButton={showClearButton}
          defaultOpen
        />
      )}
    </div>
  );
};
