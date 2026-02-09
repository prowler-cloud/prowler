"use client";

import { FilterOption } from "@/types";

import { DataTableFilterCustom } from "../ui/table";
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
}

export const FilterControls = ({
  search = false,
  providers = false,
  date = false,
  regions = false,
  accounts = false,
  mutedFindings = false,
  customFilters,
}: FilterControlsProps) => {
  return (
    <div className="flex flex-col">
      <div className="mb-4 flex flex-col items-start gap-4 md:flex-row md:items-center">
        <div className="grid w-full flex-1 grid-cols-1 items-center gap-x-4 gap-y-4 md:grid-cols-2 xl:grid-cols-4">
          {search && <CustomSearchInput />}
          {providers && <CustomSelectProvider />}
          {date && <CustomDatePicker />}
          {regions && <CustomRegionSelection />}
          {accounts && <CustomAccountSelection />}
          {mutedFindings && <CustomCheckboxMutedFindings />}
        </div>
      </div>
      {customFilters && customFilters.length > 0 && (
        <>
          <DataTableFilterCustom filters={customFilters} />
        </>
      )}
    </div>
  );
};
