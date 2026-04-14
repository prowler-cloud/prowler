"use client";

import { FilterOption } from "@/types";

import { DataTableFilterCustom } from "../ui/table";
import { CustomSearchInput } from "./custom-search-input";

export interface FilterControlsProps {
  search?: boolean;
  customFilters?: FilterOption[];
  /** Element rendered at the start of the filter grid (e.g. an active-filter chip) */
  prependElement?: React.ReactNode;
}

export const FilterControls = ({
  search = false,
  customFilters,
  prependElement,
}: FilterControlsProps) => {
  return (
    <div className="flex flex-col">
      <div className="mb-4 flex flex-col items-start gap-4 md:flex-row md:items-center">
        <div className="grid w-full flex-1 grid-cols-1 items-center gap-x-4 gap-y-4 md:grid-cols-2 xl:grid-cols-4">
          {search && <CustomSearchInput />}
        </div>
      </div>
      {customFilters && customFilters.length > 0 && (
        <>
          <DataTableFilterCustom
            filters={customFilters}
            prependElement={prependElement}
          />
        </>
      )}
    </div>
  );
};
