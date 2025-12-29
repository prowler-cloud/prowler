"use client";

import { Spacer } from "@heroui/spacer";
import { ChevronDown, ChevronUp } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/shadcn";
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
  /** Whether to show the toggle button for expanding/collapsing custom filters */
  showToggle?: boolean;
  /** Initial expanded state for custom filters (default: false) */
  defaultExpanded?: boolean;
}

export const FilterControls = ({
  search = false,
  providers = false,
  date = false,
  regions = false,
  accounts = false,
  mutedFindings = false,
  customFilters,
  showToggle = false,
  defaultExpanded = false,
}: FilterControlsProps) => {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);

  const hasCustomFilters = customFilters && customFilters.length > 0;
  const shouldShowCustomFilters =
    hasCustomFilters && (!showToggle || isExpanded);

  return (
    <div className="flex flex-col">
      <div className="flex flex-col items-start gap-4 md:flex-row md:items-center">
        <div className="grid w-full flex-1 grid-cols-1 items-center gap-x-4 gap-y-4 md:grid-cols-2 xl:grid-cols-4">
          {search && <CustomSearchInput />}
          {providers && <CustomSelectProvider />}
          {date && <CustomDatePicker />}
          {regions && <CustomRegionSelection />}
          {accounts && <CustomAccountSelection />}
          {mutedFindings && <CustomCheckboxMutedFindings />}
        </div>
        {showToggle && hasCustomFilters && (
          <Button
            variant="outline"
            size="lg"
            onClick={() => setIsExpanded(!isExpanded)}
          >
            {isExpanded ? "Less Filters" : "More Filters"}
            {isExpanded ? (
              <ChevronUp className="size-4" />
            ) : (
              <ChevronDown className="size-4" />
            )}
          </Button>
        )}
      </div>
      {shouldShowCustomFilters && (
        <>
          <Spacer y={8} />
          <DataTableFilterCustom filters={customFilters} />
        </>
      )}
    </div>
  );
};
