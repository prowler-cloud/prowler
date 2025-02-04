"use client";

import { useRouter, useSearchParams } from "next/navigation";
import React, { useCallback, useEffect, useState } from "react";

import { FilterControlsProps } from "@/types";

import { CrossIcon } from "../icons";
import { CustomButton } from "../ui/custom";
import { DataTableFilterCustom } from "../ui/table";
import { CustomAccountSelection } from "./custom-account-selection";
import { CustomCheckboxMutedFindings } from "./custom-checkbox-muted-findings";
import { CustomDatePicker } from "./custom-date-picker";
import { CustomRegionSelection } from "./custom-region-selection";
import { CustomSearchInput } from "./custom-search-input";
import { CustomSelectProvider } from "./custom-select-provider";

export const FilterControls: React.FC<FilterControlsProps> = ({
  search = false,
  providers = false,
  date = false,
  regions = false,
  accounts = false,
  mutedFindings = false,
  customFilters,
}) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [showClearButton, setShowClearButton] = useState(false);

  useEffect(() => {
    const hasFilters = Array.from(searchParams.keys()).some(
      (key) => key.startsWith("filter[") || key === "sort",
    );
    setShowClearButton(hasFilters);
  }, [searchParams]);

  const clearAllFilters = useCallback(() => {
    const params = new URLSearchParams(searchParams.toString());
    Array.from(params.keys()).forEach((key) => {
      if (key.startsWith("filter[") || key === "sort") {
        params.delete(key);
      }
    });
    router.push(`?${params.toString()}`, { scroll: false });
  }, [router, searchParams]);

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-1 items-center gap-x-4 gap-y-4 md:grid-cols-2 xl:grid-cols-4">
        {search && <CustomSearchInput />}
        {providers && <CustomSelectProvider />}
        {date && <CustomDatePicker />}
        {regions && <CustomRegionSelection />}
        {accounts && <CustomAccountSelection />}
        {mutedFindings && <CustomCheckboxMutedFindings />}

        {showClearButton && (
          <CustomButton
            ariaLabel="Reset"
            className="w-full md:w-fit"
            onPress={clearAllFilters}
            variant="dashed"
            size="md"
            endContent={<CrossIcon size={24} />}
            radius="sm"
          >
            Clear all filters
          </CustomButton>
        )}
      </div>
      {customFilters && <DataTableFilterCustom filters={customFilters} />}
    </div>
  );
};
