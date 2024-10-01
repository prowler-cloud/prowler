"use client";

import { useRouter, useSearchParams } from "next/navigation";
import React, { useCallback, useEffect, useState } from "react";

import { FilterControlsProps } from "@/types";

import { CrossIcon } from "../icons";
import { DataTableFilterCustom } from "../providers/table";
import { CustomButton } from "../ui/custom";
import { CustomCheckboxMutedFindings } from "./custo-checkbox-muted-findings";
import { CustomAccountSelection } from "./custom-account-selection";
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
  customFilters = [],
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
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-x-4 gap-y-4 items-center">
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
            size="sm"
            endContent={<CrossIcon size={24} />}
            radius="sm"
          >
            Reset
          </CustomButton>
        )}
      </div>
      <DataTableFilterCustom filters={customFilters} />
    </div>
  );
};
