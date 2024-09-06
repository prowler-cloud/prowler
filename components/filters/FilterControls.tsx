"use client";

import { Button } from "@nextui-org/react";
import { useRouter, useSearchParams } from "next/navigation";
import React, { useCallback, useEffect, useState } from "react";

import { CustomAccountSelection } from "./CustomAccountSelection";
import { CustomCheckboxMutedFindings } from "./CustomCheckboxMutedFindings";
import { CustomDatePicker } from "./CustomDatePicker";
import { CustomRegionSelection } from "./CustomRegionSelection";
import { CustomSearchInput } from "./CustomSearchInput";
import { CustomSelectProvider } from "./CustomSelectProvider";

interface FilterControlsProps {
  search?: boolean;
  providers?: boolean;
  date?: boolean;
  regions?: boolean;
  accounts?: boolean;
  mutedFindings?: boolean;
}

export const FilterControls: React.FC<FilterControlsProps> = ({
  search = false,
  providers = false,
  date = false,
  regions = false,
  accounts = false,
  mutedFindings = false,
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
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-x-4 gap-y-4 items-center">
      {search && <CustomSearchInput />}
      {providers && <CustomSelectProvider />}
      {date && <CustomDatePicker />}
      {regions && <CustomRegionSelection />}
      {accounts && <CustomAccountSelection />}
      {mutedFindings && <CustomCheckboxMutedFindings />}

      {showClearButton && (
        <Button
          className="w-full md:w-fit transition-all duration-300 ease-in-out"
          onClick={clearAllFilters}
          variant="flat"
          color="default"
          size="sm"
        >
          Clear all
        </Button>
      )}
    </div>
  );
};
