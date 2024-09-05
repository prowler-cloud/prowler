"use client";

import { Button } from "@nextui-org/react";
import { useRouter, useSearchParams } from "next/navigation";
import React from "react";
import { useCallback } from "react";

// import { SearchParamsProps } from "../../types/components";
import { CustomAccountSelection } from "./CustomAccountSelection";
import { CustomCheckboxMutedFindings } from "./CustomCheckboxMutedFindings";
import { CustomDatePicker } from "./CustomDatePicker";
import { CustomSelectProvider } from "./CustomSelectProvider";

interface FilterControlsProps {
  mutedFindings?: boolean;
  // searchParams: SearchParamsProps;
}

export const FilterControls: React.FC<FilterControlsProps> = ({
  mutedFindings = true,
  // searchParams,
}) => {
  const router = useRouter();
  const searchParams = useSearchParams();

  const clearAllFilters = useCallback(() => {
    const params = new URLSearchParams(searchParams.toString());
    // Remove all filter parameters
    Array.from(params.keys()).forEach((key) => {
      if (key.startsWith("filter[")) {
        params.delete(key);
      }
    });
    router.push(`?${params.toString()}`, { scroll: false });
  }, [router, searchParams]);
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-x-4 gap-y-4 items-center">
      <CustomSelectProvider />
      <CustomDatePicker />
      <CustomAccountSelection />
      <CustomCheckboxMutedFindings mutedFindings={mutedFindings} />
      <Button
        className="w-fit"
        onClick={clearAllFilters}
        variant="flat"
        color="default"
        size="sm"
      >
        Clear all
      </Button>
    </div>
  );
};
