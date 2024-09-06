"use client";

import { Button } from "@nextui-org/react";
import { useRouter, useSearchParams } from "next/navigation";
import React, { useCallback } from "react";

import { CustomAccountSelection } from "./CustomAccountSelection";
import { CustomCheckboxMutedFindings } from "./CustomCheckboxMutedFindings";
import { CustomDatePicker } from "./CustomDatePicker";
import { CustomSearchInput } from "./CustomSearchInput";
import { CustomSelectProvider } from "./CustomSelectProvider";

interface FilterControlsProps {
  mutedFindings?: boolean;
}

export const FilterControls: React.FC<FilterControlsProps> = ({
  mutedFindings = true,
}) => {
  const router = useRouter();
  const searchParams = useSearchParams();

  const clearAllFilters = useCallback(() => {
    const params = new URLSearchParams(searchParams.toString());
    Array.from(params.keys()).forEach((key) => {
      if (key.startsWith("filter[")) {
        params.delete(key);
      }
    });
    router.push(`?${params.toString()}`, { scroll: false });
  }, [router, searchParams]);

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-x-4 gap-y-4 items-center">
      <CustomSearchInput />
      <CustomSelectProvider />
      <CustomDatePicker />
      <CustomAccountSelection />
      <CustomCheckboxMutedFindings mutedFindings={mutedFindings} />
      <Button
        className="w-full md:w-fit"
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
