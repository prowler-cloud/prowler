"use client";

import { useSearchParams } from "next/navigation";

import { Checkbox } from "@/components/shadcn";
import { useUrlFilters } from "@/hooks/use-url-filters";

// Constants for muted filter URL values
const MUTED_FILTER_VALUES = {
  EXCLUDE: "false",
  INCLUDE: "include",
} as const;

export const CustomCheckboxMutedFindings = () => {
  const searchParams = useSearchParams();
  const { navigateWithParams } = useUrlFilters();

  // Get the current muted filter value from URL
  const mutedFilterValue = searchParams.get("filter[muted]");

  // URL states:
  // - filter[muted]=false → Exclude muted (checkbox UNCHECKED)
  // - filter[muted]=include → Include muted (checkbox CHECKED)
  const includeMuted = mutedFilterValue === MUTED_FILTER_VALUES.INCLUDE;

  const handleMutedChange = (checked: boolean | "indeterminate") => {
    const isChecked = checked === true;

    navigateWithParams((params) => {
      if (isChecked) {
        // Include muted: set special value (API will ignore invalid value and show all)
        params.set("filter[muted]", MUTED_FILTER_VALUES.INCLUDE);
      } else {
        // Exclude muted: apply filter to show only non-muted
        params.set("filter[muted]", MUTED_FILTER_VALUES.EXCLUDE);
      }
    });
  };

  return (
    <div className="flex h-full items-center gap-2 text-nowrap">
      <Checkbox
        id="include-muted"
        checked={includeMuted}
        onCheckedChange={handleMutedChange}
        aria-label="Include muted findings"
      />
      <label
        htmlFor="include-muted"
        className="cursor-pointer text-sm leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
      >
        Include muted findings
      </label>
    </div>
  );
};
