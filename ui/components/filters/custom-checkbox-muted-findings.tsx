"use client";

import { useSearchParams } from "next/navigation";

import { Checkbox } from "@/components/shadcn";
import { useUrlFilters } from "@/hooks/use-url-filters";

// Constants for muted filter URL values
const MUTED_FILTER_VALUES = {
  EXCLUDE: "false",
  INCLUDE: "include",
} as const;

interface CustomCheckboxMutedFindingsProps {
  /**
   * Called in batch mode instead of navigating directly.
   * Receives the filter key ("muted") and the string value ("include" or "false").
   * When provided, the component does NOT call `navigateWithParams`.
   */
  onBatchChange?: (filterKey: string, value: string) => void;
  /**
   * Controlled checked state override for batch mode.
   * When provided, this value is used as the checkbox state instead of reading from URL params.
   * `true` = include muted, `false` = exclude muted.
   */
  checked?: boolean;
}

export const CustomCheckboxMutedFindings = ({
  onBatchChange,
  checked: checkedProp,
}: CustomCheckboxMutedFindingsProps = {}) => {
  const searchParams = useSearchParams();
  const { navigateWithParams } = useUrlFilters();

  // Get the current muted filter value from URL
  const mutedFilterValue = searchParams.get("filter[muted]");

  // URL states:
  // - filter[muted]=false → Exclude muted (checkbox UNCHECKED)
  // - filter[muted]=include → Include muted (checkbox CHECKED)
  // When a controlled `checked` prop is provided (batch mode), use it; otherwise fall back to URL.
  const includeMuted =
    checkedProp !== undefined
      ? checkedProp
      : mutedFilterValue === MUTED_FILTER_VALUES.INCLUDE;

  const handleMutedChange = (checked: boolean | "indeterminate") => {
    const isChecked = checked === true;

    if (onBatchChange) {
      // Batch mode: notify caller instead of navigating
      onBatchChange(
        "muted",
        isChecked ? MUTED_FILTER_VALUES.INCLUDE : MUTED_FILTER_VALUES.EXCLUDE,
      );
      return;
    }

    // Instant mode (default): navigate immediately
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
