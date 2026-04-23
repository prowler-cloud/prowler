"use client";

import { useSearchParams } from "next/navigation";

import { Checkbox } from "@/components/shadcn";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { MUTED_FILTER } from "@/lib";

/** Batch mode: caller controls both the checked state and the notification callback (all-or-nothing). */
interface CustomCheckboxMutedFindingsBatchProps {
  /**
   * Called instead of navigating directly.
   * Receives the filter key ("muted") and the string value ("include" or "false").
   */
  onBatchChange: (filterKey: string, value: string) => void;
  /**
   * Controlled checked state from the parent (pending state).
   * `true` = include muted, `false` = exclude muted.
   * `undefined` defers to URL state while pending state is not yet set.
   */
  checked: boolean | undefined;
}

/** Instant mode: URL-driven — neither callback nor controlled value. */
interface CustomCheckboxMutedFindingsInstantProps {
  onBatchChange?: never;
  checked?: never;
}

type CustomCheckboxMutedFindingsProps =
  | CustomCheckboxMutedFindingsBatchProps
  | CustomCheckboxMutedFindingsInstantProps;

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
      : mutedFilterValue === MUTED_FILTER.INCLUDE;

  const handleMutedChange = (checked: boolean | "indeterminate") => {
    const isChecked = checked === true;

    if (onBatchChange) {
      // Batch mode: notify caller instead of navigating
      onBatchChange(
        "muted",
        isChecked ? MUTED_FILTER.INCLUDE : MUTED_FILTER.EXCLUDE,
      );
      return;
    }

    // Instant mode (default): navigate immediately
    navigateWithParams((params) => {
      if (isChecked) {
        // Include muted: set special value (API will ignore invalid value and show all)
        params.set("filter[muted]", MUTED_FILTER.INCLUDE);
      } else {
        // Exclude muted: apply filter to show only non-muted
        params.set("filter[muted]", MUTED_FILTER.EXCLUDE);
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
