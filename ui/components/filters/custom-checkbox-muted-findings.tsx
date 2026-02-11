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
<<<<<<< HEAD

  // Use shared transition context if available, otherwise fall back to local
  const sharedTransition = useFilterTransitionOptional();
  const [, localStartTransition] = useTransition();
  const startTransition =
    sharedTransition?.startTransition ?? localStartTransition;
=======
  const { navigateWithParams } = useUrlFilters();
>>>>>>> 86946f3a8 (fix(ui): fix findings filter silent reverts by replacing useRelatedFilters effect with pure derivation (#10021))

  // Get the current muted filter value from URL
  const mutedFilterValue = searchParams.get("filter[muted]");

  // URL states:
  // - filter[muted]=false → Exclude muted (checkbox UNCHECKED)
  // - filter[muted]=include → Include muted (checkbox CHECKED)
  const includeMuted = mutedFilterValue === MUTED_FILTER_VALUES.INCLUDE;

  const handleMutedChange = (checked: boolean | "indeterminate") => {
    const isChecked = checked === true;

<<<<<<< HEAD
    if (isChecked) {
      // Include muted: set special value (API will ignore invalid value and show all)
      params.set("filter[muted]", MUTED_FILTER_VALUES.INCLUDE);
    } else {
      // Exclude muted: apply filter to show only non-muted
      params.set("filter[muted]", MUTED_FILTER_VALUES.EXCLUDE);
    }

    // Reset to page 1 when changing filter
    if (params.has("page")) {
      params.set("page", "1");
    }

    startTransition(() => {
      router.push(`${pathname}?${params.toString()}`, { scroll: false });
=======
    navigateWithParams((params) => {
      if (isChecked) {
        // Include muted: set special value (API will ignore invalid value and show all)
        params.set("filter[muted]", MUTED_FILTER_VALUES.INCLUDE);
      } else {
        // Exclude muted: apply filter to show only non-muted
        params.set("filter[muted]", MUTED_FILTER_VALUES.EXCLUDE);
      }
>>>>>>> 86946f3a8 (fix(ui): fix findings filter silent reverts by replacing useRelatedFilters effect with pure derivation (#10021))
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
