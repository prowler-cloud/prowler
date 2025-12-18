"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

import { Checkbox } from "@/components/shadcn";

export const CustomCheckboxMutedFindings = () => {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  // Get the current muted filter value from URL
  // Middleware ensures filter[muted] is always present when navigating to /findings
  const mutedFilterValue = searchParams.get("filter[muted]");

  // URL states:
  // - filter[muted]=false → Exclude muted (checkbox UNCHECKED)
  // - filter[muted]=include → Include muted (checkbox CHECKED)
  const includeMuted = mutedFilterValue === "include";

  const handleMutedChange = (checked: boolean | "indeterminate") => {
    const isChecked = checked === true;
    const params = new URLSearchParams(searchParams.toString());

    if (isChecked) {
      // Include muted: set special value (API will ignore invalid value and show all)
      params.set("filter[muted]", "include");
    } else {
      // Exclude muted: apply filter to show only non-muted
      params.set("filter[muted]", "false");
    }

    // Reset to page 1 when changing filter
    if (params.has("page")) {
      params.set("page", "1");
    }

    router.push(`${pathname}?${params.toString()}`, { scroll: false });
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
