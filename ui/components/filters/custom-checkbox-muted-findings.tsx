"use client";

import { Checkbox } from "@nextui-org/react";
import { useSearchParams } from "next/navigation";
import { useState } from "react";

import { useUrlFilters } from "@/hooks/use-url-filters";

export const CustomCheckboxMutedFindings = () => {
  const { updateFilter } = useUrlFilters();
  const searchParams = useSearchParams();
  const [excludeMuted, setExcludeMuted] = useState(
    searchParams.get("filter[muted]") === "false",
  );

  const handleMutedChange = (value: boolean) => {
    setExcludeMuted(value);
    updateFilter("muted", value ? "false" : "true");
  };

  return (
    <div className="flex h-full">
      <Checkbox
        classNames={{
          label: "text-small",
          wrapper: "checkbox-update",
        }}
        size="md"
        color="primary"
        aria-label="Include Mutelist"
        isSelected={excludeMuted}
        onValueChange={handleMutedChange}
      >
        Exclude muted findings
      </Checkbox>
    </div>
  );
};
