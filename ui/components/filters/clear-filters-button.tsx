"use client";

import { CrossIcon } from "@/components/icons";
import { useUrlFilters } from "@/hooks/use-url-filters";

import { CustomButton } from "../ui/custom/custom-button";

export interface ClearFiltersButtonProps {
  className?: string;
  text?: string;
  ariaLabel?: string;
}

export const ClearFiltersButton = ({
  className = "w-full md:w-fit",
  text = "Clear all filters",
  ariaLabel = "Reset",
}: ClearFiltersButtonProps) => {
  const { clearAllFilters, hasFilters } = useUrlFilters();

  if (!hasFilters()) {
    return null;
  }

  return (
    <CustomButton
      ariaLabel={ariaLabel}
      className={className}
      onPress={clearAllFilters}
      variant="dashed"
      size="md"
      endContent={<CrossIcon size={24} />}
      radius="sm"
    >
      {text}
    </CustomButton>
  );
};
