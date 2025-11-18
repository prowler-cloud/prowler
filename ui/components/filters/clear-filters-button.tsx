"use client";

import { XCircle } from "lucide-react";

import { useUrlFilters } from "@/hooks/use-url-filters";

import { Button } from "../shadcn";

export interface ClearFiltersButtonProps {
  className?: string;
  text?: string;
  ariaLabel?: string;
}

export const ClearFiltersButton = ({
  text = "Clear all filters",
  ariaLabel = "Reset",
}: ClearFiltersButtonProps) => {
  const { clearAllFilters, hasFilters } = useUrlFilters();

  if (!hasFilters()) {
    return null;
  }

  return (
    <Button aria-label={ariaLabel} onClick={clearAllFilters} variant="link">
      <XCircle className="mr-0.5 size-4" />
      {text}
    </Button>
  );
};
