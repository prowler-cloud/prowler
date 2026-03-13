"use client";

import { ArrowDownNarrowWide, ArrowUpNarrowWide } from "lucide-react";

import { Button } from "@/components/shadcn/button/button";

interface SortToggleButtonProps {
  isAscending: boolean;
  onToggle: () => void;
  ascendingLabel?: string;
  descendingLabel?: string;
}

export const SortToggleButton = ({
  isAscending,
  onToggle,
  ascendingLabel = "Sort descending",
  descendingLabel = "Sort ascending",
}: SortToggleButtonProps) => {
  const SortIcon = isAscending ? ArrowUpNarrowWide : ArrowDownNarrowWide;

  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={onToggle}
      aria-label={isAscending ? ascendingLabel : descendingLabel}
    >
      <SortIcon className="size-4" />
    </Button>
  );
};
