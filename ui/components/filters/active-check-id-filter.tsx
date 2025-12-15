"use client";

import { X } from "lucide-react";
import { useSearchParams } from "next/navigation";

import { Badge } from "@/components/shadcn";
import { useUrlFilters } from "@/hooks/use-url-filters";

export const ActiveCheckIdFilter = () => {
  const searchParams = useSearchParams();
  const { clearFilter } = useUrlFilters();

  const checkIdFilter = searchParams.get("filter[check_id__in]");

  if (!checkIdFilter) {
    return null;
  }

  const checkIds = checkIdFilter.split(",");
  const displayText =
    checkIds.length > 1
      ? `${checkIds.length} Check IDs filtered`
      : `Check ID: ${checkIds[0]}`;

  return (
    <Badge
      variant="outline"
      className="flex cursor-pointer items-center gap-1 px-3 py-1.5"
      onClick={() => clearFilter("check_id__in")}
    >
      <span className="max-w-[200px] truncate text-sm">{displayText}</span>
      <X className="size-3.5 shrink-0" />
    </Badge>
  );
};
