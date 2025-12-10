"use client";

import { X } from "lucide-react";
import { useSearchParams } from "next/navigation";

import { Badge } from "@/components/shadcn";
import { useUrlFilters } from "@/hooks/use-url-filters";

export interface ActiveFilterBadgeProps {
  /**
   * The filter key without the "filter[]" wrapper.
   * Example: "scan__in", "check_id__in", "provider__in"
   */
  filterKey: string;

  /**
   * Label to display before the value.
   * Example: "Scan", "Check ID", "Provider"
   */
  label: string;

  /**
   * Optional function to format a single value for display.
   * Useful for truncating UUIDs, etc.
   * Default: shows value as-is
   */
  formatValue?: (value: string) => string;

  /**
   * Optional function to format the display when multiple values are selected.
   * Default: "{count} {label}s filtered"
   */
  formatMultiple?: (count: number, label: string) => string;
}

export const ActiveFilterBadge = ({
  filterKey,
  label,
  formatValue = (v) => v,
  formatMultiple = (count, lbl) => `${count} ${lbl}s filtered`,
}: ActiveFilterBadgeProps) => {
  const searchParams = useSearchParams();
  const { clearFilter } = useUrlFilters();

  const fullKey = filterKey.startsWith("filter[")
    ? filterKey
    : `filter[${filterKey}]`;

  const filterValue = searchParams.get(fullKey);

  if (!filterValue) {
    return null;
  }

  const values = filterValue.split(",");
  const displayText =
    values.length > 1
      ? formatMultiple(values.length, label)
      : `${label}: ${formatValue(values[0])}`;

  return (
    <Badge
      variant="outline"
      className="flex cursor-pointer items-center gap-1 px-3 py-1.5"
      onClick={() => clearFilter(filterKey)}
    >
      <span className="max-w-[200px] truncate text-sm">{displayText}</span>
      <X className="size-3.5 shrink-0" />
    </Badge>
  );
};

/**
 * Pre-configured filter badges for common use cases
 */
export const ScanFilterBadge = () => (
  <ActiveFilterBadge
    filterKey="scan__in"
    label="Scan"
    formatValue={(id) => `${id.slice(0, 8)}...`}
  />
);

export const CheckIdFilterBadge = () => (
  <ActiveFilterBadge
    filterKey="check_id__in"
    label="Check ID"
    formatMultiple={(count) => `${count} Check IDs filtered`}
  />
);
