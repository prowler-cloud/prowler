"use client";

import { X } from "lucide-react";
import { useSearchParams } from "next/navigation";

import { Badge } from "@/components/shadcn";
import { useUrlFilters } from "@/hooks/use-url-filters";

export interface FilterBadgeConfig {
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

/**
 * Default filter badge configurations for common use cases.
 * Add new filters here to automatically show them as badges.
 */
export const DEFAULT_FILTER_BADGES: FilterBadgeConfig[] = [
  {
    filterKey: "check_id__in",
    label: "Check ID",
    formatMultiple: (count) => `${count} Check IDs filtered`,
  },
];

interface ActiveFilterBadgeProps {
  config: FilterBadgeConfig;
}

/**
 * Single filter badge component that reads from URL and displays if active.
 */
const ActiveFilterBadge = ({ config }: ActiveFilterBadgeProps) => {
  const searchParams = useSearchParams();
  const { clearFilter } = useUrlFilters();

  const {
    filterKey,
    label,
    formatValue = (v) => v,
    formatMultiple = (count, lbl) => `${count} ${lbl}s filtered`,
  } = config;

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

interface ActiveFilterBadgesProps {
  /**
   * Filter configurations to render as badges.
   * Defaults to DEFAULT_FILTER_BADGES if not provided.
   */
  filters?: FilterBadgeConfig[];
}

/**
 * Renders filter badges for all configured filters that are active in the URL.
 * Only shows badges for filters that have values in the URL params.
 */
export const ActiveFilterBadges = ({
  filters = DEFAULT_FILTER_BADGES,
}: ActiveFilterBadgesProps) => {
  return (
    <>
      {filters.map((config) => (
        <ActiveFilterBadge key={config.filterKey} config={config} />
      ))}
    </>
  );
};
