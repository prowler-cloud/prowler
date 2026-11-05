"use client";

import { DataTableFilterCustom } from "@/components/shadcn/table";

export interface RealtimeFilterDefinition {
  /** Filter key without `filter[...]`, e.g. `status__in`. */
  key: string;
  label: string;
  values: string[];
  labels: Record<string, string>;
}

interface RealtimeFiltersProps {
  filters: RealtimeFilterDefinition[];
}

// Client-side so labelFormatter never crosses the RSC boundary.
export function RealtimeFilters({ filters }: RealtimeFiltersProps) {
  return (
    <DataTableFilterCustom
      filters={filters.map((filter) => ({
        key: filter.key,
        labelCheckboxGroup: filter.label,
        values: filter.values,
        labelFormatter: (value: string) => filter.labels[value] ?? value,
      }))}
      gridClassName="w-fit grid-cols-1 items-center gap-2 sm:grid-cols-[repeat(3,14rem)] lg:grid-cols-[repeat(3,14rem)] xl:grid-cols-[repeat(3,14rem)] 2xl:grid-cols-[repeat(3,14rem)]"
    />
  );
}
