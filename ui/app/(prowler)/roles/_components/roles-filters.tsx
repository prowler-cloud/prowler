"use client";

import { filterRoles } from "@/components/filters/data-filters";
import { DataTableFilterCustom } from "@/components/shadcn/table";
import { capitalize } from "@/lib/utils";

// Client-side so labelFormatter never crosses the RSC boundary.
export const RolesFilters = () => (
  <DataTableFilterCustom
    filters={filterRoles.map((filter) => ({
      ...filter,
      labelFormatter: capitalize,
    }))}
    gridClassName="w-fit grid-cols-[14rem_auto] items-center gap-4 sm:grid-cols-[14rem_auto] lg:grid-cols-[14rem_auto] xl:grid-cols-[14rem_auto] 2xl:grid-cols-[14rem_auto]"
  />
);
