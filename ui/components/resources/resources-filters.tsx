"use client";

import { DataTableFilterCustom } from "@/components/ui/table";
import { getGroupLabel } from "@/lib/categories";
import { FilterEntity } from "@/types";

interface ResourcesFiltersProps {
  providerIds: string[];
  providerDetails: { [id: string]: FilterEntity }[];
  uniqueRegions: string[];
  uniqueServices: string[];
  uniqueGroups: string[];
}

export const ResourcesFilters = ({
  providerIds,
  providerDetails,
  uniqueRegions,
  uniqueServices,
  uniqueGroups,
}: ResourcesFiltersProps) => {
  return (
    <DataTableFilterCustom
      filters={[
        {
          key: "provider__in",
          labelCheckboxGroup: "Provider",
          values: providerIds,
          valueLabelMapping: providerDetails,
        },
        {
          key: "region__in",
          labelCheckboxGroup: "Region",
          values: uniqueRegions,
        },
        {
          key: "service__in",
          labelCheckboxGroup: "Service",
          values: uniqueServices,
        },
        {
          key: "groups__in",
          labelCheckboxGroup: "Resource Group",
          values: uniqueGroups,
          labelFormatter: getGroupLabel,
        },
      ]}
    />
  );
};
