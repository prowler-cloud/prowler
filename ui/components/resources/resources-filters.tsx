"use client";

import { ChevronDown } from "lucide-react";
import { useState } from "react";

import { AccountsSelector } from "@/app/(prowler)/_overview/_components/accounts-selector";
import { ProviderTypeSelector } from "@/app/(prowler)/_overview/_components/provider-type-selector";
import { ClearFiltersButton } from "@/components/filters/clear-filters-button";
import { Button } from "@/components/shadcn";
import { ExpandableSection } from "@/components/ui/expandable-section";
import { DataTableFilterCustom } from "@/components/ui/table";
import { getGroupLabel } from "@/lib/categories";
import { ProviderProps } from "@/types/providers";

interface ResourcesFiltersProps {
  providers: ProviderProps[];
  uniqueRegions: string[];
  uniqueServices: string[];
  uniqueResourceTypes: string[];
  uniqueGroups: string[];
}

export const ResourcesFilters = ({
  providers,
  uniqueRegions,
  uniqueServices,
  uniqueResourceTypes,
  uniqueGroups,
}: ResourcesFiltersProps) => {
  const [isExpanded, setIsExpanded] = useState(false);

  // Custom filters for the expandable section
  const customFilters = [
    {
      key: "region__in",
      labelCheckboxGroup: "Regions",
      values: uniqueRegions,
      index: 1,
    },
    {
      key: "service__in",
      labelCheckboxGroup: "Services",
      values: uniqueServices,
      index: 2,
    },
    {
      key: "type__in",
      labelCheckboxGroup: "Types",
      values: uniqueResourceTypes,
      index: 3,
    },
    {
      key: "groups__in",
      labelCheckboxGroup: "Groups",
      values: uniqueGroups,
      labelFormatter: getGroupLabel,
      index: 4,
    },
  ];

  const hasCustomFilters = customFilters.length > 0;

  return (
    <div className="flex flex-col">
      {/* First row: Provider selectors + More Filters button + Clear Filters */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="min-w-[200px] flex-1 md:max-w-[280px]">
          <ProviderTypeSelector providers={providers} />
        </div>
        <div className="min-w-[200px] flex-1 md:max-w-[280px]">
          <AccountsSelector providers={providers} />
        </div>
        {hasCustomFilters && (
          <Button
            variant="outline"
            size="lg"
            onClick={() => setIsExpanded(!isExpanded)}
          >
            {isExpanded ? "Less Filters" : "More Filters"}
            <ChevronDown
              className={`size-4 transition-transform duration-300 ${isExpanded ? "rotate-180" : "rotate-0"}`}
            />
          </Button>
        )}
        <ClearFiltersButton showCount />
      </div>

      {/* Expandable filters section */}
      {hasCustomFilters && (
        <ExpandableSection isExpanded={isExpanded}>
          <DataTableFilterCustom filters={customFilters} hideClearButton />
        </ExpandableSection>
      )}
    </div>
  );
};
