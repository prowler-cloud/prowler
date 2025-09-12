"use client";

import { Spacer } from "@nextui-org/react";

import { FilterControls } from "@/components/filters";
import { DataTableFilterCustom } from "@/components/ui/table/data-table-filter-custom";

import { DataCompliance } from "./data-compliance";
import { SelectScanComplianceDataProps } from "./scan-selector";

interface ComplianceHeaderProps {
  scans: SelectScanComplianceDataProps["scans"];
  uniqueRegions: string[];
  showSearch?: boolean;
  showRegionFilter?: boolean;
  framework?: string; // Framework name to show specific filters
  showProviders?: boolean;
}

export const ComplianceHeader = ({
  scans,
  uniqueRegions,
  showSearch = true,
  showRegionFilter = true,
  framework,
  showProviders = true,
}: ComplianceHeaderProps) => {
  const frameworkFilters = [];

  // Add CIS Profile Level filter if framework is CIS
  if (framework === "CIS") {
    frameworkFilters.push({
      key: "cis_profile_level",
      labelCheckboxGroup: "Level",
      values: ["Level 1", "Level 2"],
      index: 0, // Show first
      showSelectAll: false, // No "Select All" option since Level 2 includes Level 1
      defaultValues: ["Level 2"], // Default to Level 2 selected (which includes Level 1)
    });
  }

  // Prepare region filters
  const regionFilters = showRegionFilter
    ? [
        {
          key: "region__in",
          labelCheckboxGroup: "Regions",
          values: uniqueRegions,
          index: 1, // Show after framework filters
          defaultToSelectAll: true, // Default to all regions selected
        },
      ]
    : [];

  const allFilters = [...frameworkFilters, ...regionFilters];

  return (
    <>
      {(showProviders || showSearch) && (
        <>
          <div className="flex items-start justify-start gap-4">
            {showProviders && <DataCompliance scans={scans} />}
            {showSearch && <FilterControls search />}
          </div>
        </>
      )}
      {allFilters.length > 0 && <DataTableFilterCustom filters={allFilters} />}
      <Spacer y={8} />
    </>
  );
};
