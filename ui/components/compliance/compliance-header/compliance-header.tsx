"use client";

import Image from "next/image";

import { DataTableFilterCustom } from "@/components/ui/table/data-table-filter-custom";
import { ScanEntity } from "@/types/scans";

import { ComplianceScanInfo } from "./compliance-scan-info";
import { DataCompliance } from "./data-compliance";
import { SelectScanComplianceDataProps } from "./scan-selector";

interface ComplianceHeaderProps {
  scans: SelectScanComplianceDataProps["scans"];
  uniqueRegions: string[];
  showSearch?: boolean;
  showRegionFilter?: boolean;
  framework?: string; // Framework name to show specific filters
  showProviders?: boolean;
  hideFilters?: boolean;
  logoPath?: string;
  complianceTitle?: string;
  selectedScan?: ScanEntity | null;
}

export const ComplianceHeader = ({
  scans,
  uniqueRegions,
  showSearch = true,
  showRegionFilter = true,
  framework,
  showProviders = true,
  hideFilters = false,
  logoPath,
  complianceTitle,
  selectedScan,
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
        },
      ]
    : [];

  const allFilters = [...frameworkFilters, ...regionFilters];

  const hasContent =
    showProviders ||
    showSearch ||
    (!hideFilters && allFilters.length > 0) ||
    selectedScan;

  return (
    <>
      {hasContent && (
        <div className="flex w-full items-start justify-between gap-6 sm:mb-8">
          <div className="flex flex-1 flex-col justify-end gap-4">
            {/* Showed in the details page */}
            {selectedScan && <ComplianceScanInfo scan={selectedScan} />}

            {/* Showed in the compliance page */}
            {showProviders && <DataCompliance scans={scans} />}
            {!hideFilters && allFilters.length > 0 && (
              <DataTableFilterCustom filters={allFilters} />
            )}
          </div>
          {logoPath && complianceTitle && (
            <div className="hidden shrink-0 sm:block">
              <div className="relative h-24 w-24">
                <Image
                  src={logoPath}
                  alt={`${complianceTitle} logo`}
                  fill
                  className="rounded-lg border border-gray-300 bg-white object-contain p-0"
                />
              </div>
            </div>
          )}
        </div>
      )}
    </>
  );
};
