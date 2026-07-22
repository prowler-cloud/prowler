"use client";

import Image from "next/image";

import { DataTableFilterCustom } from "@/components/shadcn/table/data-table-filter-custom";
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
  const prependElement = showProviders ? (
    <DataCompliance scans={scans} className="w-full sm:col-span-2" />
  ) : undefined;

  // Add CIS Profile Level filter if framework is CIS
  if (framework === "CIS") {
    frameworkFilters.push({
      key: "cis_profile_level",
      labelCheckboxGroup: "Level",
      values: ["Level 1", "Level 2"],
      width: "wide" as const,
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
          width: "wide" as const,
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
        <div className="flex w-full flex-col gap-4">
          {/* Identity row: framework logo anchoring the scan context. */}
          {(selectedScan || (logoPath && complianceTitle)) && (
            <div className="flex w-full items-center gap-4">
              {logoPath && complianceTitle && (
                <div className="relative h-12 w-12 shrink-0">
                  <Image
                    src={logoPath}
                    alt={`${complianceTitle} logo`}
                    fill
                    className="border-border-neutral-tertiary bg-bg-logo-surface rounded-lg border object-contain p-0"
                  />
                </div>
              )}
              {selectedScan && <ComplianceScanInfo scan={selectedScan} />}
            </div>
          )}

          {/* Filters row */}
          {!hideFilters && (allFilters.length > 0 || showProviders) && (
            <DataTableFilterCustom
              filters={allFilters}
              prependElement={prependElement}
            />
          )}
        </div>
      )}
    </>
  );
};
