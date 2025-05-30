"use client";

import { Spacer } from "@nextui-org/react";

import { FilterControls } from "@/components/filters";
import { DataTableFilterCustom } from "@/components/ui/table/data-table-filter-custom";

import { DataCompliance } from "./data-compliance";
import { SelectScanComplianceDataProps } from "./select-scan-compliance-data";

interface ComplianceHeaderProps {
  scans: SelectScanComplianceDataProps["scans"];
  uniqueRegions: string[];
  showSearch?: boolean;
  showRegionFilter?: boolean;
}

export const ComplianceHeader = ({
  scans,
  uniqueRegions,
  showSearch = true,
  showRegionFilter = true,
}: ComplianceHeaderProps) => {
  return (
    <>
      {showSearch && <FilterControls search />}
      <Spacer y={8} />
      <DataCompliance scans={scans} />
      {showRegionFilter && (
        <>
          <Spacer y={8} />
          <DataTableFilterCustom
            filters={[
              {
                key: "region__in",
                labelCheckboxGroup: "Regions",
                values: uniqueRegions,
              },
            ]}
            defaultOpen={true}
          />
        </>
      )}
      <Spacer y={12} />
    </>
  );
};
