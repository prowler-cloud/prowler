"use client";

import { Spacer } from "@nextui-org/react";

import { FilterControls } from "@/components/filters";
import { DataTableFilterCustom } from "@/components/ui/table/data-table-filter-custom";
import { SelectScanComplianceDataProps } from "@/types";

import { DataCompliance } from "./data-compliance";

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
      {showSearch && (
        <>
          <FilterControls search />
          <Spacer y={8} />
        </>
      )}
      <div className="flex flex-col items-start gap-4 lg:flex-row lg:items-center lg:justify-start">
        <div className="w-full lg:w-1/3">
          <DataCompliance scans={scans} />
        </div>
        {showRegionFilter && (
          <div className="w-2/3">
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
          </div>
        )}
      </div>
      <Spacer y={12} />
    </>
  );
};
