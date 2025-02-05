"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { SelectScanComplianceData } from "@/components/compliance/data-compliance";
import { CrossIcon } from "@/components/icons";
import { CustomButton, CustomDropdownFilter } from "@/components/ui/custom";

interface DataComplianceProps {
  scans: { id: string; name: string; state: string; progress: number }[];
  regions: string[];
}

export const DataCompliance = ({ scans, regions }: DataComplianceProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [showClearButton, setShowClearButton] = useState(false);
  const scanIdParam = searchParams.get("scanId");
  const selectedScanId = scanIdParam || (scans.length > 0 ? scans[0].id : "");

  useEffect(() => {
    if (!scanIdParam && scans.length > 0) {
      const params = new URLSearchParams(searchParams);
      params.set("scanId", scans[0].id);
      router.push(`?${params.toString()}`);
    }
  }, [scans, scanIdParam, searchParams, router]);

  useEffect(() => {
    const hasFilters = Array.from(searchParams.keys()).some(
      (key) => key.startsWith("filter[") || key === "sort",
    );
    setShowClearButton(hasFilters);
  }, [searchParams]);
  const handleScanChange = (selectedKey: string) => {
    const params = new URLSearchParams(searchParams);
    params.set("scanId", selectedKey);
    router.push(`?${params.toString()}`);
  };

  const pushDropdownFilter = useCallback(
    (key: string, values: string[]) => {
      const params = new URLSearchParams(searchParams);
      const filterKey = `filter[${key}]`;

      if (values.length === 0) {
        params.delete(filterKey);
      } else {
        params.set(filterKey, values.join(","));
      }

      router.push(`?${params.toString()}`);
    },
    [router, searchParams],
  );
  const clearAllFilters = useCallback(() => {
    const params = new URLSearchParams(searchParams.toString());
    Array.from(params.keys()).forEach((key) => {
      if (key.startsWith("filter[") || key === "sort") {
        params.delete(key);
      }
    });
    router.push(`?${params.toString()}`, { scroll: false });
  }, [router, searchParams]);
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-1 items-center gap-x-4 gap-y-4 md:grid-cols-2 xl:grid-cols-4">
        <SelectScanComplianceData
          scans={scans}
          selectedScanId={selectedScanId}
          onSelectionChange={handleScanChange}
        />
        <CustomDropdownFilter
          filter={{
            key: "region__in",
            values: regions,
            labelCheckboxGroup: "Regions",
          }}
          onFilterChange={pushDropdownFilter}
        />
        {showClearButton && (
          <CustomButton
            ariaLabel="Reset"
            className="w-full md:w-fit"
            onPress={clearAllFilters}
            variant="dashed"
            size="sm"
            endContent={<CrossIcon size={24} />}
            radius="sm"
          >
            Reset
          </CustomButton>
        )}
      </div>
    </div>
  );
};
