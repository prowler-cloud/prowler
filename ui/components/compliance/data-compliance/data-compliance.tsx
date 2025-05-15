"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useEffect } from "react";

import { SelectScanComplianceData } from "@/components/compliance/data-compliance";
import { SelectScanComplianceDataProps } from "@/types";
interface DataComplianceProps {
  scans: SelectScanComplianceDataProps["scans"];
}

export const DataCompliance = ({ scans }: DataComplianceProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();

  const scanIdParam = searchParams.get("scanId");

  const selectedScanId = scanIdParam || (scans.length > 0 ? scans[0].id : "");

  useEffect(() => {
    if (!scanIdParam && scans.length > 0) {
      const params = new URLSearchParams(searchParams);
      params.set("scanId", scans[0].id);
      router.push(`?${params.toString()}`);
    }
  }, [scans, scanIdParam, searchParams, router]);

  const handleScanChange = (selectedKey: string) => {
    const params = new URLSearchParams(searchParams);
    params.set("scanId", selectedKey);
    router.push(`?${params.toString()}`);
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-1 items-center gap-x-4 gap-y-4 md:grid-cols-2 lg:grid-cols-3">
        <SelectScanComplianceData
          scans={scans}
          selectedScanId={selectedScanId}
          onSelectionChange={handleScanChange}
        />
      </div>
    </div>
  );
};
