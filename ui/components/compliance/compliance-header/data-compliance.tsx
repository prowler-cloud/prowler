"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useEffect } from "react";

import {
  ScanSelector,
  SelectScanComplianceDataProps,
} from "@/components/compliance/compliance-header/index";
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
      <div className="flex max-w-fit">
        <ScanSelector
          scans={scans}
          selectedScanId={selectedScanId}
          onSelectionChange={handleScanChange}
        />
      </div>
    </div>
  );
};
