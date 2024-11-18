"use client";

import { useRouter, useSearchParams } from "next/navigation";

import { SelectScanComplianceData } from "@/components/compliance/data-compliance";

interface DataComplianceProps {
  scans: { id: string; name: string; state: string; progress: number }[];
}

export const DataCompliance = ({ scans }: DataComplianceProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const scanIdParam = searchParams.get("scanId");
  const selectedScanId =
    scanIdParam === "undefined" || !scanIdParam ? scans[0]?.id : scanIdParam;

  if (scanIdParam === "undefined") {
    router.replace("/compliance");
    return null;
  }

  const handleSelectionChange = (selectedKey: string) => {
    router.push(`?scanId=${selectedKey}`);
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-1 items-center gap-x-4 gap-y-4 md:grid-cols-2 xl:grid-cols-4">
        <SelectScanComplianceData
          scans={scans}
          selectedScanId={selectedScanId}
          onSelectionChange={handleSelectionChange}
        />
      </div>
    </div>
  );
};
