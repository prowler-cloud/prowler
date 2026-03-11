"use client";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { ProviderType, ScanProps } from "@/types";

import { ComplianceScanInfo } from "./compliance-scan-info";

export interface SelectScanComplianceDataProps {
  scans: (ScanProps & {
    providerInfo: {
      provider: ProviderType;
      uid: string;
      alias: string;
    };
  })[];
  selectedScanId: string;
  onSelectionChange: (selectedKey: string) => void;
}

export const ScanSelector = ({
  scans,
  selectedScanId,
  onSelectionChange,
}: SelectScanComplianceDataProps) => {
  const selectedScan = scans.find((item) => item.id === selectedScanId);

  return (
    <Select
      value={selectedScanId}
      onValueChange={(value) => {
        if (value && value !== selectedScanId) {
          onSelectionChange(value);
        }
      }}
    >
      <SelectTrigger className="w-full max-w-[360px]">
        <SelectValue placeholder="Select a scan">
          {selectedScan ? (
            <ComplianceScanInfo scan={selectedScan} />
          ) : (
            "Select a scan"
          )}
        </SelectValue>
      </SelectTrigger>
      <SelectContent className="max-w-[360px]">
        {scans.map((scan) => (
          <SelectItem
            key={scan.id}
            value={scan.id}
            className="data-[state=checked]:bg-bg-neutral-tertiary"
          >
            <ComplianceScanInfo scan={scan} />
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
};
