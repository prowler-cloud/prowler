"use client";

import { Badge } from "@/components/shadcn/badge/badge";
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
  const triggerLabel =
    selectedScan?.attributes.name ||
    selectedScan?.providerInfo.alias ||
    selectedScan?.providerInfo.uid ||
    "";

  return (
    <Select
      value={selectedScanId}
      onValueChange={(value) => {
        if (value && value !== selectedScanId) {
          onSelectionChange(value);
        }
      }}
    >
      <SelectTrigger className="w-full">
        <SelectValue placeholder="Select a scan">
          {selectedScan ? (
            <>
              <span className="text-text-neutral-secondary shrink-0 text-xs">
                Scan:
              </span>
              <Badge variant="tag" className="truncate">
                {triggerLabel}
              </Badge>
            </>
          ) : (
            "Select a scan"
          )}
        </SelectValue>
      </SelectTrigger>
      <SelectContent>
        {scans.map((scan) => (
          <SelectItem
            key={scan.id}
            value={scan.id}
            className="data-[state=checked]:bg-bg-neutral-tertiary [&_svg:not([class*='size-'])]:size-6"
          >
            <ComplianceScanInfo scan={scan} />
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
};
