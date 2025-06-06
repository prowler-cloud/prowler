import { Select, SelectItem } from "@nextui-org/react";

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
  return (
    <Select
      aria-label="Select a Scan"
      placeholder="Select a scan"
      classNames={{
        trigger: "w-full min-w-[365px]",
      }}
      size="lg"
      labelPlacement="outside"
      selectedKeys={new Set([selectedScanId])}
      onSelectionChange={(keys) =>
        onSelectionChange(Array.from(keys)[0] as string)
      }
      renderValue={() => {
        const selectedItem = scans.find((item) => item.id === selectedScanId);
        return selectedItem ? (
          <ComplianceScanInfo scan={selectedItem} />
        ) : (
          "Select a scan"
        );
      }}
    >
      {scans.map((scan) => (
        <SelectItem key={scan.id} textValue={scan.attributes.name || "- -"}>
          <ComplianceScanInfo scan={scan} />
        </SelectItem>
      ))}
    </Select>
  );
};
