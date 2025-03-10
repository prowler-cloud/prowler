import { Select, SelectItem } from "@nextui-org/react";

import { SelectScanComplianceDataProps } from "@/types";

import { ComplianceScanInfo } from "../compliance-scan-info";

export const SelectScanComplianceData = ({
  scans,
  selectedScanId,
  onSelectionChange,
}: SelectScanComplianceDataProps) => {
  return (
    <Select
      aria-label="Select a Scan"
      placeholder="Select a scan"
      classNames={{
        selectorIcon: "right-2",
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
