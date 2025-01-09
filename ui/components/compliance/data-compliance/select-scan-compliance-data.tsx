import { Select, SelectItem } from "@nextui-org/react";

interface SelectScanComplianceDataProps {
  scans: { id: string; name: string; state: string; progress: number }[];
  selectedScanId: string;
  onSelectionChange: (selectedKey: string) => void;
}

export const SelectScanComplianceData = ({
  scans,
  selectedScanId,
  onSelectionChange,
}: SelectScanComplianceDataProps) => {
  return (
    <Select
      aria-label="Select a Scan"
      placeholder="Select a scan"
      labelPlacement="outside"
      size="md"
      selectedKeys={new Set([selectedScanId])}
      onSelectionChange={(keys) =>
        onSelectionChange(Array.from(keys)[0] as string)
      }
      renderValue={() => {
        const selectedItem = scans.find((item) => item.id === selectedScanId);
        return selectedItem ? (
          <div className="flex flex-col">
            <span className="font-bold">{selectedItem.name}</span>
            <span className="text-sm text-gray-500">
              State: {selectedItem.state}, Progress: {selectedItem.progress}%
            </span>
          </div>
        ) : (
          "Select a scan"
        );
      }}
    >
      {scans.map((scan) => (
        <SelectItem key={scan.id} textValue={scan.name}>
          <div className="flex flex-col">
            <span className="font-bold">{scan.name}</span>
            <span className="text-sm text-gray-500">
              State: {scan.state}, Progress: {scan.progress}%
            </span>
          </div>
        </SelectItem>
      ))}
    </Select>
  );
};
