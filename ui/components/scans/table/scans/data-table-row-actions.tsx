"use client";

import {
  Button,
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownSection,
  DropdownTrigger,
} from "@nextui-org/react";
import {
  // DeleteDocumentBulkIcon,
  EditDocumentBulkIcon,
} from "@nextui-org/shared-icons";
import { Row } from "@tanstack/react-table";
import { DownloadIcon } from "lucide-react";
import { useState } from "react";

import { getExportsZip } from "@/actions/scans";
import { VerticalDotsIcon } from "@/components/icons";
import { useToast } from "@/components/ui";
import { CustomAlertModal } from "@/components/ui/custom";

import { EditScanForm } from "../../forms";

interface DataTableRowActionsProps<ScanProps> {
  row: Row<ScanProps>;
}
const iconClasses =
  "text-2xl text-default-500 pointer-events-none flex-shrink-0";

export function DataTableRowActions<ScanProps>({
  row,
}: DataTableRowActionsProps<ScanProps>) {
  const { toast } = useToast();
  const [isEditOpen, setIsEditOpen] = useState(false);
  const scanId = (row.original as { id: string }).id;
  const scanName = (row.original as any).attributes?.name;
  const scanState = (row.original as any).attributes?.state;

  const handleExportZip = async () => {
    const result = await getExportsZip(scanId);

    if (result?.success && result?.data) {
      // Convert base64 to blob
      const binaryString = window.atob(result.data);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      const blob = new Blob([bytes], { type: "application/zip" });

      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = result.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);

      toast({
        title: "Download Complete",
        description: "Your scan report has been downloaded successfully.",
      });
    } else if (result?.error) {
      toast({
        variant: "destructive",
        title: "Download Failed",
        description: result.error,
      });
    }
  };

  return (
    <>
      <CustomAlertModal
        isOpen={isEditOpen}
        onOpenChange={setIsEditOpen}
        title="Edit Scan Name"
      >
        <EditScanForm
          scanId={scanId}
          scanName={scanName}
          setIsOpen={setIsEditOpen}
        />
      </CustomAlertModal>

      <div className="relative flex items-center justify-end gap-2">
        <Dropdown
          className="shadow-xl dark:bg-prowler-blue-800"
          placement="bottom"
        >
          <DropdownTrigger>
            <Button isIconOnly radius="full" size="sm" variant="light">
              <VerticalDotsIcon className="text-default-400" />
            </Button>
          </DropdownTrigger>
          <DropdownMenu
            closeOnSelect
            aria-label="Actions"
            color="default"
            variant="flat"
          >
            <DropdownSection title="Export artifacts">
              <DropdownItem
                key="export"
                description="Available only for completed scans"
                textValue="Export Scan Artifacts"
                startContent={<DownloadIcon className={iconClasses} />}
                onPress={handleExportZip}
                isDisabled={scanState !== "completed"}
              >
                Download .zip
              </DropdownItem>
            </DropdownSection>
            <DropdownSection title="Actions">
              <DropdownItem
                key="edit"
                description="Allows you to edit the scan name"
                textValue="Edit Scan Name"
                startContent={<EditDocumentBulkIcon className={iconClasses} />}
                onPress={() => setIsEditOpen(true)}
              >
                Edit scan name
              </DropdownItem>
            </DropdownSection>
          </DropdownMenu>
        </Dropdown>
      </div>
    </>
  );
}
