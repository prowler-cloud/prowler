"use client";

import {
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownSection,
  DropdownTrigger,
} from "@heroui/dropdown";
import {
  // DeleteDocumentBulkIcon,
  EditDocumentBulkIcon,
} from "@heroui/shared-icons";
import { Row } from "@tanstack/react-table";
import { DownloadIcon } from "lucide-react";
import { useState } from "react";

import { VerticalDotsIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/ui";
import { downloadScanZip } from "@/lib/helper";

import { EditScanForm } from "../../forms";

interface DataTableRowActionsProps<ScanProps> {
  row: Row<ScanProps>;
}
const iconClasses = "text-2xl text-default-500 pointer-events-none shrink-0";

export function DataTableRowActions<ScanProps>({
  row,
}: DataTableRowActionsProps<ScanProps>) {
  const { toast } = useToast();
  const [isEditOpen, setIsEditOpen] = useState(false);
  const scanId = (row.original as { id: string }).id;
  const scanName = (row.original as any).attributes?.name;
  const scanState = (row.original as any).attributes?.state;

  return (
    <>
      <Modal
        open={isEditOpen}
        onOpenChange={setIsEditOpen}
        title="Edit Scan Name"
      >
        <EditScanForm
          scanId={scanId}
          scanName={scanName}
          setIsOpen={setIsEditOpen}
        />
      </Modal>

      <div className="relative flex items-center justify-end gap-2">
        <Dropdown
          className="border-border-neutral-secondary bg-bg-neutral-secondary border shadow-xl"
          placement="bottom"
        >
          <DropdownTrigger>
            <Button variant="ghost" size="icon-sm" className="rounded-full">
              <VerticalDotsIcon className="text-slate-400" />
            </Button>
          </DropdownTrigger>
          <DropdownMenu
            closeOnSelect
            aria-label="Actions"
            color="default"
            variant="flat"
          >
            <DropdownSection title="Download reports">
              <DropdownItem
                key="export"
                description="Available only for completed scans"
                textValue="Download .zip"
                startContent={<DownloadIcon className={iconClasses} />}
                onPress={() => downloadScanZip(scanId, toast)}
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
