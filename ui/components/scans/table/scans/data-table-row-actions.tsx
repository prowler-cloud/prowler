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
// import clsx from "clsx";
import { useState } from "react";

import { VerticalDotsIcon } from "@/components/icons";
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
  const [isEditOpen, setIsEditOpen] = useState(false);
  const scanId = (row.original as { id: string }).id;
  const scanName = (row.original as any).attributes?.name;
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
            <DropdownSection title="Actions">
              <DropdownItem
                key="edit"
                description="Allows you to edit the scan name"
                textValue="Edit Scan Name"
                startContent={<EditDocumentBulkIcon className={iconClasses} />}
                onClick={() => setIsEditOpen(true)}
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
