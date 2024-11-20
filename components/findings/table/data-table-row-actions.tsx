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
  // AddNoteBulkIcon,
  EditDocumentBulkIcon,
} from "@nextui-org/shared-icons";
import { Row } from "@tanstack/react-table";

// import { useState } from "react";
import { VerticalDotsIcon } from "@/components/icons";
// import { CustomAlertModal } from "@/components/ui/custom";

// import { EditForm } from "../forms";
// import { DeleteForm } from "../forms/delete-form";

interface DataTableRowActionsProps<FindingProps> {
  row: Row<FindingProps>;
}
const iconClasses =
  "text-2xl text-default-500 pointer-events-none flex-shrink-0";

export function DataTableRowActions<FindingProps>({
  row,
}: DataTableRowActionsProps<FindingProps>) {
  const findingId = (row.original as { id: string }).id;
  return (
    <>
      {/* <CustomAlertModal
        isOpen={isEditOpen}
        onOpenChange={setIsEditOpen}
        title="Edit Provider"
        description={"Edit the provider details"}
      >
        <EditForm
          providerId={providerId}
          providerAlias={providerAlias}
          setIsOpen={setIsEditOpen}
        />
      </CustomAlertModal>
      <CustomAlertModal
        isOpen={isDeleteOpen}
        onOpenChange={setIsDeleteOpen}
        title="Are you absolutely sure?"
        description="This action cannot be undone. This will permanently delete your provider account and remove your data from the server."
      >
        <DeleteForm providerId={providerId} setIsOpen={setIsDeleteOpen} />
      </CustomAlertModal> */}

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
                key="jira"
                description="Allows you to send the finding to Jira"
                textValue="Send to Jira"
                startContent={<EditDocumentBulkIcon className={iconClasses} />}
                // onClick={() => setIsEditOpen(true)}
              >
                <span className="hidden text-sm">{findingId}</span>
                Send to Jira
              </DropdownItem>
              <DropdownItem
                key="slack"
                description="Allows you to send the finding to Slack"
                textValue="Send to Slack"
                startContent={<EditDocumentBulkIcon className={iconClasses} />}
                // onClick={() => setIsEditOpen(true)}
              >
                Send to Slack
              </DropdownItem>
            </DropdownSection>
          </DropdownMenu>
        </Dropdown>
      </div>
    </>
  );
}
