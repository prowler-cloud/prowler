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
  AddNoteBulkIcon,
  DeleteDocumentBulkIcon,
  EditDocumentBulkIcon,
} from "@nextui-org/shared-icons";
import { Row } from "@tanstack/react-table";
import clsx from "clsx";
import { useState } from "react";

import { VerticalDotsIcon } from "@/components/icons";
import { CustomAlertModal } from "@/components/ui/custom";

import { CheckConnectionProvider } from "../CheckConnectionProvider";
import { DeleteForm } from "../forms/DeleteForm";
import EditForm from "../forms/EditForm";

interface DataTableRowActionsProps<ProviderProps> {
  row: Row<ProviderProps>;
}
const iconClasses =
  "text-2xl text-default-500 pointer-events-none flex-shrink-0";

export function DataTableRowActions<ProviderProps>({
  row,
}: DataTableRowActionsProps<ProviderProps>) {
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const providerId = (row.original as { id: string }).id;
  return (
    <>
      <CustomAlertModal
        isOpen={isEditOpen}
        onOpenChange={setIsEditOpen}
        title="Edit Provider"
        description={"Edit the provider details"}
      >
        <EditForm providerId={providerId} setIsOpen={setIsEditOpen} />
      </CustomAlertModal>
      <CustomAlertModal
        isOpen={isDeleteOpen}
        onOpenChange={setIsDeleteOpen}
        title="Are you absolutely sure?"
        description="This action cannot be undone. This will permanently delete your provider account and remove your data from the server."
      >
        <DeleteForm providerId={providerId} setIsOpen={setIsDeleteOpen} />
      </CustomAlertModal>

      <div className="relative flex justify-end items-center gap-2">
        <Dropdown className="shadow-xl" placement="bottom">
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
                key="new"
                description="Check the connection to the provider"
                shortcut="⌘N"
                textValue="Check Connection"
                startContent={<AddNoteBulkIcon className={iconClasses} />}
              >
                <CheckConnectionProvider id={providerId} />
              </DropdownItem>
              <DropdownItem
                key="edit"
                description="Allows you to edit the provider"
                shortcut="⌘⇧E"
                textValue="Edit Provider"
                startContent={<EditDocumentBulkIcon className={iconClasses} />}
                onClick={() => setIsEditOpen(true)}
              >
                Edit Provider
              </DropdownItem>
            </DropdownSection>
            <DropdownSection title="Danger zone">
              <DropdownItem
                key="delete"
                className="text-danger"
                color="danger"
                description="Delete the provider permanently"
                textValue="Delete Provider"
                shortcut="⌘⇧D"
                startContent={
                  <DeleteDocumentBulkIcon
                    className={clsx(iconClasses, "!text-danger")}
                  />
                }
                onClick={() => setIsDeleteOpen(true)}
              >
                Delete Provider
              </DropdownItem>
            </DropdownSection>
          </DropdownMenu>
        </Dropdown>
      </div>
    </>
  );
}
