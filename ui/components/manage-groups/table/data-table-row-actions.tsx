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
  DeleteDocumentBulkIcon,
  EditDocumentBulkIcon,
} from "@nextui-org/shared-icons";
import { Row } from "@tanstack/react-table";
import clsx from "clsx";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { VerticalDotsIcon } from "@/components/icons";
import { CustomAlertModal } from "@/components/ui/custom";

import { DeleteGroupForm } from "../forms";

interface DataTableRowActionsProps<ProviderProps> {
  row: Row<ProviderProps>;
}
const iconClasses =
  "text-2xl text-default-500 pointer-events-none flex-shrink-0";

export function DataTableRowActions<ProviderProps>({
  row,
}: DataTableRowActionsProps<ProviderProps>) {
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const groupId = (row.original as { id: string }).id;

  const router = useRouter();

  return (
    <>
      <CustomAlertModal
        isOpen={isDeleteOpen}
        onOpenChange={setIsDeleteOpen}
        title="Are you absolutely sure?"
        description="This action cannot be undone. This will permanently delete your provider account and remove your data from the server."
      >
        <DeleteGroupForm groupId={groupId} setIsOpen={setIsDeleteOpen} />
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
                description="Allows you to edit the provider group"
                textValue="Edit Provider Group"
                startContent={<EditDocumentBulkIcon className={iconClasses} />}
                onClick={() => router.push(`/manage-groups?groupId=${groupId}`)}
              >
                Edit Provider Group
              </DropdownItem>
            </DropdownSection>
            <DropdownSection title="Danger zone">
              <DropdownItem
                key="delete"
                className="text-danger"
                color="danger"
                description="Delete the provider group permanently"
                textValue="Delete Provider Group"
                startContent={
                  <DeleteDocumentBulkIcon
                    className={clsx(iconClasses, "!text-danger")}
                  />
                }
                onClick={() => setIsDeleteOpen(true)}
              >
                Delete Provider Group
              </DropdownItem>
            </DropdownSection>
          </DropdownMenu>
        </Dropdown>
      </div>
    </>
  );
}
