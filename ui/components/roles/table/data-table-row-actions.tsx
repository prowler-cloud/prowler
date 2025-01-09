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
import { CustomAlertModal } from "@/components/ui/custom/custom-alert-modal";

import { DeleteRoleForm } from "../workflow/forms";
interface DataTableRowActionsProps<RoleProps> {
  row: Row<RoleProps>;
}
const iconClasses =
  "text-2xl text-default-500 pointer-events-none flex-shrink-0";

export function DataTableRowActions<RoleProps>({
  row,
}: DataTableRowActionsProps<RoleProps>) {
  const router = useRouter();
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const roleId = (row.original as { id: string }).id;
  return (
    <>
      <CustomAlertModal
        isOpen={isDeleteOpen}
        onOpenChange={setIsDeleteOpen}
        title="Are you absolutely sure?"
        description="This action cannot be undone. This will permanently delete your role and remove your data from the server."
      >
        <DeleteRoleForm roleId={roleId} setIsOpen={setIsDeleteOpen} />
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
                description="Edit the role details"
                textValue="Edit Role"
                startContent={<EditDocumentBulkIcon className={iconClasses} />}
                onPress={() => router.push(`/roles/edit?roleId=${roleId}`)}
              >
                Edit Role
              </DropdownItem>
            </DropdownSection>
            <DropdownSection title="Danger zone">
              <DropdownItem
                key="delete"
                className="text-danger"
                color="danger"
                description="Delete the role permanently"
                textValue="Delete Role"
                startContent={
                  <DeleteDocumentBulkIcon
                    className={clsx(iconClasses, "!text-danger")}
                  />
                }
                onPress={() => setIsDeleteOpen(true)}
              >
                Delete Role
              </DropdownItem>
            </DropdownSection>
          </DropdownMenu>
        </Dropdown>
      </div>
    </>
  );
}
