"use client";

import {
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownSection,
  DropdownTrigger,
} from "@heroui/dropdown";
import {
  DeleteDocumentBulkIcon,
  EditDocumentBulkIcon,
} from "@heroui/shared-icons";
import { Row } from "@tanstack/react-table";
import clsx from "clsx";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { VerticalDotsIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";

import { DeleteRoleForm } from "../workflow/forms";
interface DataTableRowActionsProps<RoleProps> {
  row: Row<RoleProps>;
}
const iconClasses = "text-2xl text-default-500 pointer-events-none shrink-0";

export function DataTableRowActions<RoleProps>({
  row,
}: DataTableRowActionsProps<RoleProps>) {
  const router = useRouter();
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const roleId = (row.original as { id: string }).id;
  return (
    <>
      <Modal
        open={isDeleteOpen}
        onOpenChange={setIsDeleteOpen}
        title="Are you absolutely sure?"
        description="This action cannot be undone. This will permanently delete your role and remove your data from the server."
      >
        <DeleteRoleForm roleId={roleId} setIsOpen={setIsDeleteOpen} />
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
                className="text-text-error"
                color="danger"
                description="Delete the role permanently"
                textValue="Delete Role"
                startContent={
                  <DeleteDocumentBulkIcon
                    className={clsx(iconClasses, "!text-text-error")}
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
