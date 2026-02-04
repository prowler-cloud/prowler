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
import { useState } from "react";

import { VerticalDotsIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";

import { DeleteForm, EditForm } from "../forms";

interface DataTableRowActionsProps<UserProps> {
  row: Row<UserProps>;
  roles?: { id: string; name: string }[];
}
const iconClasses = "text-2xl text-default-500 pointer-events-none shrink-0";

export function DataTableRowActions<UserProps>({
  row,
  roles,
}: DataTableRowActionsProps<UserProps>) {
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const userId = (row.original as { id: string }).id;
  const userName = (row.original as any).attributes?.name;
  const userEmail = (row.original as any).attributes?.email;
  const userCompanyName = (row.original as any).attributes?.company_name;
  const userRole = (row.original as any).attributes?.role?.name;

  return (
    <>
      <Modal
        open={isEditOpen}
        onOpenChange={setIsEditOpen}
        title="Edit user details"
      >
        <EditForm
          userId={userId}
          userName={userName}
          userEmail={userEmail}
          userCompanyName={userCompanyName}
          currentRole={userRole}
          roles={roles || []}
          setIsOpen={setIsEditOpen}
        />
      </Modal>
      <Modal
        open={isDeleteOpen}
        onOpenChange={setIsDeleteOpen}
        title="Are you absolutely sure?"
        description="This action cannot be undone. This will permanently delete your user account and remove your data from the server."
      >
        <DeleteForm userId={userId} setIsOpen={setIsDeleteOpen} />
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
                description="Allows you to edit the user"
                textValue="Edit User"
                startContent={<EditDocumentBulkIcon className={iconClasses} />}
                onPress={() => setIsEditOpen(true)}
              >
                Edit User
              </DropdownItem>
            </DropdownSection>
            <DropdownSection title="Danger zone">
              <DropdownItem
                key="delete"
                className="text-text-error"
                color="danger"
                description="Delete the user permanently"
                textValue="Delete User"
                startContent={
                  <DeleteDocumentBulkIcon
                    className={clsx(iconClasses, "!text-text-error")}
                  />
                }
                onPress={() => setIsDeleteOpen(true)}
              >
                Delete User
              </DropdownItem>
            </DropdownSection>
          </DropdownMenu>
        </Dropdown>
      </div>
    </>
  );
}
