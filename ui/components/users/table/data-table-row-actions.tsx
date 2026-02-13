"use client";

import { Row } from "@tanstack/react-table";
import { Pencil, Trash2 } from "lucide-react";
import { useState } from "react";

import { VerticalDotsIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import {
  ActionDropdown,
  ActionDropdownDangerZone,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { Modal } from "@/components/shadcn/modal";

import { DeleteForm, EditForm } from "../forms";

interface DataTableRowActionsProps<UserProps> {
  row: Row<UserProps>;
  roles?: { id: string; name: string }[];
}

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
        <ActionDropdown
          trigger={
            <Button variant="ghost" size="icon-sm" className="rounded-full">
              <VerticalDotsIcon className="text-slate-400" />
            </Button>
          }
        >
          <ActionDropdownItem
            icon={<Pencil />}
            label="Edit User"
            onSelect={() => setIsEditOpen(true)}
          />
          <ActionDropdownDangerZone>
            <ActionDropdownItem
              icon={<Trash2 />}
              label="Delete User"
              destructive
              onSelect={() => setIsDeleteOpen(true)}
            />
          </ActionDropdownDangerZone>
        </ActionDropdown>
      </div>
    </>
  );
}
