"use client";

import { Row } from "@tanstack/react-table";
import { Eye, Pencil, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
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

interface DataTableRowActionsProps<InvitationProps> {
  row: Row<InvitationProps>;
  roles?: { id: string; name: string }[];
}

export function DataTableRowActions<InvitationProps>({
  row,
  roles,
}: DataTableRowActionsProps<InvitationProps>) {
  const router = useRouter();
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const invitationId = (row.original as { id: string }).id;
  const invitationEmail = (row.original as any).attributes?.email;
  const invitationRole = (row.original as any).relationships?.role?.attributes
    ?.name;
  const invitationAccepted = (row.original as any).attributes?.state;

  return (
    <>
      <Modal
        open={isEditOpen}
        onOpenChange={setIsEditOpen}
        title="Edit invitation details"
      >
        <EditForm
          invitationId={invitationId}
          invitationEmail={invitationEmail}
          currentRole={invitationRole}
          roles={roles || []}
          setIsOpen={setIsEditOpen}
        />
      </Modal>
      <Modal
        open={isDeleteOpen}
        onOpenChange={setIsDeleteOpen}
        title="Are you absolutely sure?"
        description="This action cannot be undone. This will permanently revoke your invitation."
      >
        <DeleteForm invitationId={invitationId} setIsOpen={setIsDeleteOpen} />
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
            icon={<Eye />}
            label="Check Details"
            onSelect={() =>
              router.push(`/invitations/check-details?id=${invitationId}`)
            }
          />
          <ActionDropdownItem
            icon={<Pencil />}
            label="Edit Invitation"
            onSelect={() => setIsEditOpen(true)}
            disabled={invitationAccepted === "accepted"}
          />
          <ActionDropdownDangerZone>
            <ActionDropdownItem
              icon={<Trash2 />}
              label="Revoke Invitation"
              destructive
              onSelect={() => setIsDeleteOpen(true)}
              disabled={invitationAccepted === "accepted"}
            />
          </ActionDropdownDangerZone>
        </ActionDropdown>
      </div>
    </>
  );
}
