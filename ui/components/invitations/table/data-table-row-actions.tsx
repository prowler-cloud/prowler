"use client";

import { Row } from "@tanstack/react-table";
import { Eye, Pencil, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  ActionDropdown,
  ActionDropdownDangerZone,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { Modal } from "@/components/shadcn/modal";
import { InvitationProps } from "@/types";

import { DeleteForm, EditForm } from "../forms";

interface DataTableRowActionsProps {
  row: Row<InvitationProps>;
  roles?: { id: string; name: string }[];
}

export function DataTableRowActions({ row, roles }: DataTableRowActionsProps) {
  const router = useRouter();
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const invitationId = row.original.id;
  const invitationEmail = row.original.attributes.email;
  const invitationRole = row.original.relationships.role?.attributes?.name;
  const isInvitationPending = row.original.attributes.state === "pending";

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
        <ActionDropdown>
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
            disabled={!isInvitationPending}
          />
          <ActionDropdownDangerZone>
            <ActionDropdownItem
              icon={<Trash2 />}
              label="Revoke Invitation"
              destructive
              onSelect={() => setIsDeleteOpen(true)}
              disabled={!isInvitationPending}
            />
          </ActionDropdownDangerZone>
        </ActionDropdown>
      </div>
    </>
  );
}
