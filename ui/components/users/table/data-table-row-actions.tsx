"use client";

import { Row } from "@tanstack/react-table";
import { Pencil, Trash2, UserMinus } from "lucide-react";
import { useState } from "react";

import {
  ActionDropdown,
  ActionDropdownDangerZone,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { Modal } from "@/components/shadcn/modal";

import { DeleteForm, EditForm, ExpelUserForm } from "../forms";

interface UserRowRole {
  name?: string;
}

interface UserRowAttributes {
  name?: string;
  email?: string;
  company_name?: string;
  role?: UserRowRole;
}

interface UserRowData {
  id: string;
  attributes?: UserRowAttributes;
  canBeExpelled?: boolean;
  currentTenantId?: string;
}

interface DataTableRowActionsProps<UserProps extends UserRowData> {
  row: Row<UserProps>;
  roles?: { id: string; name: string }[];
}

export function DataTableRowActions<UserProps extends UserRowData>({
  row,
  roles,
}: DataTableRowActionsProps<UserProps>) {
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const [isExpelOpen, setIsExpelOpen] = useState(false);
  const userId = row.original.id;
  const userName = row.original.attributes?.name;
  const userEmail = row.original.attributes?.email;
  const userCompanyName = row.original.attributes?.company_name;
  const userRole = row.original.attributes?.role?.name;

  // Expel gate is resolved server-side against the active tenant's membership
  // role (owner vs member), mirroring the backend rule in
  // TenantMembersViewSet.destroy. The row is only expel-eligible when the
  // current user is an owner of the active tenant and the row is not theirs.
  const canExpelUser =
    row.original.canBeExpelled === true && !!row.original.currentTenantId;
  const currentTenantId = row.original.currentTenantId;

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
      {canExpelUser && currentTenantId && (
        <Modal
          open={isExpelOpen}
          onOpenChange={setIsExpelOpen}
          title="Expel user from this organization"
        >
          <ExpelUserForm
            userId={userId}
            userName={userName}
            tenantId={currentTenantId}
            setIsOpen={setIsExpelOpen}
          />
        </Modal>
      )}

      <div className="relative flex items-center justify-end gap-2">
        <ActionDropdown>
          <ActionDropdownItem
            icon={<Pencil aria-hidden="true" />}
            label="Edit User"
            onSelect={() => setIsEditOpen(true)}
          />
          <ActionDropdownDangerZone>
            {canExpelUser && (
              <ActionDropdownItem
                icon={<UserMinus aria-hidden="true" />}
                label="Expel from organization"
                destructive
                onSelect={() => setIsExpelOpen(true)}
              />
            )}
            <ActionDropdownItem
              icon={<Trash2 aria-hidden="true" />}
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
