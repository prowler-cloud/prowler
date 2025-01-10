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
import { useRouter } from "next/navigation";
import { useState } from "react";

import { VerticalDotsIcon } from "@/components/icons";
import { CustomAlertModal } from "@/components/ui/custom";

import { DeleteForm, EditForm } from "../forms";

interface DataTableRowActionsProps<InvitationProps> {
  row: Row<InvitationProps>;
  roles?: { id: string; name: string }[];
}
const iconClasses =
  "text-2xl text-default-500 pointer-events-none flex-shrink-0";

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

  return (
    <>
      <CustomAlertModal
        isOpen={isEditOpen}
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
      </CustomAlertModal>
      <CustomAlertModal
        isOpen={isDeleteOpen}
        onOpenChange={setIsDeleteOpen}
        title="Are you absolutely sure?"
        description="This action cannot be undone. This will permanently revoke your invitation."
      >
        <DeleteForm invitationId={invitationId} setIsOpen={setIsDeleteOpen} />
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
                key="check-details"
                description="View invitation details"
                textValue="Check Details"
                startContent={<AddNoteBulkIcon className={iconClasses} />}
                onPress={() =>
                  router.push(`/invitations/check-details?id=${invitationId}`)
                }
              >
                Check Details
              </DropdownItem>

              <DropdownItem
                key="edit"
                description="Allows you to edit the invitation"
                textValue="Edit Invitation"
                startContent={<EditDocumentBulkIcon className={iconClasses} />}
                onPress={() => setIsEditOpen(true)}
              >
                Edit Invitation
              </DropdownItem>
            </DropdownSection>
            <DropdownSection title="Danger zone">
              <DropdownItem
                key="delete"
                className="text-danger"
                color="danger"
                description="Delete the invitation permanently"
                textValue="Delete Invitation"
                startContent={
                  <DeleteDocumentBulkIcon
                    className={clsx(iconClasses, "!text-danger")}
                  />
                }
                onPress={() => setIsDeleteOpen(true)}
              >
                Revoke Invitation
              </DropdownItem>
            </DropdownSection>
          </DropdownMenu>
        </Dropdown>
      </div>
    </>
  );
}
