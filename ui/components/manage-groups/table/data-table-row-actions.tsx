"use client";

import { Row } from "@tanstack/react-table";
import { Pencil, Trash2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { VerticalDotsIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import {
  ActionDropdown,
  ActionDropdownItem,
  ActionDropdownLabel,
  ActionDropdownSeparator,
} from "@/components/shadcn/dropdown";
import { Modal } from "@/components/shadcn/modal";

import { DeleteGroupForm } from "../forms";

interface DataTableRowActionsProps<ProviderProps> {
  row: Row<ProviderProps>;
}

export function DataTableRowActions<ProviderProps>({
  row,
}: DataTableRowActionsProps<ProviderProps>) {
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const groupId = (row.original as { id: string }).id;

  const router = useRouter();

  return (
    <>
      <Modal
        open={isDeleteOpen}
        onOpenChange={setIsDeleteOpen}
        title="Are you absolutely sure?"
        description="This action cannot be undone. This will permanently delete your provider account and remove your data from the server."
      >
        <DeleteGroupForm groupId={groupId} setIsOpen={setIsDeleteOpen} />
      </Modal>

      <div className="relative flex items-center justify-end gap-2">
        <ActionDropdown
          trigger={
            <Button variant="ghost" size="icon-sm" className="rounded-full">
              <VerticalDotsIcon className="text-slate-400" />
            </Button>
          }
          label="Actions"
        >
          <ActionDropdownItem
            icon={<Pencil />}
            label="Edit Provider Group"
            description="Allows you to edit the provider group"
            onSelect={() => router.push(`/manage-groups?groupId=${groupId}`)}
          />
          <ActionDropdownSeparator />
          <ActionDropdownLabel>Danger zone</ActionDropdownLabel>
          <ActionDropdownItem
            icon={<Trash2 />}
            label="Delete Provider Group"
            description="Delete the provider group permanently"
            destructive
            onSelect={() => setIsDeleteOpen(true)}
          />
        </ActionDropdown>
      </div>
    </>
  );
}
