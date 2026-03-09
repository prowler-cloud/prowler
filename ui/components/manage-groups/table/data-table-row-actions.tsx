"use client";

import { Row } from "@tanstack/react-table";
import { Pencil, Trash2 } from "lucide-react";
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
        >
          <ActionDropdownItem
            icon={<Pencil />}
            label="Edit Provider Group"
            onSelect={() => router.push(`/manage-groups?groupId=${groupId}`)}
          />
          <ActionDropdownDangerZone>
            <ActionDropdownItem
              icon={<Trash2 />}
              label="Delete Provider Group"
              destructive
              onSelect={() => setIsDeleteOpen(true)}
            />
          </ActionDropdownDangerZone>
        </ActionDropdown>
      </div>
    </>
  );
}
