"use client";

import { Row } from "@tanstack/react-table";
import { Download, Pencil } from "lucide-react";
import { useState } from "react";

import { VerticalDotsIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/ui";
import { downloadScanZip } from "@/lib/helper";

import { EditScanForm } from "../../forms";

interface DataTableRowActionsProps<ScanProps> {
  row: Row<ScanProps>;
}

export function DataTableRowActions<ScanProps>({
  row,
}: DataTableRowActionsProps<ScanProps>) {
  const { toast } = useToast();
  const [isEditOpen, setIsEditOpen] = useState(false);
  const scanId = (row.original as { id: string }).id;
  const scanName = (row.original as any).attributes?.name;
  const scanState = (row.original as any).attributes?.state;

  return (
    <>
      <Modal
        open={isEditOpen}
        onOpenChange={setIsEditOpen}
        title="Edit Scan Name"
      >
        <EditScanForm
          scanId={scanId}
          scanName={scanName}
          setIsOpen={setIsEditOpen}
        />
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
            icon={<Download />}
            label="Download .zip"
            description="Available only for completed scans"
            onSelect={() => downloadScanZip(scanId, toast)}
            disabled={scanState !== "completed"}
          />
          <ActionDropdownItem
            icon={<Pencil />}
            label="Edit Scan Name"
            onSelect={() => setIsEditOpen(true)}
          />
        </ActionDropdown>
      </div>
    </>
  );
}
