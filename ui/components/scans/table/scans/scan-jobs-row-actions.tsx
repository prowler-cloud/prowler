"use client";

import { Download, Eye, Pencil } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { EditAliasModal } from "@/components/scans/edit-alias-modal";
import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { useToast } from "@/components/ui";
import { toLocalDateString } from "@/lib/date-utils";
import { downloadScanZip } from "@/lib/helper";
import type { ScanProps } from "@/types";

interface ScanJobsRowActionsProps {
  scan: ScanProps;
}

export function ScanJobsRowActions({ scan }: ScanJobsRowActionsProps) {
  const router = useRouter();
  const { toast } = useToast();
  const [editOpen, setEditOpen] = useState(false);
  const scanState = scan.attributes.state;
  const isCompleted = scanState === "completed";
  const scanDate = toLocalDateString(scan.attributes.completed_at);

  const openFindings = () => {
    if (!isCompleted || !scanDate) return;
    router.push(
      `/findings?filter[scan]=${scan.id}&filter[inserted_at]=${scanDate}&filter[status__in]=FAIL`,
    );
  };

  return (
    <div className="flex items-center justify-end">
      <ActionDropdown>
        {isCompleted && (
          <>
            <ActionDropdownItem
              icon={<Eye />}
              label="View Findings"
              onSelect={openFindings}
              disabled={!scanDate}
            />
            <ActionDropdownItem
              icon={<Download />}
              label="Download Findings"
              onSelect={() => downloadScanZip(scan.id, toast)}
            />
          </>
        )}
        {/* TODO: Expand Edit to also cover schedule once the backend exposes a schedule update endpoint. */}
        <ActionDropdownItem
          icon={<Pencil />}
          label="Edit"
          onSelect={() => setEditOpen(true)}
        />
        {/* TODO: Restore Cancel Scan once the backend exposes a public scan cancellation endpoint. */}
      </ActionDropdown>

      <EditAliasModal
        open={editOpen}
        onOpenChange={setEditOpen}
        scanId={scan.id}
        currentAlias={scan.attributes.name ?? ""}
      />
    </div>
  );
}
