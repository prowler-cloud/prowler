"use client";

import { ColumnDef, RowSelectionState } from "@tanstack/react-table";

import { DataTableRowActions } from "@/components/findings/table";
import {
  DeltaType,
  NotificationIndicator,
} from "@/components/findings/table/notification-indicator";
import { Checkbox } from "@/components/shadcn";
import { DateWithTime } from "@/components/ui/entities";
import {
  DataTableColumnHeader,
  Severity,
  SeverityBadge,
  StatusFindingBadge,
} from "@/components/ui/table";

export interface ResourceFinding {
  type: "findings";
  id: string;
  attributes: {
    status: "PASS" | "FAIL" | "MANUAL";
    severity: Severity;
    muted?: boolean;
    muted_reason?: string;
    delta?: DeltaType;
    updated_at?: string;
    check_metadata?: {
      checktitle?: string;
    };
  };
}

export const getResourceFindingsColumns = (
  rowSelection: RowSelectionState,
  selectableRowCount: number,
  onNavigate: (id: string) => void,
  onMuteComplete?: (findingIds: string[]) => void,
): ColumnDef<ResourceFinding>[] => {
  const selectedCount = Object.values(rowSelection).filter(Boolean).length;
  const isAllSelected =
    selectedCount > 0 && selectedCount === selectableRowCount;
  const isSomeSelected =
    selectedCount > 0 && selectedCount < selectableRowCount;

  return [
    {
      id: "notification",
      header: () => null,
      cell: ({ row }) => (
        <div className="flex items-center justify-center pr-4">
          <NotificationIndicator
            delta={row.original.attributes.delta}
            isMuted={row.original.attributes.muted}
            mutedReason={row.original.attributes.muted_reason}
          />
        </div>
      ),
      enableSorting: false,
      enableHiding: false,
    },
    {
      id: "select",
      header: ({ table }) => (
        <div className="ml-1 flex w-6 items-center justify-center pr-4">
          <Checkbox
            checked={
              isAllSelected ? true : isSomeSelected ? "indeterminate" : false
            }
            onCheckedChange={(checked) =>
              table.toggleAllPageRowsSelected(checked === true)
            }
            aria-label="Select all"
            disabled={selectableRowCount === 0}
          />
        </div>
      ),
      cell: ({ row }) => (
        <div className="ml-1 flex w-6 items-center justify-center pr-4">
          <Checkbox
            checked={!!rowSelection[row.id]}
            disabled={row.original.attributes.muted}
            onCheckedChange={(checked) => row.toggleSelected(checked === true)}
            aria-label="Select row"
          />
        </div>
      ),
      enableSorting: false,
    },
    {
      accessorKey: "status",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Status" />
      ),
      cell: ({ row }) => (
        <StatusFindingBadge status={row.original.attributes.status || "-"} />
      ),
      enableSorting: false,
    },
    {
      accessorKey: "finding",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Finding" />
      ),
      cell: ({ row }) => (
        <button
          onClick={() => onNavigate(row.original.id)}
          className="text-text-neutral-primary hover:text-button-tertiary max-w-[300px] cursor-pointer truncate text-left text-sm hover:underline"
        >
          {row.original.attributes.check_metadata?.checktitle ||
            "Unknown check"}
        </button>
      ),
      enableSorting: false,
    },
    {
      accessorKey: "severity",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Severity" />
      ),
      cell: ({ row }) => (
        <SeverityBadge severity={row.original.attributes.severity || "-"} />
      ),
      enableSorting: false,
    },
    {
      accessorKey: "updated_at",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Time" />
      ),
      cell: ({ row }) => (
        <DateWithTime dateTime={row.original.attributes.updated_at || "-"} />
      ),
      enableSorting: false,
    },
    {
      id: "actions",
      header: () => <div className="w-10" />,
      cell: ({ row }) => (
        <DataTableRowActions row={row} onMuteComplete={onMuteComplete} />
      ),
      enableSorting: false,
    },
  ];
};
