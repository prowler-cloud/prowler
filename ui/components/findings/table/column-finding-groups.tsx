"use client";

import { ColumnDef, RowSelectionState } from "@tanstack/react-table";
import { ChevronRight } from "lucide-react";

import { Checkbox } from "@/components/shadcn";
import {
  DataTableColumnHeader,
  SeverityBadge,
  StatusFindingBadge,
} from "@/components/ui/table";
import { cn } from "@/lib";
import { FindingGroupRow, ProviderType } from "@/types";

import { DataTableRowActions } from "./data-table-row-actions";
import { ImpactedProvidersCell } from "./impacted-providers-cell";
import { ImpactedResourcesCell } from "./impacted-resources-cell";
import { DeltaValues, NotificationIndicator } from "./notification-indicator";

interface GetColumnFindingGroupsOptions {
  rowSelection: RowSelectionState;
  selectableRowCount: number;
  onDrillDown: (checkId: string, group: FindingGroupRow) => void;
  expandedCheckId?: string | null;
  /** True when the expanded group has individually selected resources */
  hasResourceSelection?: boolean;
}

export function getColumnFindingGroups({
  rowSelection,
  selectableRowCount,
  onDrillDown,
  expandedCheckId,
  hasResourceSelection = false,
}: GetColumnFindingGroupsOptions): ColumnDef<FindingGroupRow>[] {
  const selectedCount = Object.values(rowSelection).filter(Boolean).length;
  const isAllSelected =
    selectedCount > 0 && selectedCount === selectableRowCount;
  const isSomeSelected =
    selectedCount > 0 && selectedCount < selectableRowCount;

  return [
    // Combined column: notification + expand toggle + checkbox
    {
      id: "select",
      header: ({ table }) => {
        const headerChecked = isAllSelected
          ? true
          : isSomeSelected
            ? "indeterminate"
            : false;

        return (
          <div className="flex items-center gap-2">
            <div className="w-2" />
            <div className="w-4" />
            <Checkbox
              size="sm"
              checked={headerChecked}
              onCheckedChange={(checked) =>
                table.toggleAllPageRowsSelected(checked === true)
              }
              onClick={(e) => e.stopPropagation()}
              aria-label="Select all"
              disabled={selectableRowCount === 0}
            />
          </div>
        );
      },
      cell: ({ row }) => {
        const group = row.original;
        const allMuted =
          group.mutedCount > 0 && group.mutedCount === group.resourcesTotal;
        const isExpanded = expandedCheckId === group.checkId;

        const delta =
          group.newCount > 0
            ? DeltaValues.NEW
            : group.changedCount > 0
              ? DeltaValues.CHANGED
              : DeltaValues.NONE;

        return (
          <div className="flex items-center gap-2">
            <NotificationIndicator delta={delta} isMuted={allMuted} />
            <button
              type="button"
              aria-label={`Expand ${group.checkTitle}`}
              className="hover:bg-bg-neutral-tertiary flex size-4 shrink-0 items-center justify-center rounded-md transition-colors"
              onClick={() => onDrillDown(group.checkId, group)}
            >
              <ChevronRight
                className={cn(
                  "text-text-neutral-secondary size-4 transition-transform duration-200",
                  isExpanded && "rotate-90",
                )}
              />
            </button>
            <Checkbox
              size="sm"
              checked={
                rowSelection[row.id] && isExpanded && hasResourceSelection
                  ? "indeterminate"
                  : !!rowSelection[row.id]
              }
              onCheckedChange={(checked) => {
                // When indeterminate (resources selected), clicking deselects the group
                if (
                  rowSelection[row.id] &&
                  isExpanded &&
                  hasResourceSelection
                ) {
                  row.toggleSelected(false);
                } else {
                  row.toggleSelected(checked === true);
                }
              }}
              onClick={(e) => e.stopPropagation()}
              aria-label="Select row"
            />
          </div>
        );
      },
      enableSorting: false,
      enableHiding: false,
    },
    // Status column — not sortable on finding-groups endpoint
    {
      accessorKey: "status",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Status" />
      ),
      cell: ({ row }) => {
        const rawStatus = row.original.status as string;
        const status = rawStatus === "MUTED" ? "FAIL" : row.original.status;
        return <StatusFindingBadge status={status} />;
      },
      enableSorting: false,
    },
    // Finding title column
    {
      accessorKey: "finding",
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title="Finding Groups"
          param="check_id"
        />
      ),
      cell: ({ row }) => {
        const group = row.original;

        return (
          <div>
            <p
              className="text-text-neutral-primary hover:text-button-tertiary cursor-pointer text-left text-sm break-words whitespace-normal hover:underline"
              onClick={() => onDrillDown(group.checkId, group)}
            >
              {group.checkTitle}
            </p>
          </div>
        );
      },
    },
    // Severity column
    {
      accessorKey: "severity",
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title="Severity"
          param="severity"
        />
      ),
      cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
    },
    // Impacted Providers column
    {
      id: "impactedProviders",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Impacted Providers" />
      ),
      cell: ({ row }) => (
        <ImpactedProvidersCell
          providers={row.original.providers as ProviderType[]}
        />
      ),
      enableSorting: false,
    },
    // Impacted Resources column
    {
      id: "impactedResources",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Impacted Resources" />
      ),
      cell: ({ row }) => {
        const group = row.original;
        return (
          <ImpactedResourcesCell
            impacted={group.resourcesFail}
            total={group.resourcesTotal}
          />
        );
      },
      enableSorting: false,
    },
    // Actions column
    {
      id: "actions",
      header: () => <div className="w-10" />,
      cell: ({ row }) => <DataTableRowActions row={row} />,
      enableSorting: false,
    },
  ];
}
