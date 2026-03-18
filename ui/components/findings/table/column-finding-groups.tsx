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
}

export function getColumnFindingGroups({
  rowSelection,
  selectableRowCount,
  onDrillDown,
}: GetColumnFindingGroupsOptions): ColumnDef<FindingGroupRow>[] {
  const selectedCount = Object.values(rowSelection).filter(Boolean).length;
  const isAllSelected =
    selectedCount > 0 && selectedCount === selectableRowCount;
  const isSomeSelected =
    selectedCount > 0 && selectedCount < selectableRowCount;

  return [
    // Notification column — delta derived from new_count / changed_count
    {
      id: "notification",
      header: () => null,
      cell: ({ row }) => {
        const group = row.original;
        const allMuted =
          group.mutedCount > 0 && group.mutedCount === group.resourcesTotal;

        const delta =
          group.newCount > 0
            ? DeltaValues.NEW
            : group.changedCount > 0
              ? DeltaValues.CHANGED
              : DeltaValues.NONE;

        return <NotificationIndicator delta={delta} isMuted={allMuted} />;
      },
      enableSorting: false,
      enableHiding: false,
    },
    // Expand column — chevron only if resources_total > 1
    {
      id: "expand",
      header: () => null,
      cell: ({ row }) => {
        const group = row.original;

        if (group.resourcesTotal <= 1) {
          return <div className="w-6" />;
        }

        return (
          <button
            type="button"
            aria-label={`Expand ${group.checkTitle}`}
            className="hover:bg-bg-neutral-tertiary flex size-6 items-center justify-center rounded-md transition-colors"
            onClick={() => onDrillDown(group.checkId, group)}
          >
            <ChevronRight className="text-text-neutral-secondary size-4" />
          </button>
        );
      },
      enableSorting: false,
      enableHiding: false,
    },
    // Select column
    {
      id: "select",
      header: ({ table }) => {
        const headerChecked = isAllSelected
          ? true
          : isSomeSelected
            ? "indeterminate"
            : false;

        return (
          <div className="ml-1 flex w-6 items-center justify-center pr-4">
            <Checkbox
              checked={headerChecked}
              onCheckedChange={(checked) =>
                table.toggleAllPageRowsSelected(checked === true)
              }
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
        const isSelected = !!rowSelection[row.id];

        return (
          <div className="ml-1 flex w-6 items-center justify-center pr-4">
            <Checkbox
              checked={isSelected}
              disabled={allMuted}
              onCheckedChange={(checked) =>
                row.toggleSelected(checked === true)
              }
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
      cell: ({ row }) => <StatusFindingBadge status={row.original.status} />,
      enableSorting: false,
    },
    // Finding title column
    {
      accessorKey: "finding",
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title="Finding"
          param="check_id"
        />
      ),
      cell: ({ row }) => {
        const group = row.original;

        return (
          <div className="max-w-[500px]">
            <p
              className={cn(
                "text-text-neutral-primary text-left text-sm break-words whitespace-normal",
                group.resourcesTotal > 1 &&
                  "hover:text-button-tertiary cursor-pointer hover:underline",
              )}
              onClick={
                group.resourcesTotal > 1
                  ? () => onDrillDown(group.checkId, group)
                  : undefined
              }
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
        <DataTableColumnHeader column={column} title="Providers" />
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
        <DataTableColumnHeader column={column} title="Resources" />
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
