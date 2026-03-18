"use client";

import { ColumnDef, Row, RowSelectionState } from "@tanstack/react-table";
import { CornerDownRight, VolumeOff, VolumeX } from "lucide-react";
import { useContext, useState } from "react";

import { MuteFindingsModal } from "@/components/findings/mute-findings-modal";
import { VerticalDotsIcon } from "@/components/icons";
import { Checkbox } from "@/components/shadcn";
import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { DateWithTime } from "@/components/ui/entities";
import { EntityInfo } from "@/components/ui/entities/entity-info";
import { SeverityBadge } from "@/components/ui/table";
import { FindingResourceRow } from "@/types";

import { FindingsSelectionContext } from "./findings-selection-context";
import { NotificationIndicator } from "./notification-indicator";

/**
 * Computes a human-readable "failing for" duration from first_seen_at to now.
 * Returns null if the resource is not failing or has no first_seen_at.
 */
function getFailingForLabel(firstSeenAt: string | null): string | null {
  if (!firstSeenAt) return null;

  const start = new Date(firstSeenAt);
  if (isNaN(start.getTime())) return null;

  const now = new Date();
  const diffMs = now.getTime() - start.getTime();
  if (diffMs < 0) return null;

  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffDays < 1) return "< 1 day";
  if (diffDays < 30) return `${diffDays} day${diffDays > 1 ? "s" : ""}`;

  const diffMonths = Math.floor(diffDays / 30);
  if (diffMonths < 12)
    return `${diffMonths} month${diffMonths > 1 ? "s" : ""}`;

  const diffYears = Math.floor(diffMonths / 12);
  return `${diffYears} year${diffYears > 1 ? "s" : ""}`;
}

const ResourceRowActions = ({ row }: { row: Row<FindingResourceRow> }) => {
  const resource = row.original;
  const [isMuteModalOpen, setIsMuteModalOpen] = useState(false);

  const { selectedFindingIds, clearSelection } =
    useContext(FindingsSelectionContext) || {
      selectedFindingIds: [],
      clearSelection: () => {},
    };

  const isCurrentSelected = selectedFindingIds.includes(resource.findingId);
  const hasMultipleSelected = selectedFindingIds.length > 1;

  const getMuteIds = (): string[] => {
    if (isCurrentSelected && hasMultipleSelected) {
      return selectedFindingIds;
    }
    return [resource.findingId];
  };

  const getMuteLabel = () => {
    if (resource.isMuted) return "Muted";
    const ids = getMuteIds();
    if (ids.length > 1) return `Mute ${ids.length}`;
    return "Mute";
  };

  return (
    <>
      <MuteFindingsModal
        isOpen={isMuteModalOpen}
        onOpenChange={setIsMuteModalOpen}
        findingIds={getMuteIds()}
        onComplete={clearSelection}
      />
      <div className="flex items-center justify-end">
        <ActionDropdown
          trigger={
            <button
              type="button"
              aria-label="Resource actions"
              className="hover:bg-bg-neutral-tertiary rounded-md p-1 transition-colors"
            >
              <VerticalDotsIcon
                size={20}
                className="text-text-neutral-secondary"
              />
            </button>
          }
          ariaLabel="Resource actions"
        >
          <ActionDropdownItem
            icon={
              resource.isMuted ? (
                <VolumeOff className="size-5" />
              ) : (
                <VolumeX className="size-5" />
              )
            }
            label={getMuteLabel()}
            disabled={resource.isMuted}
            onSelect={() => setIsMuteModalOpen(true)}
          />
        </ActionDropdown>
      </div>
    </>
  );
};

interface GetColumnFindingResourcesOptions {
  rowSelection: RowSelectionState;
  selectableRowCount: number;
}

export function getColumnFindingResources({
  rowSelection,
  selectableRowCount,
}: GetColumnFindingResourcesOptions): ColumnDef<FindingResourceRow>[] {
  const selectedCount = Object.values(rowSelection).filter(Boolean).length;
  const isAllSelected =
    selectedCount > 0 && selectedCount === selectableRowCount;
  const isSomeSelected =
    selectedCount > 0 && selectedCount < selectableRowCount;

  return [
    // Notification column — muted indicator only
    {
      id: "notification",
      header: () => null,
      cell: ({ row }) => (
        <NotificationIndicator
          isMuted={row.original.isMuted}
          mutedReason={row.original.mutedReason}
        />
      ),
      enableSorting: false,
      enableHiding: false,
    },
    // Child icon — corner-down-right arrow
    {
      id: "childIcon",
      header: () => null,
      cell: () => (
        <div className="flex size-6 items-center justify-center">
          <CornerDownRight className="text-text-neutral-tertiary size-4" />
        </div>
      ),
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
              aria-label="Select all resources"
              disabled={selectableRowCount === 0}
            />
          </div>
        );
      },
      cell: ({ row }) => (
        <div className="ml-1 flex w-6 items-center justify-center pr-4">
          <Checkbox
            checked={!!rowSelection[row.id]}
            disabled={row.original.isMuted}
            onCheckedChange={(checked) =>
              row.toggleSelected(checked === true)
            }
            aria-label="Select resource"
          />
        </div>
      ),
      enableSorting: false,
      enableHiding: false,
    },
    // Resource — name + uid (EntityInfo with resource icon)
    {
      id: "resource",
      header: () => (
        <span className="text-text-neutral-secondary text-sm font-medium">
          Resource
        </span>
      ),
      cell: ({ row }) => (
        <EntityInfo
          entityAlias={row.original.resourceName}
          entityId={row.original.resourceUid}
        />
      ),
      enableSorting: false,
    },
    // Service
    {
      id: "service",
      header: () => (
        <span className="text-text-neutral-secondary text-sm font-medium">
          Service
        </span>
      ),
      cell: ({ row }) => (
        <p className="text-text-neutral-primary max-w-[100px] truncate text-sm">
          {row.original.service}
        </p>
      ),
      enableSorting: false,
    },
    // Region
    {
      id: "region",
      header: () => (
        <span className="text-text-neutral-secondary text-sm font-medium">
          Region
        </span>
      ),
      cell: ({ row }) => (
        <p className="text-text-neutral-primary max-w-[120px] truncate text-sm">
          {row.original.region}
        </p>
      ),
      enableSorting: false,
    },
    // Severity
    {
      id: "severity",
      header: () => (
        <span className="text-text-neutral-secondary text-sm font-medium">
          Severity
        </span>
      ),
      cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
      enableSorting: false,
    },
    // Account — alias + uid (EntityInfo with provider logo)
    {
      id: "account",
      header: () => (
        <span className="text-text-neutral-secondary text-sm font-medium">
          Account
        </span>
      ),
      cell: ({ row }) => (
        <EntityInfo
          cloudProvider={row.original.providerType}
          entityAlias={row.original.providerAlias}
          entityId={row.original.providerUid}
        />
      ),
      enableSorting: false,
    },
    // Last seen
    {
      id: "lastSeen",
      header: () => (
        <span className="text-text-neutral-secondary text-sm font-medium">
          Last seen
        </span>
      ),
      cell: ({ row }) => (
        <DateWithTime dateTime={row.original.lastSeenAt} />
      ),
      enableSorting: false,
    },
    // Failing for — duration since first_seen_at
    {
      id: "failingFor",
      header: () => (
        <span className="text-text-neutral-secondary text-sm font-medium">
          Failing for
        </span>
      ),
      cell: ({ row }) => {
        const label = getFailingForLabel(row.original.firstSeenAt);
        return (
          <p className="text-text-neutral-primary text-sm">
            {label || "-"}
          </p>
        );
      },
      enableSorting: false,
    },
    // Actions column — mute only
    {
      id: "actions",
      header: () => <div className="w-10" />,
      cell: ({ row }) => <ResourceRowActions row={row} />,
      enableSorting: false,
    },
  ];
}
