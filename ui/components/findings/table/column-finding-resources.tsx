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
import { getFailingForLabel } from "@/lib/date-utils";
import { FindingResourceRow } from "@/types";

import { FindingsSelectionContext } from "./findings-selection-context";
import { NotificationIndicator } from "./notification-indicator";

const ResourceRowActions = ({ row }: { row: Row<FindingResourceRow> }) => {
  const resource = row.original;
  const [isMuteModalOpen, setIsMuteModalOpen] = useState(false);
  const [resolvedIds, setResolvedIds] = useState<string[]>([]);
  const [isResolving, setIsResolving] = useState(false);

  const { selectedFindingIds, clearSelection, resolveMuteIds } = useContext(
    FindingsSelectionContext,
  ) || {
    selectedFindingIds: [],
    clearSelection: () => {},
  };

  const isCurrentSelected = selectedFindingIds.includes(resource.findingId);
  const hasMultipleSelected = selectedFindingIds.length > 1;

  const getDisplayIds = (): string[] => {
    if (isCurrentSelected && hasMultipleSelected) {
      return selectedFindingIds;
    }
    return [resource.findingId];
  };

  const getMuteLabel = () => {
    if (resource.isMuted) return "Muted";
    const ids = getDisplayIds();
    if (ids.length > 1) return `Mute ${ids.length}`;
    return "Mute";
  };

  const handleMuteClick = async () => {
    const displayIds = getDisplayIds();

    if (resolveMuteIds) {
      setIsResolving(true);
      const ids = await resolveMuteIds(displayIds);
      setResolvedIds(ids);
      setIsResolving(false);
      if (ids.length > 0) setIsMuteModalOpen(true);
    } else {
      setResolvedIds(displayIds);
      setIsMuteModalOpen(true);
    }
  };

  const handleMuteComplete = () => {
    clearSelection();
    setResolvedIds([]);
  };

  return (
    <>
      <MuteFindingsModal
        isOpen={isMuteModalOpen}
        onOpenChange={setIsMuteModalOpen}
        findingIds={resolvedIds}
        onComplete={handleMuteComplete}
      />
      <div
        className="flex items-center justify-end"
        onClick={(e) => e.stopPropagation()}
      >
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
              ) : isResolving ? (
                <div className="size-5 animate-spin rounded-full border-2 border-current border-t-transparent" />
              ) : (
                <VolumeX className="size-5" />
              )
            }
            label={isResolving ? "Resolving..." : getMuteLabel()}
            disabled={resource.isMuted || isResolving}
            onSelect={handleMuteClick}
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
    // Combined column: notification + child icon + checkbox
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
              aria-label="Select all resources"
              disabled={selectableRowCount === 0}
            />
          </div>
        );
      },
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <NotificationIndicator
            isMuted={row.original.isMuted}
            mutedReason={row.original.mutedReason}
          />
          <CornerDownRight className="text-text-neutral-tertiary h-4 w-4 shrink-0" />
          <Checkbox
            size="sm"
            checked={!!rowSelection[row.id]}
            disabled={row.original.isMuted}
            onCheckedChange={(checked) => row.toggleSelected(checked === true)}
            onClick={(e) => e.stopPropagation()}
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
      cell: ({ row }) => <DateWithTime dateTime={row.original.lastSeenAt} />,
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
          <p className="text-text-neutral-primary text-sm">{label || "-"}</p>
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
