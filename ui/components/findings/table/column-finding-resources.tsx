"use client";

import { ColumnDef, Row, RowSelectionState } from "@tanstack/react-table";
import { Container, CornerDownRight, VolumeOff, VolumeX } from "lucide-react";
import { useContext, useState } from "react";

import { MuteFindingsModal } from "@/components/findings/mute-findings-modal";
import { SendToJiraModal } from "@/components/findings/send-to-jira-modal";
import { JiraIcon } from "@/components/icons/services/IconServices";
import { Checkbox } from "@/components/shadcn";
import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { InfoField } from "@/components/shadcn/info-field/info-field";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { DateWithTime } from "@/components/ui/entities";
import { EntityInfo } from "@/components/ui/entities/entity-info";
import { SeverityBadge } from "@/components/ui/table";
import { DataTableColumnHeader } from "@/components/ui/table/data-table-column-header";
import {
  type FindingStatus,
  StatusFindingBadge,
} from "@/components/ui/table/status-finding-badge";
import { getFailingForLabel } from "@/lib/date-utils";
import { FindingResourceRow } from "@/types";

import { FindingsSelectionContext } from "./findings-selection-context";
import { NotificationIndicator } from "./notification-indicator";

const ResourceRowActions = ({ row }: { row: Row<FindingResourceRow> }) => {
  const resource = row.original;
  const [isMuteModalOpen, setIsMuteModalOpen] = useState(false);
  const [isJiraModalOpen, setIsJiraModalOpen] = useState(false);
  const [resolvedIds, setResolvedIds] = useState<string[]>([]);
  const [isResolving, setIsResolving] = useState(false);

  const { selectedFindingIds, clearSelection, resolveMuteIds, onMuteComplete } =
    useContext(FindingsSelectionContext) || {
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
    onMuteComplete?.();
  };

  return (
    <>
      {!resource.isMuted && (
        <MuteFindingsModal
          isOpen={isMuteModalOpen}
          onOpenChange={setIsMuteModalOpen}
          findingIds={resolvedIds}
          onComplete={handleMuteComplete}
        />
      )}
      <SendToJiraModal
        isOpen={isJiraModalOpen}
        onOpenChange={setIsJiraModalOpen}
        findingId={resource.findingId}
        findingTitle={resource.checkId}
      />
      <div
        className="flex items-center justify-end"
        onClick={(e) => e.stopPropagation()}
      >
        <ActionDropdown ariaLabel="Resource actions">
          <ActionDropdownItem
            icon={<JiraIcon size={20} />}
            label="Send to Jira"
            onSelect={() => setIsJiraModalOpen(true)}
          />
          <ActionDropdownItem
            icon={
              resource.isMuted ? (
                <VolumeOff className="size-5" />
              ) : isResolving ? (
                <Spinner className="size-5" />
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
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Resource" />
      ),
      cell: ({ row }) => (
        <div className="max-w-[240px]">
          <EntityInfo
            nameIcon={<Container className="size-4" />}
            entityAlias={row.original.resourceGroup}
            entityId={row.original.resourceUid}
          />
        </div>
      ),
      enableSorting: false,
    },
    // Status
    {
      id: "status",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Status" />
      ),
      cell: ({ row }) => {
        const rawStatus = row.original.status;
        const status =
          rawStatus === "MUTED" ? "FAIL" : (rawStatus as FindingStatus);
        return <StatusFindingBadge status={status} />;
      },
      enableSorting: false,
    },
    // Service
    {
      id: "service",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Service" />
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
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Region" />
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
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Severity" />
      ),
      cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
      enableSorting: false,
    },
    // Account — alias + uid (EntityInfo with provider logo)
    {
      id: "account",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Account" />
      ),
      cell: ({ row }) => (
        <div className="max-w-[240px]">
          <EntityInfo
            cloudProvider={row.original.providerType}
            entityAlias={row.original.providerAlias}
            entityId={row.original.providerUid}
          />
        </div>
      ),
      enableSorting: false,
    },
    // Last seen
    {
      id: "lastSeen",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Last seen" />
      ),
      cell: ({ row }) => (
        <InfoField label="Last seen" variant="compact">
          <DateWithTime dateTime={row.original.lastSeenAt} inline />
        </InfoField>
      ),
      enableSorting: false,
    },
    // Failing for — duration since first_seen_at
    {
      id: "failingFor",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Failing for" />
      ),
      cell: ({ row }) => {
        const duration = getFailingForLabel(row.original.firstSeenAt);
        return (
          <InfoField label="Failing for" variant="compact">
            {duration || "-"}
          </InfoField>
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
