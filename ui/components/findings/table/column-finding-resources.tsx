"use client";

import { ColumnDef, Row, RowSelectionState } from "@tanstack/react-table";
import { CornerDownRight, VolumeOff, VolumeX } from "lucide-react";
import { useContext, useState } from "react";

import { JiraDispatchActionItem } from "@/components/findings/jira-dispatch-action-item";
import { MuteFindingsModal } from "@/components/findings/mute-findings-modal";
import { Checkbox } from "@/components/shadcn";
import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { DateWithTime } from "@/components/shadcn/entities";
import { EntityInfo } from "@/components/shadcn/entities/entity-info";
import { InfoField } from "@/components/shadcn/info-field/info-field";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { SeverityBadge } from "@/components/shadcn/table";
import { DataTableColumnHeader } from "@/components/shadcn/table/data-table-column-header";
import { getFailingForLabel } from "@/lib/date-utils";
import { buildJiraActionLabel } from "@/lib/jira-dispatch-action";
import { createJiraDispatchPayload } from "@/lib/jira-dispatch-selection";
import { buildFindingResourceContext } from "@/lib/lighthouse/context/contributions";
import { isCloud } from "@/lib/shared/env";
import { FindingResourceRow } from "@/types";
import type {
  FindingTriageContext,
  FindingTriageDetailLoadHandler,
  FindingTriageNoteLoadHandler,
  FindingTriageUpdateHandler,
} from "@/types/findings-triage";
import { JIRA_DISPATCH_TARGET } from "@/types/integrations";

import { canMuteFindingResource } from "./finding-resource-selection";
import {
  FindingNoteActionItem,
  FindingTriageStatusCell,
} from "./finding-triage-cells";
import { FindingsSelectionContext } from "./findings-selection-context";
import {
  LighthouseSkillsRowButton,
  LighthouseSkillsSubmenu,
  useLighthousePromptLaunch,
  useLighthouseSkillLaunch,
} from "./lighthouse-skills-launch";
import {
  type DeltaType,
  NotificationIndicator,
} from "./notification-indicator";

const buildFindingResourceTriageContext = (
  resource: FindingResourceRow,
  findingTitle?: string,
): FindingTriageContext => ({
  title: findingTitle || resource.checkId,
  resource: resource.resourceName,
  provider: resource.providerAlias,
  providerType: resource.providerType,
});

// One finding-context item per resource row, shared by the leading Skills
// pill and the ⋮ submenu so both launch with identical context.
const buildResourceFindingItem = (resource: FindingResourceRow) =>
  buildFindingResourceContext({
    findingId: resource.findingId,
    checkId: resource.checkId,
    severity: resource.severity,
    status: resource.status,
    providerUid: resource.providerUid,
    resourceUid: resource.resourceUid,
    region: resource.region,
  });

const ResourceRowActions = ({
  row,
  findingTitle,
  onSkillLaunchOpenDrawer,
  onTriageUpdateAction,
  onTriageNoteLoadAction,
  onTriageDetailLoadAction,
}: {
  row: Row<FindingResourceRow>;
  findingTitle?: string;
  onSkillLaunchOpenDrawer?: (rowIndex: number) => void;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
  onTriageNoteLoadAction?: FindingTriageNoteLoadHandler;
  onTriageDetailLoadAction?: FindingTriageDetailLoadHandler;
}) => {
  const resource = row.original;
  const canMute = canMuteFindingResource(resource);
  const launchSkill = useLighthouseSkillLaunch();
  const launchPrompt = useLighthousePromptLaunch();
  const [isMuteModalOpen, setIsMuteModalOpen] = useState(false);
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
  const displayIds = getDisplayIds();
  const jiraPayload = createJiraDispatchPayload({
    targetIds: displayIds,
    targetType: JIRA_DISPATCH_TARGET.FINDING_ID,
    findingTitle: findingTitle || resource.checkId,
    selectedResourceCount: displayIds.length,
    isFindingGroupSelection: true,
  });

  const handleMuteClick = async () => {
    const displayIds = getDisplayIds();

    // Single resource: findingId is already a real finding UUID
    if (displayIds.length === 1) {
      setResolvedIds(displayIds);
      setIsMuteModalOpen(true);
      return;
    }

    // Multi-select: resolve through context
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
      {canMute && (
        <MuteFindingsModal
          isOpen={isMuteModalOpen}
          onOpenChange={setIsMuteModalOpen}
          findingIds={resolvedIds}
          onComplete={handleMuteComplete}
        />
      )}
      <div
        className="flex items-center justify-end"
        onClick={(e) => e.stopPropagation()}
      >
        <ActionDropdown ariaLabel="Resource actions">
          <FindingNoteActionItem
            triage={resource.triage}
            findingContext={buildFindingResourceTriageContext(
              resource,
              findingTitle,
            )}
            onTriageUpdateAction={onTriageUpdateAction}
            onTriageNoteLoadAction={onTriageNoteLoadAction}
            onTriageDetailLoadAction={onTriageDetailLoadAction}
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
            disabled={!canMute || isResolving}
            onSelect={handleMuteClick}
          />
          <JiraDispatchActionItem
            label={buildJiraActionLabel({
              findingCount: displayIds.length,
            })}
            payload={jiraPayload}
          />
          {isCloud() && (
            <LighthouseSkillsSubmenu
              onLaunch={(skill) => {
                onSkillLaunchOpenDrawer?.(row.index);
                launchSkill(skill, buildResourceFindingItem(resource));
              }}
              onSubmitPrompt={(text) => {
                onSkillLaunchOpenDrawer?.(row.index);
                launchPrompt(text, buildResourceFindingItem(resource));
              }}
            />
          )}
        </ActionDropdown>
      </div>
    </>
  );
};

interface GetColumnFindingResourcesOptions {
  rowSelection: RowSelectionState;
  selectableRowCount: number;
  findingTitle?: string;
  // Skill launch (pill or ⋮ submenu) opens this row's finding drawer behind
  // the chat tab, so the run and the finding share the side panel.
  onSkillLaunchOpenDrawer?: (rowIndex: number) => void;
  onTriageUpdateAction?: FindingTriageUpdateHandler;
  onTriageNoteLoadAction?: FindingTriageNoteLoadHandler;
  onTriageDetailLoadAction?: FindingTriageDetailLoadHandler;
}

export function getColumnFindingResources({
  rowSelection,
  selectableRowCount,
  findingTitle,
  onSkillLaunchOpenDrawer,
  onTriageUpdateAction,
  onTriageNoteLoadAction,
  onTriageDetailLoadAction,
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
            {/* Mirrors the row's indicator + arrow so checkboxes stay aligned */}
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
        // relative: paints above the cell's hover-extension pseudo-element,
        // which would otherwise cover the in-flow checkbox and indicator.
        <div className="relative flex items-center gap-2">
          <NotificationIndicator
            delta={row.original.delta as DeltaType | undefined}
            isMuted={row.original.isMuted}
            mutedReason={row.original.mutedReason}
            showDeltaWhenMuted
          />
          {isCloud() ? (
            <LighthouseSkillsRowButton
              findingItem={buildResourceFindingItem(row.original)}
              onSkillLaunch={() => onSkillLaunchOpenDrawer?.(row.index)}
            />
          ) : (
            <CornerDownRight className="text-text-neutral-tertiary h-4 w-4 shrink-0" />
          )}
          <Checkbox
            size="sm"
            checked={!!rowSelection[row.id]}
            disabled={!canMuteFindingResource(row.original)}
            onCheckedChange={(checked) => row.toggleSelected(checked === true)}
            onClick={(e) => e.stopPropagation()}
            aria-label="Select resource"
          />
        </div>
      ),
      enableSorting: false,
      enableHiding: false,
    },
    // Affected failing resource — name + uid
    {
      id: "resource",
      header: ({ column }) => (
        <DataTableColumnHeader
          column={column}
          title="Affected failing resource"
        />
      ),
      cell: ({ row }) => (
        <div className="max-w-[240px]">
          <EntityInfo
            entityAlias={row.original.resourceName}
            entityId={row.original.resourceUid}
          />
        </div>
      ),
      enableSorting: false,
    },
    // Provider — alias + uid (same style as Resource)
    {
      id: "provider",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Provider" />
      ),
      cell: ({ row }) => (
        <div className="max-w-[240px]">
          <EntityInfo
            entityAlias={row.original.providerAlias}
            entityId={row.original.providerUid}
          />
        </div>
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
    // Service
    {
      id: "service",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Service" />
      ),
      cell: ({ row }) => (
        <InfoField label="Service" variant="compact">
          {row.original.service || "-"}
        </InfoField>
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
        <InfoField label="Region" variant="compact">
          <span className="block truncate whitespace-nowrap">
            {row.original.region || "-"}
          </span>
        </InfoField>
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
          <DateWithTime dateTime={row.original.lastSeenAt} />
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
    // Triage — keep the compact label: these cells also render inside
    // expanded finding-group rows, which have no header row of their own.
    {
      id: "triage",
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Triage" />
      ),
      cell: ({ row }) => (
        <InfoField label="Triage" variant="compact">
          <FindingTriageStatusCell
            triage={row.original.triage}
            findingContext={buildFindingResourceTriageContext(
              row.original,
              findingTitle,
            )}
            onTriageUpdateAction={onTriageUpdateAction}
            onTriageDetailLoadAction={onTriageDetailLoadAction}
          />
        </InfoField>
      ),
      enableSorting: false,
    },
    // Actions column — utility actions are kept last.
    {
      id: "actions",
      size: 56,
      header: () => <div className="w-10" />,
      cell: ({ row }) => (
        <ResourceRowActions
          row={row}
          findingTitle={findingTitle}
          onSkillLaunchOpenDrawer={onSkillLaunchOpenDrawer}
          onTriageUpdateAction={onTriageUpdateAction}
          onTriageNoteLoadAction={onTriageNoteLoadAction}
          onTriageDetailLoadAction={onTriageDetailLoadAction}
        />
      ),
      enableSorting: false,
    },
  ];
}
