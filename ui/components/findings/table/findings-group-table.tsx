"use client";

import { Row, RowSelectionState } from "@tanstack/react-table";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import {
  resolveFindingIds,
  resolveFindingIdsByCheckIds,
} from "@/actions/findings/findings-by-resource";
import { DataTable } from "@/components/ui/table";
import { FindingGroupRow, MetaDataProps } from "@/types";

import { FloatingMuteButton } from "../floating-mute-button";
import { getColumnFindingGroups } from "./column-finding-groups";
import { FindingsSelectionContext } from "./findings-selection-context";
import { InlineResourceContainer } from "./inline-resource-container";

function buildMuteLabel(groupCount: number, resourceCount: number): string {
  const parts: string[] = [];
  if (groupCount > 0) {
    parts.push(`${groupCount} ${groupCount === 1 ? "Group" : "Groups"}`);
  }
  if (resourceCount > 0) {
    parts.push(
      `${resourceCount} ${resourceCount === 1 ? "Resource" : "Resources"}`,
    );
  }
  return `Mute ${parts.join(" and ")}`;
}

interface FindingsGroupTableProps {
  data: FindingGroupRow[];
  metadata?: MetaDataProps;
}

export function FindingsGroupTable({
  data,
  metadata,
}: FindingsGroupTableProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [expandedCheckId, setExpandedCheckId] = useState<string | null>(null);
  const [expandedGroup, setExpandedGroup] = useState<FindingGroupRow | null>(
    null,
  );
  const [resourceSearch, setResourceSearch] = useState("");
  const [resourceSelection, setResourceSelection] = useState<string[]>([]);

  // State resets (selection, drill-down) are handled by the parent via
  // key={groupKey} — when data changes, the component remounts with fresh state.

  const safeData = data ?? [];
  const hasResourceSelection = resourceSelection.length > 0;

  // Get selected check IDs (not UUIDs) — resolveFindingIdsByCheckIds expects check_id values.
  // When the expanded group has individual resource selections, exclude it from
  // group-level mute targets — the resource-level FloatingMuteButton handles those.
  const selectedCheckIds = Object.keys(rowSelection)
    .filter((key) => rowSelection[key])
    .map((idx) => safeData[parseInt(idx)]?.checkId)
    .filter(Boolean)
    .filter(
      (checkId) => !(hasResourceSelection && checkId === expandedCheckId),
    );

  const selectedFindings = Object.keys(rowSelection)
    .filter((key) => rowSelection[key])
    .map((idx) => safeData[parseInt(idx)])
    .filter(Boolean);

  // Count of selectable rows (groups where not ALL findings are muted)
  const selectableRowCount = safeData.filter(
    (g) => !(g.mutedCount > 0 && g.mutedCount === g.resourcesTotal),
  ).length;

  const getRowCanSelect = (row: Row<FindingGroupRow>): boolean => {
    const group = row.original;
    return !(group.mutedCount > 0 && group.mutedCount === group.resourcesTotal);
  };

  const clearSelection = () => {
    setRowSelection({});
  };

  const isSelected = (id: string) => {
    return selectedCheckIds.includes(id);
  };

  /** Shared resolver for row action dropdowns (via context). */
  const resolveMuteIds = async (checkIds: string[]) =>
    resolveFindingIdsByCheckIds({ checkIds });

  const handleMuteComplete = () => {
    clearSelection();
    setResourceSelection([]);
    router.refresh();
  };

  const handleDrillDown = (checkId: string, group: FindingGroupRow) => {
    // Toggle: same group = collapse, different = switch
    if (expandedCheckId === checkId) {
      handleCollapse();
      return;
    }
    setExpandedCheckId(checkId);
    setExpandedGroup(group);
    setResourceSearch("");
    setResourceSelection([]);
  };

  const handleCollapse = () => {
    setExpandedCheckId(null);
    setExpandedGroup(null);
    setResourceSearch("");
    setResourceSelection([]);
  };

  const columns = getColumnFindingGroups({
    rowSelection,
    selectableRowCount,
    onDrillDown: handleDrillDown,
    expandedCheckId,
    hasResourceSelection,
  });

  const renderAfterRow = (row: Row<FindingGroupRow>) => {
    const group = row.original;
    if (group.checkId !== expandedCheckId || !expandedGroup) return null;

    return (
      <InlineResourceContainer
        key={`${group.checkId}|${searchParams.toString()}|${resourceSearch}`}
        group={expandedGroup}
        resourceSearch={resourceSearch}
        columnCount={columns.length}
        onResourceSelectionChange={setResourceSelection}
      />
    );
  };

  return (
    <FindingsSelectionContext.Provider
      value={{
        selectedFindingIds: selectedCheckIds,
        selectedFindings,
        clearSelection,
        isSelected,
        resolveMuteIds,
      }}
    >
      <DataTable
        columns={columns}
        data={safeData}
        metadata={metadata}
        enableRowSelection
        rowSelection={rowSelection}
        onRowSelectionChange={setRowSelection}
        getRowCanSelect={getRowCanSelect}
        showSearch
        searchPlaceholder={
          expandedCheckId ? "Search resources..." : "Search by name"
        }
        controlledSearch={expandedCheckId ? resourceSearch : undefined}
        onSearchChange={expandedCheckId ? setResourceSearch : undefined}
        searchBadge={
          expandedGroup
            ? { label: expandedGroup.checkTitle, onDismiss: handleCollapse }
            : undefined
        }
        renderAfterRow={renderAfterRow}
      />

      {(selectedCheckIds.length > 0 || hasResourceSelection) && (
        <FloatingMuteButton
          selectedCount={selectedCheckIds.length + resourceSelection.length}
          selectedFindingIds={[...selectedCheckIds, ...resourceSelection]}
          label={buildMuteLabel(
            selectedCheckIds.length,
            resourceSelection.length,
          )}
          onBeforeOpen={async () => {
            const [groupIds, resourceIds] = await Promise.all([
              selectedCheckIds.length > 0
                ? resolveFindingIdsByCheckIds({ checkIds: selectedCheckIds })
                : Promise.resolve([]),
              hasResourceSelection && expandedCheckId
                ? resolveFindingIds({
                    checkId: expandedCheckId,
                    resourceUids: resourceSelection,
                  })
                : Promise.resolve([]),
            ]);
            return [...groupIds, ...resourceIds];
          }}
          onComplete={handleMuteComplete}
          isBulkOperation
        />
      )}
    </FindingsSelectionContext.Provider>
  );
}
