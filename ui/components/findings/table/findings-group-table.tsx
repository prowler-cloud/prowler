"use client";

import { Row, RowSelectionState } from "@tanstack/react-table";
import { useRouter, useSearchParams } from "next/navigation";
import { useRef, useState } from "react";

import { resolveFindingIdsByVisibleGroupResources } from "@/actions/findings/findings-by-resource";
import { CustomCheckboxMutedFindings } from "@/components/filters/custom-checkbox-muted-findings";
import { DataTable } from "@/components/ui/table";
import { canDrillDownFindingGroup } from "@/lib/findings-groups";
import { FindingGroupRow, MetaDataProps } from "@/types";

import { FloatingMuteButton } from "../floating-mute-button";
import { getColumnFindingGroups } from "./column-finding-groups";
import { canMuteFindingGroup } from "./finding-group-selection";
import { FindingsSelectionContext } from "./findings-selection-context";
import {
  InlineResourceContainer,
  InlineResourceContainerHandle,
} from "./inline-resource-container";

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
  resolvedFilters: Record<string, string>;
  hasHistoricalData: boolean;
}

export function FindingsGroupTable({
  data,
  metadata,
  resolvedFilters,
  hasHistoricalData,
}: FindingsGroupTableProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [expandedCheckId, setExpandedCheckId] = useState<string | null>(null);
  const [expandedGroup, setExpandedGroup] = useState<FindingGroupRow | null>(
    null,
  );
  // Separate display state (updates on keystroke) from committed search (updates on Enter only).
  // This prevents InlineResourceContainer from remounting on every keystroke.
  const [resourceSearchInput, setResourceSearchInput] = useState("");
  const [resourceSearch, setResourceSearch] = useState("");
  const [resourceSelection, setResourceSelection] = useState<string[]>([]);
  const inlineRef = useRef<InlineResourceContainerHandle>(null);

  // State resets (selection, drill-down) are handled by the parent via
  // key={groupKey} — when data changes, the component remounts with fresh state.

  const safeData = data ?? [];
  const hasResourceSelection = resourceSelection.length > 0;
  const filters = resolvedFilters;

  // Get selected group check IDs. When the expanded group has individual resource
  // selections, exclude it from group-level mute targets — the resource-level
  // FloatingMuteButton handles those.
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
  const selectableRowCount = safeData.filter((g) =>
    canMuteFindingGroup({
      resourcesFail: g.resourcesFail,
      resourcesTotal: g.resourcesTotal,
      muted: g.muted,
      mutedCount: g.mutedCount,
    }),
  ).length;

  const getRowCanSelect = (row: Row<FindingGroupRow>): boolean => {
    const group = row.original;
    return canMuteFindingGroup({
      resourcesFail: group.resourcesFail,
      resourcesTotal: group.resourcesTotal,
      muted: group.muted,
      mutedCount: group.mutedCount,
    });
  };

  const clearSelection = () => {
    setRowSelection({});
  };

  const isSelected = (id: string) => {
    return selectedCheckIds.includes(id);
  };

  const resolveGroupMuteIds = async (checkIds: string[]) => {
    const results = await Promise.all(
      checkIds.map((checkId) =>
        resolveFindingIdsByVisibleGroupResources({
          checkId,
          filters,
          hasDateOrScanFilter: hasHistoricalData,
          resourceSearch:
            checkId === expandedCheckId && resourceSearch
              ? resourceSearch
              : undefined,
        }),
      ),
    );

    return Array.from(new Set(results.flat()));
  };

  /** Shared resolver for group row action dropdowns (via context). */
  const resolveMuteIds = async (checkIds: string[]) =>
    resolveGroupMuteIds(checkIds);

  const handleMuteComplete = () => {
    clearSelection();
    setResourceSelection([]);
    inlineRef.current?.clearSelection();
    inlineRef.current?.refresh();
    router.refresh();
  };

  const handleDrillDown = (checkId: string, group: FindingGroupRow) => {
    // No resources in the group → nothing to show, skip drill-down
    if (!canDrillDownFindingGroup(group)) return;

    // Toggle: same group = collapse, different = switch
    if (expandedCheckId === checkId) {
      handleCollapse();
      return;
    }
    setExpandedCheckId(checkId);
    setExpandedGroup(group);
    setResourceSearchInput("");
    setResourceSearch("");
    setResourceSelection([]);
  };

  const handleCollapse = () => {
    setExpandedCheckId(null);
    setExpandedGroup(null);
    setResourceSearchInput("");
    setResourceSearch("");
    setResourceSelection([]);
  };

  const columns = getColumnFindingGroups({
    rowSelection,
    selectableRowCount,
    onDrillDown: handleDrillDown,
    expandedCheckId,
    hasResourceSelection,
    filters,
  });

  const renderAfterRow = (row: Row<FindingGroupRow>) => {
    const group = row.original;
    if (group.checkId !== expandedCheckId || !expandedGroup) return null;

    return (
      <InlineResourceContainer
        ref={inlineRef}
        key={`${group.checkId}|${searchParams.toString()}|${resourceSearch}`}
        group={expandedGroup}
        resolvedFilters={resolvedFilters}
        hasHistoricalData={hasHistoricalData}
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
        controlledSearch={expandedCheckId ? resourceSearchInput : undefined}
        onSearchChange={expandedCheckId ? setResourceSearchInput : undefined}
        onSearchCommit={expandedCheckId ? setResourceSearch : undefined}
        searchBadge={
          expandedGroup
            ? { label: expandedGroup.checkTitle, onDismiss: handleCollapse }
            : undefined
        }
        toolbarRightContent={<CustomCheckboxMutedFindings />}
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
                ? resolveGroupMuteIds(selectedCheckIds)
                : Promise.resolve([]),
              // resourceSelection already contains real finding UUIDs
              Promise.resolve(hasResourceSelection ? resourceSelection : []),
            ]);
            return [...groupIds, ...resourceIds];
          }}
          onComplete={handleMuteComplete}
          isBulkOperation={
            selectedCheckIds.length > 0 || resourceSelection.length > 1
          }
        />
      )}
    </FindingsSelectionContext.Provider>
  );
}
