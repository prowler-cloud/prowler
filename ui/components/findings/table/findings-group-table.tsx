"use client";

import { Row, RowSelectionState } from "@tanstack/react-table";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { resolveFindingIdsByCheckIds } from "@/actions/findings/findings-by-resource";
import { DataTable } from "@/components/ui/table";
import { FindingGroupRow, MetaDataProps } from "@/types";

import { FloatingMuteButton } from "../floating-mute-button";
import { getColumnFindingGroups } from "./column-finding-groups";
import { FindingsGroupDrillDown } from "./findings-group-drill-down";
import { FindingsSelectionContext } from "./findings-selection-context";

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
  const [isDrillingDown, setIsDrillingDown] = useState(false);

  // State resets (selection, drill-down) are handled by the parent via
  // key={groupKey} — when data changes, the component remounts with fresh state.

  const safeData = data ?? [];

  // Get selected check IDs (not UUIDs) — resolveFindingIdsByCheckIds expects check_id values
  const selectedCheckIds = Object.keys(rowSelection)
    .filter((key) => rowSelection[key])
    .map((idx) => safeData[parseInt(idx)]?.checkId)
    .filter(Boolean);

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
    router.refresh();
  };

  const handleDrillDown = (checkId: string, group: FindingGroupRow) => {
    setIsDrillingDown(true);
    setRowSelection({});
    // Brief loading state before switching to drill-down view
    setTimeout(() => {
      setExpandedCheckId(checkId);
      setExpandedGroup(group);
      setIsDrillingDown(false);
    }, 150);
  };

  const handleCollapse = () => {
    setExpandedCheckId(null);
    setExpandedGroup(null);
  };

  const columns = getColumnFindingGroups({
    rowSelection,
    selectableRowCount,
    onDrillDown: handleDrillDown,
  });

  // Drill-down mode: show sticky header + resources table
  if (expandedCheckId && expandedGroup) {
    return (
      <FindingsGroupDrillDown
        key={`${expandedGroup.checkId}|${searchParams.toString()}`}
        group={expandedGroup}
        onCollapse={handleCollapse}
      />
    );
  }

  // Normal mode: show finding groups table
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
        searchPlaceholder="Search by Check ID"
        isLoading={isDrillingDown}
      />

      {selectedCheckIds.length > 0 && (
        <FloatingMuteButton
          selectedCount={selectedCheckIds.length}
          selectedFindingIds={selectedCheckIds}
          onBeforeOpen={async () => {
            return resolveFindingIdsByCheckIds({
              checkIds: selectedCheckIds,
            });
          }}
          onComplete={handleMuteComplete}
          isBulkOperation
        />
      )}
    </FindingsSelectionContext.Provider>
  );
}
