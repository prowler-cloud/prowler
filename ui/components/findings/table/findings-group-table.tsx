"use client";

import { Row, RowSelectionState } from "@tanstack/react-table";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

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
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [expandedCheckId, setExpandedCheckId] = useState<string | null>(null);
  const [expandedGroup, setExpandedGroup] = useState<FindingGroupRow | null>(
    null,
  );
  const [isDrillingDown, setIsDrillingDown] = useState(false);

  // Track finding group IDs to detect data changes (e.g., after muting)
  const currentIds = (data ?? []).map((g) => g.id).join(",");
  const previousIdsRef = useRef(currentIds);

  // Reset selection when page changes
  useEffect(() => {
    setRowSelection({});
  }, [metadata?.pagination?.page]);

  // Reset selection and collapse drill-down when data changes (e.g., filters)
  useEffect(() => {
    if (previousIdsRef.current !== currentIds) {
      setRowSelection({});
      setExpandedCheckId(null);
      setExpandedGroup(null);
      previousIdsRef.current = currentIds;
    }
  }, [currentIds]);

  const safeData = data ?? [];

  // Get selected group IDs (only non-fully-muted groups can be selected)
  const selectedFindingIds = Object.keys(rowSelection)
    .filter((key) => rowSelection[key])
    .map((idx) => safeData[parseInt(idx)]?.id)
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
    return selectedFindingIds.includes(id);
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
        group={expandedGroup}
        onCollapse={handleCollapse}
      />
    );
  }

  // Normal mode: show finding groups table
  return (
    <FindingsSelectionContext.Provider
      value={{
        selectedFindingIds,
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

      {selectedFindingIds.length > 0 && (
        <FloatingMuteButton
          selectedCount={selectedFindingIds.length}
          selectedFindingIds={selectedFindingIds}
          onBeforeOpen={async () => {
            return resolveFindingIdsByCheckIds({
              checkIds: selectedFindingIds,
            });
          }}
          onComplete={handleMuteComplete}
        />
      )}
    </FindingsSelectionContext.Provider>
  );
}
