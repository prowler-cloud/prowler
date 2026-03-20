"use client";

import { Row, RowSelectionState } from "@tanstack/react-table";
import { VolumeX } from "lucide-react";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";

import { resolveFindingIdsByCheckIds } from "@/actions/findings/findings-by-resource";
import { Button } from "@/components/shadcn";
import { TreeSpinner } from "@/components/shadcn/tree-view/tree-spinner";
import { DataTable } from "@/components/ui/table";
import { FindingGroupRow, MetaDataProps } from "@/types";

import { MuteFindingsModal } from "../mute-findings-modal";
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

  // Mute modal state — check IDs resolved to finding UUIDs on-click
  const [isMuteModalOpen, setIsMuteModalOpen] = useState(false);
  const [resolvedFindingIds, setResolvedFindingIds] = useState<string[]>([]);
  const [isResolvingIds, setIsResolvingIds] = useState(false);

  const handleMuteClick = async () => {
    setIsResolvingIds(true);
    const findingIds = await resolveFindingIdsByCheckIds({
      checkIds: selectedFindingIds,
    });
    setResolvedFindingIds(findingIds);
    setIsResolvingIds(false);
    if (findingIds.length > 0) {
      setIsMuteModalOpen(true);
    }
  };

  /** Shared resolver for row action dropdowns (via context). */
  const resolveMuteIds = useCallback(
    async (checkIds: string[]) => resolveFindingIdsByCheckIds({ checkIds }),
    [],
  );

  const handleMuteComplete = () => {
    clearSelection();
    setResolvedFindingIds([]);
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
        <>
          <MuteFindingsModal
            isOpen={isMuteModalOpen}
            onOpenChange={setIsMuteModalOpen}
            findingIds={resolvedFindingIds}
            onComplete={handleMuteComplete}
          />
          <div className="animate-in fade-in slide-in-from-bottom-4 fixed right-6 bottom-6 z-50 duration-300">
            <Button
              onClick={handleMuteClick}
              disabled={isResolvingIds}
              size="lg"
              className="shadow-lg"
            >
              {isResolvingIds ? (
                <TreeSpinner className="size-5" />
              ) : (
                <VolumeX className="size-5" />
              )}
              Mute ({selectedFindingIds.length})
            </Button>
          </div>
        </>
      )}
    </FindingsSelectionContext.Provider>
  );
}
