"use client";

import { OnChangeFn, Row, RowSelectionState } from "@tanstack/react-table";
import { useState } from "react";

import { canMuteFindingResource } from "@/components/findings/table/finding-resource-selection";
import { useResourceDetailDrawer } from "@/components/findings/table/resource-detail-drawer";
import { useFindingGroupResources } from "@/hooks/use-finding-group-resources";
import { applyDefaultMutedFilter } from "@/lib";
import { FindingGroupRow, FindingResourceRow } from "@/types";

interface UseFindingGroupResourceStateOptions {
  group: FindingGroupRow;
  filters: Record<string, string>;
  hasHistoricalData: boolean;
  onResourceSelectionChange?: (findingIds: string[]) => void;
  scrollContainerRef?: React.RefObject<HTMLElement | null>;
}

interface UseFindingGroupResourceStateReturn {
  rowSelection: RowSelectionState;
  resources: FindingResourceRow[];
  isLoading: boolean;
  sentinelRef: (node: HTMLDivElement | null) => void;
  refresh: () => void;
  loadMore: () => void;
  totalCount: number | null;
  drawer: ReturnType<typeof useResourceDetailDrawer>;
  handleDrawerMuteComplete: () => void;
  selectedFindingIds: string[];
  selectableRowCount: number;
  getRowCanSelect: (row: Row<FindingResourceRow>) => boolean;
  clearSelection: () => void;
  isSelected: (id: string) => boolean;
  handleMuteComplete: () => void;
  handleRowSelectionChange: OnChangeFn<RowSelectionState>;
  resolveSelectedFindingIds: (ids: string[]) => Promise<string[]>;
}

export function useFindingGroupResourceState({
  group,
  filters,
  hasHistoricalData,
  onResourceSelectionChange,
  scrollContainerRef,
}: UseFindingGroupResourceStateOptions): UseFindingGroupResourceStateReturn {
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [resources, setResources] = useState<FindingResourceRow[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const effectiveFilters = applyDefaultMutedFilter(filters);

  const handleSetResources = (
    newResources: FindingResourceRow[],
    _hasMore: boolean,
  ) => {
    setResources(newResources);
    setIsLoading(false);
  };

  const handleAppendResources = (
    newResources: FindingResourceRow[],
    _hasMore: boolean,
  ) => {
    setResources((prev) => [...prev, ...newResources]);
    setIsLoading(false);
  };

  const handleSetLoading = (loading: boolean) => {
    setIsLoading(loading);
  };

  const { sentinelRef, refresh, loadMore, totalCount } =
    useFindingGroupResources({
      checkId: group.checkId,
      hasDateOrScanFilter: hasHistoricalData,
      filters: effectiveFilters,
      onSetResources: handleSetResources,
      onAppendResources: handleAppendResources,
      onSetLoading: handleSetLoading,
      scrollContainerRef,
    });

  const drawer = useResourceDetailDrawer({
    resources,
    totalResourceCount: totalCount ?? group.resourcesTotal,
    onRequestMoreResources: loadMore,
    canLoadOtherFindings: group.resourcesTotal !== 0,
    includeMutedInOtherFindings: true,
  });

  const handleDrawerMuteComplete = () => {
    drawer.refetchCurrent();
    refresh();
  };

  const selectedFindingIds = Object.keys(rowSelection)
    .filter((key) => rowSelection[key])
    .map((idx) => resources[parseInt(idx)]?.findingId)
    .filter((id): id is string => Boolean(id));

  const selectableRowCount = resources.filter(canMuteFindingResource).length;

  const getRowCanSelect = (row: Row<FindingResourceRow>): boolean => {
    return canMuteFindingResource(row.original);
  };

  const clearSelection = () => {
    setRowSelection({});
    onResourceSelectionChange?.([]);
  };

  const isSelected = (id: string) => {
    return selectedFindingIds.includes(id);
  };

  const handleMuteComplete = () => {
    clearSelection();
    refresh();
  };

  const handleRowSelectionChange = (
    updater:
      | RowSelectionState
      | ((prev: RowSelectionState) => RowSelectionState),
  ) => {
    const newSelection =
      typeof updater === "function" ? updater(rowSelection) : updater;
    setRowSelection(newSelection);

    if (onResourceSelectionChange) {
      const newFindingIds = Object.keys(newSelection)
        .filter((key) => newSelection[key])
        .map((idx) => resources[parseInt(idx)]?.findingId)
        .filter((id): id is string => Boolean(id));
      onResourceSelectionChange(newFindingIds);
    }
  };

  const resolveSelectedFindingIds = async (ids: string[]) => {
    return ids.filter(Boolean);
  };

  return {
    rowSelection,
    resources,
    isLoading,
    sentinelRef,
    refresh,
    loadMore,
    totalCount,
    drawer,
    handleDrawerMuteComplete,
    selectedFindingIds,
    selectableRowCount,
    getRowCanSelect,
    clearSelection,
    isSelected,
    handleMuteComplete,
    handleRowSelectionChange,
    resolveSelectedFindingIds,
  };
}
