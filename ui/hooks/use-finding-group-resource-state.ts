"use client";

import { OnChangeFn, Row, RowSelectionState } from "@tanstack/react-table";
import { useRef, useState } from "react";

import { canMuteFindingResource } from "@/components/findings/table/finding-resource-selection";
import { useResourceDetailDrawer } from "@/components/findings/table/resource-detail-drawer";
import { useFindingGroupResources } from "@/hooks/use-finding-group-resources";
import { applyDefaultMutedFilter } from "@/lib";
import {
  applyOptimisticTriageSummaryUpdate,
  getOptimisticTriageMutedReason,
  shouldMarkFindingMutedForTriageUpdate,
} from "@/lib/finding-triage";
import { FindingGroupRow, FindingResourceRow } from "@/types";
import type { UpdateFindingTriageInput } from "@/types/findings-triage";

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
  updateTriageOptimistically: (
    input: UpdateFindingTriageInput,
    updateAction: (input: UpdateFindingTriageInput) => Promise<void>,
  ) => Promise<void>;
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
  const baseResourcesRef = useRef<FindingResourceRow[]>([]);
  const optimisticTriageByFindingIdRef = useRef(
    new Map<string, { token: string; input: UpdateFindingTriageInput }>(),
  );
  const settledOptimisticFindingIdsRef = useRef(new Set<string>());

  const mergeOptimisticTriage = (items: FindingResourceRow[]) =>
    items.map((resource) => {
      const optimisticEntry = optimisticTriageByFindingIdRef.current.get(
        resource.findingId,
      );
      const optimistic = optimisticEntry?.input;

      if (!optimistic || !resource.triage) {
        return resource;
      }

      const shouldMarkMuted = shouldMarkFindingMutedForTriageUpdate(optimistic);
      const shouldSetTriageMuteReason =
        shouldMarkMuted && optimistic.isMuted !== true;

      return {
        ...resource,
        isMuted: shouldMarkMuted ? true : resource.isMuted,
        mutedReason: shouldSetTriageMuteReason
          ? getOptimisticTriageMutedReason(optimistic.status!)
          : resource.mutedReason,
        triage: applyOptimisticTriageSummaryUpdate(resource.triage, optimistic),
      };
    });

  const removeOptimisticEntry = (findingId: string) => {
    optimisticTriageByFindingIdRef.current.delete(findingId);
    settledOptimisticFindingIdsRef.current.delete(findingId);
  };

  const resourceSatisfiesOptimisticUpdate = (
    resource: FindingResourceRow,
    optimistic: UpdateFindingTriageInput,
  ) => {
    const statusMatches =
      !optimistic.status || resource.triage?.status === optimistic.status;
    const noteMatches =
      !optimistic.note ||
      Boolean(resource.triage?.hasVisibleNote) ||
      (resource.triage?.notesCount ?? 0) > 0;

    return statusMatches && noteMatches;
  };

  const clearSettledOptimisticUpdates = (items: FindingResourceRow[]) => {
    for (const resource of items) {
      const optimistic = optimisticTriageByFindingIdRef.current.get(
        resource.findingId,
      )?.input;

      if (
        optimistic &&
        settledOptimisticFindingIdsRef.current.has(resource.findingId) &&
        resourceSatisfiesOptimisticUpdate(resource, optimistic)
      ) {
        removeOptimisticEntry(resource.findingId);
      }
    }
  };

  const handleSetResources = (
    newResources: FindingResourceRow[],
    _hasMore: boolean,
  ) => {
    clearSettledOptimisticUpdates(newResources);
    baseResourcesRef.current = newResources;
    setResources(mergeOptimisticTriage(baseResourcesRef.current));
    setIsLoading(false);
  };

  const handleAppendResources = (
    newResources: FindingResourceRow[],
    _hasMore: boolean,
  ) => {
    clearSettledOptimisticUpdates(newResources);
    baseResourcesRef.current = [...baseResourcesRef.current, ...newResources];
    setResources(mergeOptimisticTriage(baseResourcesRef.current));
    setIsLoading(false);
  };

  const handleSetLoading = (loading: boolean) => {
    setIsLoading(loading);
  };

  const effectiveFilters = applyDefaultMutedFilter(filters);

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
    includeMutedInOtherFindings: filters["filter[muted]"] === "include",
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

  const applyOptimisticTriageUpdate = (input: UpdateFindingTriageInput) => {
    removeOptimisticEntry(input.findingId);
    const token = crypto.randomUUID();
    optimisticTriageByFindingIdRef.current.set(input.findingId, {
      token,
      input,
    });
    setResources(mergeOptimisticTriage(baseResourcesRef.current));
    return token;
  };

  const clearOptimisticTriageUpdate = (findingId: string, token: string) => {
    if (
      optimisticTriageByFindingIdRef.current.get(findingId)?.token !== token
    ) {
      return;
    }

    removeOptimisticEntry(findingId);
    setResources(mergeOptimisticTriage(baseResourcesRef.current));
  };

  const settleOptimisticTriageUpdate = (findingId: string, token: string) => {
    if (
      optimisticTriageByFindingIdRef.current.get(findingId)?.token !== token
    ) {
      return;
    }

    settledOptimisticFindingIdsRef.current.add(findingId);
  };

  const updateTriageOptimistically = async (
    input: UpdateFindingTriageInput,
    updateAction: (input: UpdateFindingTriageInput) => Promise<void>,
  ) => {
    const optimisticToken = applyOptimisticTriageUpdate(input);
    try {
      await updateAction(input);
      settleOptimisticTriageUpdate(input.findingId, optimisticToken);
      refresh();
    } catch (error) {
      clearOptimisticTriageUpdate(input.findingId, optimisticToken);
      refresh();
      throw error;
    }
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
    updateTriageOptimistically,
  };
}
