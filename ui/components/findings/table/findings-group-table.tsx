"use client";

import { Row, RowSelectionState } from "@tanstack/react-table";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { resolveFindingIdsByVisibleGroupResources } from "@/actions/findings/findings-by-resource";
import { CustomCheckboxMutedFindings } from "@/components/filters/custom-checkbox-muted-findings";
import { DataTable } from "@/components/ui/table";
import { includesMutedFindings } from "@/lib/findings-filters";
import { canDrillDownFindingGroup } from "@/lib/findings-groups";
import {
  loadOptimisticallyMutedCheckIds,
  persistOptimisticallyMutedCheckIds,
  removePersistedOptimisticEntries,
} from "@/lib/optimistic-muted-groups";
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
  // Group check_ids the user just muted, hidden client-side until the server
  // catches up. Hydrated from sessionStorage on mount so a fast reload still
  // honours the optimistic hide. See lib/optimistic-muted-groups.ts.
  const [optimisticallyMutedCheckIds, setOptimisticallyMutedCheckIds] =
    useState<Set<string>>(() => new Set());
  const inlineRef = useRef<InlineResourceContainerHandle>(null);

  useEffect(() => {
    const persisted = loadOptimisticallyMutedCheckIds();
    if (persisted.size > 0) setOptimisticallyMutedCheckIds(persisted);
  }, []);

  // State resets (selection, drill-down) are handled by the parent via
  // key={groupKey} — when data changes, the component remounts with fresh state.

  const visibleData = (data ?? []).filter(
    (g) => !optimisticallyMutedCheckIds.has(g.checkId),
  );
  const hasResourceSelection = resourceSelection.length > 0;
  const filters = resolvedFilters;

  // When a previously-hidden group disappears from the server payload, drop
  // it from both client state and storage so we don't keep a stale entry.
  useEffect(() => {
    if (optimisticallyMutedCheckIds.size === 0) return;
    const incoming = new Set((data ?? []).map((g) => g.checkId));
    const confirmed: string[] = [];
    const stillPending = new Set<string>();
    optimisticallyMutedCheckIds.forEach((id) => {
      if (incoming.has(id)) {
        stillPending.add(id);
      } else {
        confirmed.push(id);
      }
    });
    if (confirmed.length > 0) {
      removePersistedOptimisticEntries(confirmed);
      setOptimisticallyMutedCheckIds(stillPending);
    }
  }, [data, optimisticallyMutedCheckIds]);

  // Get selected group check IDs. When the expanded group has individual resource
  // selections, exclude it from group-level mute targets — the resource-level
  // FloatingMuteButton handles those.
  const selectedCheckIds = Object.keys(rowSelection)
    .filter((key) => rowSelection[key])
    .map((idx) => visibleData[parseInt(idx)]?.checkId)
    .filter(Boolean)
    .filter(
      (checkId) => !(hasResourceSelection && checkId === expandedCheckId),
    );

  const selectedFindings = Object.keys(rowSelection)
    .filter((key) => rowSelection[key])
    .map((idx) => visibleData[parseInt(idx)])
    .filter(Boolean);

  // Count of selectable rows (groups where not ALL findings are muted)
  const selectableRowCount = visibleData.filter((g) =>
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

  const handleCollapse = () => {
    setExpandedCheckId(null);
    setExpandedGroup(null);
    setResourceSearchInput("");
    setResourceSearch("");
    setResourceSelection([]);
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

  const hideMutedGroups = (mutedCheckIds: string[]) => {
    if (mutedCheckIds.length === 0) return;
    // When the user opted into showing muted findings, the row stays visible
    // (with the muted indicator) after reload — don't hide it client-side or
    // we'll diverge from the post-reload state.
    if (includesMutedFindings(resolvedFilters)) return;
    persistOptimisticallyMutedCheckIds(mutedCheckIds);
    setOptimisticallyMutedCheckIds((prev) => {
      const next = new Set(prev);
      mutedCheckIds.forEach((id) => next.add(id));
      return next;
    });
    if (expandedCheckId && mutedCheckIds.includes(expandedCheckId)) {
      handleCollapse();
    }
  };

  /**
   * True when muting `mutedResourceCount` findings is expected to leave the
   * given group fully muted on the next read. Conservative: requires that
   * every unmuted FAIL is covered AND there are no unmuted PASS/MANUAL
   * findings, which matches the API model where `muted=True` only when every
   * finding in the group is muted.
   */
  const willResourceMuteEmptyGroup = (
    group: FindingGroupRow,
    mutedResourceCount: number,
  ): boolean => {
    const unmutedFail = group.failCount ?? group.resourcesFail;
    const unmutedPass = group.passCount ?? 0;
    const unmutedManual = group.manualCount ?? 0;
    return (
      mutedResourceCount >= unmutedFail &&
      unmutedPass === 0 &&
      unmutedManual === 0
    );
  };

  const handleMuteComplete = () => {
    // Snapshot the group selection BEFORE clearing it; the optimistic-hide
    // helper needs the IDs that were actually muted as whole groups.
    const mutedGroupCheckIds = [...selectedCheckIds];
    // If the FloatingMuteButton flow includes resource-level mutes that fully
    // empty the expanded group, hide that group too (the row would have stayed
    // visible otherwise until the server caught up).
    if (
      expandedGroup &&
      resourceSelection.length > 0 &&
      !mutedGroupCheckIds.includes(expandedGroup.checkId) &&
      willResourceMuteEmptyGroup(expandedGroup, resourceSelection.length)
    ) {
      mutedGroupCheckIds.push(expandedGroup.checkId);
    }
    clearSelection();
    setResourceSelection([]);
    inlineRef.current?.clearSelection();
    inlineRef.current?.refresh();
    hideMutedGroups(mutedGroupCheckIds);
    router.refresh();
  };

  // Triggered by group row-action mutes (single-row dropdown). Receives the
  // group check IDs that were sent to the mute API.
  const handleRowMuteComplete = (mutedIds?: string[]) => {
    hideMutedGroups(mutedIds ?? []);
    router.refresh();
  };

  // Triggered by resource-row mutes inside the drill-down. Hides the
  // surrounding group when the mute leaves it fully muted.
  const handleResourceMuteFromDrillDown = (mutedResourceCount: number) => {
    if (mutedResourceCount <= 0 || !expandedGroup) return;
    if (willResourceMuteEmptyGroup(expandedGroup, mutedResourceCount)) {
      hideMutedGroups([expandedGroup.checkId]);
    }
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
        onResourceMuteCompleted={handleResourceMuteFromDrillDown}
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
        onMuteComplete: handleRowMuteComplete,
      }}
    >
      <DataTable
        columns={columns}
        data={visibleData}
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
