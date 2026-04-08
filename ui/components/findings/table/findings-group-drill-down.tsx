"use client";

import {
  flexRender,
  getCoreRowModel,
  Row,
  RowSelectionState,
  useReactTable,
} from "@tanstack/react-table";
import { ChevronLeft } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { useState } from "react";

import { resolveFindingIds } from "@/actions/findings/findings-by-resource";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge, StatusFindingBadge } from "@/components/ui/table";
import { useInfiniteResources } from "@/hooks/use-infinite-resources";
import { cn, hasDateOrScanFilter } from "@/lib";
import { FindingGroupRow, FindingResourceRow } from "@/types";

import { FloatingMuteButton } from "../floating-mute-button";
import { getColumnFindingResources } from "./column-finding-resources";
import { canMuteFindingResource } from "./finding-resource-selection";
import { FindingsSelectionContext } from "./findings-selection-context";
import { ImpactedResourcesCell } from "./impacted-resources-cell";
import { DeltaValues, NotificationIndicator } from "./notification-indicator";
import {
  ResourceDetailDrawer,
  useResourceDetailDrawer,
} from "./resource-detail-drawer";

interface FindingsGroupDrillDownProps {
  group: FindingGroupRow;
  onCollapse: () => void;
}

export function FindingsGroupDrillDown({
  group,
  onCollapse,
}: FindingsGroupDrillDownProps) {
  const searchParams = useSearchParams();
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [resources, setResources] = useState<FindingResourceRow[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Derive hasDateOrScan from current URL params
  const currentParams = Object.fromEntries(searchParams.entries());
  const hasDateOrScan = hasDateOrScanFilter(currentParams);

  // Extract filter params from search params
  const filters: Record<string, string> = {};
  searchParams.forEach((value, key) => {
    if (key.startsWith("filter[") || key.includes("__in")) {
      filters[key] = value;
    }
  });

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

  const { sentinelRef, refresh, loadMore, totalCount } = useInfiniteResources({
    checkId: group.checkId,
    hasDateOrScanFilter: hasDateOrScan,
    filters,
    onSetResources: handleSetResources,
    onAppendResources: handleAppendResources,
    onSetLoading: handleSetLoading,
  });

  // Resource detail drawer
  const drawer = useResourceDetailDrawer({
    resources,
    checkId: group.checkId,
    totalResourceCount: totalCount ?? group.resourcesTotal,
    onRequestMoreResources: loadMore,
  });

  const handleDrawerMuteComplete = () => {
    drawer.refetchCurrent();
    refresh();
  };

  // Selection logic — tracks by findingId (resource_id) for checkbox consistency
  const selectedFindingIds = Object.keys(rowSelection)
    .filter((key) => rowSelection[key])
    .map((idx) => resources[parseInt(idx)]?.findingId)
    .filter((id): id is string => id !== null && id !== undefined && id !== "");

  /** Converts resource_ids (display) → resourceUids → finding UUIDs via API. */
  const resolveResourceIds = async (ids: string[]) => {
    const resourceUids = ids
      .map((id) => resources.find((r) => r.findingId === id)?.resourceUid)
      .filter(Boolean) as string[];
    if (resourceUids.length === 0) return [];
    return resolveFindingIds({
      checkId: group.checkId,
      resourceUids,
      filters,
      hasDateOrScanFilter: hasDateOrScan,
    });
  };

  const selectableRowCount = resources.filter(canMuteFindingResource).length;

  const getRowCanSelect = (row: Row<FindingResourceRow>): boolean => {
    return canMuteFindingResource(row.original);
  };

  const clearSelection = () => {
    setRowSelection({});
  };

  const isSelected = (id: string) => {
    return selectedFindingIds.includes(id);
  };

  const handleMuteComplete = () => {
    clearSelection();
    refresh();
  };

  const columns = getColumnFindingResources({
    rowSelection,
    selectableRowCount,
  });

  const table = useReactTable({
    data: resources,
    columns,
    enableRowSelection: getRowCanSelect,
    getCoreRowModel: getCoreRowModel(),
    onRowSelectionChange: setRowSelection,
    manualPagination: true,
    state: {
      rowSelection,
    },
  });

  // Delta for the sticky header
  const delta =
    group.newCount > 0
      ? DeltaValues.NEW
      : group.changedCount > 0
        ? DeltaValues.CHANGED
        : DeltaValues.NONE;

  const allMuted =
    group.mutedCount > 0 && group.mutedCount === group.resourcesTotal;

  const rows = table.getRowModel().rows;

  return (
    <FindingsSelectionContext.Provider
      value={{
        selectedFindingIds,
        selectedFindings: [],
        clearSelection,
        isSelected,
        resolveMuteIds: resolveResourceIds,
        onMuteComplete: handleMuteComplete,
      }}
    >
      <div
        className={cn(
          "minimal-scrollbar rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary",
          "flex w-full flex-col overflow-auto border",
        )}
      >
        {/* Sticky header — expanded finding group summary */}
        <div className="bg-bg-neutral-secondary border-border-neutral-secondary sticky top-0 z-10 border-b p-4">
          <div className="flex items-center gap-3">
            {/* Back button */}
            <button
              type="button"
              aria-label="Collapse and go back to findings"
              className="hover:bg-bg-neutral-tertiary flex size-8 items-center justify-center rounded-md transition-colors"
              onClick={onCollapse}
            >
              <ChevronLeft className="text-text-neutral-secondary size-5" />
            </button>

            {/* Notification indicator */}
            <NotificationIndicator delta={delta} isMuted={allMuted} />

            {/* Status badge */}
            <StatusFindingBadge status={group.status} />

            {/* Finding title */}
            <div className="min-w-0 flex-1">
              <p className="text-text-neutral-primary truncate text-sm font-medium">
                {group.checkTitle}
              </p>
            </div>

            {/* Severity */}
            <SeverityBadge severity={group.severity} />

            {/* Impacted resources count */}
            <ImpactedResourcesCell
              impacted={group.resourcesFail}
              total={group.resourcesTotal}
            />
          </div>
        </div>

        {/* Resources table */}
        <div className="p-4 pt-0">
          <Table>
            <TableHeader>
              {table.getHeaderGroups().map((headerGroup) => (
                <TableRow key={headerGroup.id}>
                  {headerGroup.headers.map((header) => (
                    <TableHead key={header.id}>
                      {header.isPlaceholder
                        ? null
                        : flexRender(
                            header.column.columnDef.header,
                            header.getContext(),
                          )}
                    </TableHead>
                  ))}
                </TableRow>
              ))}
            </TableHeader>
            <TableBody>
              {rows?.length ? (
                rows.map((row) => (
                  <TableRow
                    key={row.id}
                    data-state={row.getIsSelected() && "selected"}
                    className="cursor-pointer"
                    onClick={() => drawer.openDrawer(row.index)}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <TableCell key={cell.id}>
                        {flexRender(
                          cell.column.columnDef.cell,
                          cell.getContext(),
                        )}
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              ) : !isLoading ? (
                <TableRow className="hover:bg-transparent">
                  <TableCell
                    colSpan={columns.length}
                    className="h-24 text-center"
                  >
                    No resources found.
                  </TableCell>
                </TableRow>
              ) : null}
            </TableBody>
          </Table>

          {/* Loading indicator */}
          {isLoading && (
            <div className="flex items-center justify-center gap-2 py-8">
              <Spinner className="size-6" />
              <span className="text-text-neutral-tertiary text-sm">
                Loading resources...
              </span>
            </div>
          )}

          {/* Sentinel for infinite scroll */}
          <div ref={sentinelRef} className="h-1" />
        </div>
      </div>

      {selectedFindingIds.length > 0 && (
        <FloatingMuteButton
          selectedCount={selectedFindingIds.length}
          selectedFindingIds={selectedFindingIds}
          onBeforeOpen={async () => {
            return resolveResourceIds(selectedFindingIds);
          }}
          onComplete={handleMuteComplete}
          isBulkOperation
        />
      )}

      <ResourceDetailDrawer
        open={drawer.isOpen}
        onOpenChange={(open) => {
          if (!open) drawer.closeDrawer();
        }}
        isLoading={drawer.isLoading}
        isNavigating={drawer.isNavigating}
        checkMeta={drawer.checkMeta}
        currentIndex={drawer.currentIndex}
        totalResources={drawer.totalResources}
        currentFinding={drawer.currentFinding}
        otherFindings={drawer.otherFindings}
        onNavigatePrev={drawer.navigatePrev}
        onNavigateNext={drawer.navigateNext}
        onMuteComplete={handleDrawerMuteComplete}
      />
    </FindingsSelectionContext.Provider>
  );
}
