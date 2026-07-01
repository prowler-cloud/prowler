"use client";

import {
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { ChevronLeft } from "lucide-react";
import { useSearchParams } from "next/navigation";

import { LoadingState } from "@/components/shadcn/spinner/loading-state";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge, StatusFindingBadge } from "@/components/ui/table";
import { useFindingGroupResourceState } from "@/hooks/use-finding-group-resource-state";
import { cn, hasHistoricalFindingFilter } from "@/lib";
import {
  getFilteredFindingGroupDelta,
  getFindingGroupImpactedCounts,
  isFindingGroupMuted,
} from "@/lib/findings-groups";
import { FindingGroupRow } from "@/types";

import { FloatingMuteButton } from "../floating-mute-button";
import { getColumnFindingResources } from "./column-finding-resources";
import { FindingsSelectionContext } from "./findings-selection-context";
import { ImpactedResourcesCell } from "./impacted-resources-cell";
import { getFindingGroupEmptyStateMessage } from "./inline-resource-container.utils";
import { NotificationIndicator } from "./notification-indicator";
import { ResourceDetailDrawer } from "./resource-detail-drawer";

interface FindingsGroupDrillDownProps {
  group: FindingGroupRow;
  onCollapse: () => void;
}

export function FindingsGroupDrillDown({
  group,
  onCollapse,
}: FindingsGroupDrillDownProps) {
  const searchParams = useSearchParams();

  // Keep drill-down endpoint selection aligned with the grouped findings page.
  const currentParams = Object.fromEntries(searchParams.entries());
  const hasHistoricalFilterActive = hasHistoricalFindingFilter(currentParams);

  // Extract filter params from search params
  const filters: Record<string, string> = {};
  searchParams.forEach((value, key) => {
    if (key.startsWith("filter[") || key.includes("__in")) {
      filters[key] = value;
    }
  });

  const {
    rowSelection,
    resources,
    isLoading,
    sentinelRef,
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
  } = useFindingGroupResourceState({
    group,
    filters,
    hasHistoricalData: hasHistoricalFilterActive,
  });

  const columns = getColumnFindingResources({
    rowSelection,
    selectableRowCount,
  });

  const table = useReactTable({
    data: resources,
    columns,
    enableRowSelection: getRowCanSelect,
    getCoreRowModel: getCoreRowModel(),
    onRowSelectionChange: handleRowSelectionChange,
    manualPagination: true,
    state: {
      rowSelection,
    },
  });

  // Delta for the sticky header
  const deltaKey = getFilteredFindingGroupDelta(group, filters);
  const allMuted = isFindingGroupMuted(group);
  const impactedCounts = getFindingGroupImpactedCounts(group);

  const rows = table.getRowModel().rows;

  return (
    <FindingsSelectionContext.Provider
      value={{
        selectedFindingIds,
        selectedFindings: [],
        clearSelection,
        isSelected,
        resolveMuteIds: resolveSelectedFindingIds,
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
            <NotificationIndicator
              delta={deltaKey}
              isMuted={allMuted}
              showDeltaWhenMuted
            />

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
              impacted={impactedCounts.impacted}
              total={impactedCounts.total}
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
                    {getFindingGroupEmptyStateMessage(group, filters)}
                  </TableCell>
                </TableRow>
              ) : null}
            </TableBody>
          </Table>

          {/* Loading indicator */}
          {isLoading && <LoadingState label="Loading resources..." />}

          {/* Sentinel for infinite scroll */}
          <div ref={sentinelRef} className="h-1" />
        </div>
      </div>

      {selectedFindingIds.length > 0 && (
        <FloatingMuteButton
          selectedCount={selectedFindingIds.length}
          selectedFindingIds={selectedFindingIds}
          onBeforeOpen={async () => {
            return resolveSelectedFindingIds(selectedFindingIds);
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
        currentResource={drawer.currentResource}
        currentFinding={drawer.currentFinding}
        otherFindings={drawer.otherFindings}
        showSyntheticResourceHint={group.resourcesTotal === 0}
        onNavigatePrev={drawer.navigatePrev}
        onNavigateNext={drawer.navigateNext}
        onMuteComplete={handleDrawerMuteComplete}
      />
    </FindingsSelectionContext.Provider>
  );
}
