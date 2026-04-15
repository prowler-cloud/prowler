"use client";

import {
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronsDown } from "lucide-react";
import { useImperativeHandle, useRef } from "react";

import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { TableCell, TableRow } from "@/components/ui/table";
import { useFindingGroupResourceState } from "@/hooks/use-finding-group-resource-state";
import { useScrollHint } from "@/hooks/use-scroll-hint";
import { FindingGroupRow } from "@/types";

import { getColumnFindingResources } from "./column-finding-resources";
import { FindingsSelectionContext } from "./findings-selection-context";
import {
  getFilteredFindingGroupResourceCount,
  getFindingGroupSkeletonCount,
} from "./inline-resource-container.utils";
import { ResourceDetailDrawer } from "./resource-detail-drawer";

export interface InlineResourceContainerHandle {
  /** Soft-refresh resources (re-fetch page 1 without skeletons). */
  refresh: () => void;
  /** Clear internal row selection and notify parent. */
  clearSelection: () => void;
}

interface InlineResourceContainerProps {
  group: FindingGroupRow;
  resolvedFilters: Record<string, string>;
  hasHistoricalData: boolean;
  resourceSearch: string;
  columnCount: number;
  /** Called with selected finding IDs (real UUIDs) for parent-level mute */
  onResourceSelectionChange: (findingIds: string[]) => void;
  ref?: React.Ref<InlineResourceContainerHandle>;
}

// NOTE: We intentionally do NOT auto-select child resources when a parent group
// is selected. Group-level mute resolution now fetches the group's visible
// resources separately. Auto-selecting children would still require syncing state
// with infinite scroll (resources load 10 at a time), causing cascading setState
// during render and confusing partial selections. Resource-level checkboxes are
// for selecting a specific subset independently.

/** Max skeleton rows that fit in the 440px scroll container */
const MAX_SKELETON_ROWS = 7;

function ResourceSkeletonRow({
  isEmptyStateSized = false,
}: {
  isEmptyStateSized?: boolean;
}) {
  const cellClassName = isEmptyStateSized ? "h-24 py-3" : "py-3";

  return (
    <TableRow className="hover:bg-transparent">
      {/* Select: indicator + corner arrow + checkbox */}
      <TableCell className={cellClassName}>
        <div className="flex items-center gap-2">
          <Skeleton className="size-1.5 rounded-full" />
          <Skeleton className="size-4 rounded" />
          <div className="bg-bg-input-primary border-border-input-primary size-5 rounded-sm border shadow-[0_1px_2px_0_rgba(0,0,0,0.1)]" />
        </div>
      </TableCell>
      {/* Resource: icon + name + uid */}
      <TableCell className={cellClassName}>
        <div className="flex items-center gap-2">
          <Skeleton className="size-4 rounded" />
          <div className="space-y-1.5">
            <Skeleton className="h-4 w-32 rounded" />
            <Skeleton className="h-3.5 w-20 rounded" />
          </div>
        </div>
      </TableCell>
      {/* Status */}
      <TableCell className={cellClassName}>
        <Skeleton className="h-6 w-11 rounded-md" />
      </TableCell>
      {/* Service */}
      <TableCell className={cellClassName}>
        <Skeleton className="h-4.5 w-16 rounded" />
      </TableCell>
      {/* Region */}
      <TableCell className={cellClassName}>
        <Skeleton className="h-4.5 w-20 rounded" />
      </TableCell>
      {/* Severity */}
      <TableCell className={cellClassName}>
        <div className="flex items-center gap-2">
          <Skeleton className="size-2 rounded-full" />
          <Skeleton className="h-4.5 w-12 rounded" />
        </div>
      </TableCell>
      {/* Account: provider icon + alias + uid */}
      <TableCell className={cellClassName}>
        <div className="flex items-center gap-2">
          <Skeleton className="size-4 rounded" />
          <div className="space-y-1.5">
            <Skeleton className="h-4 w-24 rounded" />
            <Skeleton className="h-3.5 w-16 rounded" />
          </div>
        </div>
      </TableCell>
      {/* Last seen */}
      <TableCell className={cellClassName}>
        <Skeleton className="h-4.5 w-24 rounded" />
      </TableCell>
      {/* Failing for */}
      <TableCell className={cellClassName}>
        <Skeleton className="h-4.5 w-16 rounded" />
      </TableCell>
      {/* Actions */}
      <TableCell className={cellClassName}>
        <Skeleton className="size-8 rounded-md" />
      </TableCell>
    </TableRow>
  );
}

export function InlineResourceContainer({
  group,
  resolvedFilters,
  hasHistoricalData,
  resourceSearch,
  columnCount,
  onResourceSelectionChange,
  ref,
}: InlineResourceContainerProps) {
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const filters: Record<string, string> = { ...resolvedFilters };
  if (resourceSearch) {
    filters["filter[name__icontains]"] = resourceSearch;
  }

  const skeletonRowCount = getFindingGroupSkeletonCount(
    group,
    filters,
    MAX_SKELETON_ROWS,
  );
  const filteredResourceCount = getFilteredFindingGroupResourceCount(
    group,
    filters,
  );

  const {
    rowSelection,
    resources,
    isLoading,
    sentinelRef,
    refresh,
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
    hasHistoricalData,
    onResourceSelectionChange,
    scrollContainerRef,
  });

  // Scroll hint: shows "scroll for more" when content overflows
  const {
    containerRef: scrollHintContainerRef,
    sentinelRef: scrollHintSentinelRef,
    showScrollHint,
  } = useScrollHint({ refreshToken: resources.length });

  // Combine scrollContainerRef (for IntersectionObserver root) with scrollHintContainerRef
  const combinedScrollRef = (node: HTMLDivElement | null) => {
    scrollContainerRef.current = node;
    scrollHintContainerRef(node);
  };

  useImperativeHandle(ref, () => ({ refresh, clearSelection }));

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
      <tr>
        <td colSpan={columnCount} className="p-0">
          <AnimatePresence initial>
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.2, ease: "easeOut" }}
              className="overflow-hidden"
            >
              <div className="relative">
                <div
                  ref={combinedScrollRef}
                  className="max-h-[440px] overflow-y-auto pl-6"
                >
                  {/* Resource rows or skeleton placeholder */}
                  <table className="-mt-2.5 w-full border-separate border-spacing-y-4">
                    <tbody>
                      {isLoading && rows.length === 0 ? (
                        Array.from({ length: skeletonRowCount }).map((_, i) => (
                          <ResourceSkeletonRow
                            key={i}
                            isEmptyStateSized={filteredResourceCount === 0}
                          />
                        ))
                      ) : rows.length > 0 ? (
                        rows.map((row) => (
                          <TableRow
                            key={row.id}
                            data-state={row.getIsSelected() && "selected"}
                            className="cursor-pointer"
                            onClick={(e) => {
                              // Don't open drawer if clicking interactive elements
                              // (links, buttons, checkboxes, dropdown items)
                              const target = e.target as HTMLElement;
                              if (
                                target.closest(
                                  "a, button, input, [role=menuitem]",
                                )
                              )
                                return;
                              drawer.openDrawer(row.index);
                            }}
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
                      ) : (
                        <TableRow className="hover:bg-transparent">
                          <TableCell
                            colSpan={columns.length}
                            className="h-24 text-center"
                          >
                            {Object.keys(filters).length > 0
                              ? "No resources found for the selected filters."
                              : "No resources found."}
                          </TableCell>
                        </TableRow>
                      )}
                    </tbody>
                  </table>

                  {/* Spinner for infinite scroll (subsequent pages only) */}
                  {isLoading && rows.length > 0 && (
                    <div className="flex items-center justify-center gap-2 py-8">
                      <Spinner className="size-6" />
                      <span className="text-text-neutral-tertiary text-sm">
                        Loading resources...
                      </span>
                    </div>
                  )}

                  {/* Sentinel for scroll hint detection */}
                  <div
                    ref={scrollHintSentinelRef}
                    aria-hidden
                    className="h-px shrink-0"
                  />

                  {/* Sentinel for infinite scroll */}
                  <div ref={sentinelRef} className="h-1" />
                </div>

                {/* Gradients rendered after scroll container so they paint on top */}
                <div className="from-bg-neutral-secondary pointer-events-none absolute top-0 right-0 left-6 z-20 h-6 bg-gradient-to-b to-transparent" />
                <div className="from-bg-neutral-secondary pointer-events-none absolute right-0 bottom-0 left-6 z-20 h-6 bg-gradient-to-t to-transparent" />

                {/* Scroll hint */}
                {showScrollHint && (
                  <div className="pointer-events-none absolute right-0 bottom-0 left-6 z-30">
                    <div className="absolute inset-x-0 bottom-2 flex justify-center">
                      <div className="bg-bg-neutral-tertiary text-text-neutral-secondary animate-bounce rounded-full px-3 py-1 text-xs shadow-md">
                        <ChevronsDown className="inline size-3.5" /> Scroll for
                        more
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </motion.div>
          </AnimatePresence>
        </td>
      </tr>

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
