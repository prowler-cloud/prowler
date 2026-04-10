"use client";

import {
  flexRender,
  getCoreRowModel,
  Row,
  RowSelectionState,
  useReactTable,
} from "@tanstack/react-table";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronsDown } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { useImperativeHandle, useRef, useState } from "react";

import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { TableCell, TableRow } from "@/components/ui/table";
import { useInfiniteResources } from "@/hooks/use-infinite-resources";
import { useScrollHint } from "@/hooks/use-scroll-hint";
import { hasDateOrScanFilter } from "@/lib";
import { FindingGroupRow, FindingResourceRow } from "@/types";

import { getColumnFindingResources } from "./column-finding-resources";
import { canMuteFindingResource } from "./finding-resource-selection";
import { FindingsSelectionContext } from "./findings-selection-context";
import {
  getFilteredFindingGroupResourceCount,
  getFindingGroupSkeletonCount,
} from "./inline-resource-container.utils";
import {
  ResourceDetailDrawer,
  useResourceDetailDrawer,
} from "./resource-detail-drawer";

export interface InlineResourceContainerHandle {
  /** Soft-refresh resources (re-fetch page 1 without skeletons). */
  refresh: () => void;
  /** Clear internal row selection and notify parent. */
  clearSelection: () => void;
}

interface InlineResourceContainerProps {
  group: FindingGroupRow;
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
  resourceSearch,
  columnCount,
  onResourceSelectionChange,
  ref,
}: InlineResourceContainerProps) {
  const searchParams = useSearchParams();
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [resources, setResources] = useState<FindingResourceRow[]>([]);
  const [isLoading, setIsLoading] = useState(true);
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

  // Derive hasDateOrScan from current URL params
  const currentParams = Object.fromEntries(searchParams.entries());
  const hasDateOrScan = hasDateOrScanFilter(currentParams);

  // Extract filter params from search params, merge with local resource search
  const filters: Record<string, string> = {};
  searchParams.forEach((value, key) => {
    if (key.startsWith("filter[") || key.includes("__in")) {
      filters[key] = value;
    }
  });
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
    scrollContainerRef,
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

  // Selection logic
  const selectedFindingIds = Object.keys(rowSelection)
    .filter((key) => rowSelection[key])
    .map((idx) => resources[parseInt(idx)]?.findingId)
    .filter(Boolean);

  const resolveResourceIds = async (ids: string[]) => {
    // findingId values are already real finding UUIDs (from the group
    // resources endpoint), so no second resolution round-trip is needed.
    return ids.filter(Boolean);
  };

  const selectableRowCount = resources.filter(canMuteFindingResource).length;

  const getRowCanSelect = (row: Row<FindingResourceRow>): boolean => {
    return canMuteFindingResource(row.original);
  };

  const clearSelection = () => {
    setRowSelection({});
    onResourceSelectionChange([]);
  };

  useImperativeHandle(ref, () => ({ refresh, clearSelection }));

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

    const newFindingIds = Object.keys(newSelection)
      .filter((key) => newSelection[key])
      .map((idx) => resources[parseInt(idx)]?.findingId)
      .filter(Boolean);
    onResourceSelectionChange(newFindingIds);
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
        resolveMuteIds: resolveResourceIds,
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
                            No resources found.
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
