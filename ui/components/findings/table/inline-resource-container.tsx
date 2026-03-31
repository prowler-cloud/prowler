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

import { resolveFindingIds } from "@/actions/findings/findings-by-resource";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { TableCell, TableRow } from "@/components/ui/table";
import { useInfiniteResources } from "@/hooks/use-infinite-resources";
import { useScrollHint } from "@/hooks/use-scroll-hint";
import { hasDateOrScanFilter } from "@/lib";
import { FindingGroupRow, FindingResourceRow } from "@/types";

import { getColumnFindingResources } from "./column-finding-resources";
import { FindingsSelectionContext } from "./findings-selection-context";
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
  /** Called with selected resource UIDs (not finding IDs) for parent-level mute resolution */
  onResourceSelectionChange: (resourceUids: string[]) => void;
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

function ResourceSkeletonRow() {
  return (
    <TableRow className="hover:bg-transparent">
      {/* Select: indicator + corner arrow + checkbox */}
      <TableCell>
        <div className="flex items-center gap-2">
          <Skeleton className="size-1.5 rounded-full" />
          <Skeleton className="size-4 rounded" />
          <div className="bg-bg-input-primary border-border-input-primary size-5 rounded-sm border shadow-[0_1px_2px_0_rgba(0,0,0,0.1)]" />
        </div>
      </TableCell>
      {/* Resource: icon + name + uid */}
      <TableCell>
        <div className="flex items-center gap-2">
          <Skeleton className="size-4 rounded" />
          <div className="space-y-1">
            <Skeleton className="h-3.5 w-32 rounded" />
            <Skeleton className="h-3 w-20 rounded" />
          </div>
        </div>
      </TableCell>
      {/* Status */}
      <TableCell>
        <Skeleton className="h-6 w-11 rounded-md" />
      </TableCell>
      {/* Service */}
      <TableCell>
        <Skeleton className="h-4 w-16 rounded" />
      </TableCell>
      {/* Region */}
      <TableCell>
        <Skeleton className="h-4 w-20 rounded" />
      </TableCell>
      {/* Severity */}
      <TableCell>
        <div className="flex items-center gap-2">
          <Skeleton className="size-2 rounded-full" />
          <Skeleton className="h-4 w-12 rounded" />
        </div>
      </TableCell>
      {/* Account: provider icon + alias + uid */}
      <TableCell>
        <div className="flex items-center gap-2">
          <Skeleton className="size-4 rounded" />
          <div className="space-y-1">
            <Skeleton className="h-3.5 w-24 rounded" />
            <Skeleton className="h-3 w-16 rounded" />
          </div>
        </div>
      </TableCell>
      {/* Last seen */}
      <TableCell>
        <Skeleton className="h-4 w-24 rounded" />
      </TableCell>
      {/* Failing for */}
      <TableCell>
        <Skeleton className="h-4 w-16 rounded" />
      </TableCell>
      {/* Actions */}
      <TableCell>
        <Skeleton className="size-6 rounded" />
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

  const { sentinelRef, refresh, loadMore } = useInfiniteResources({
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
    totalResourceCount: group.resourcesTotal,
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

  const selectableRowCount = resources.filter((r) => !r.isMuted).length;

  const getRowCanSelect = (row: Row<FindingResourceRow>): boolean => {
    return !row.original.isMuted;
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

    const newResourceUids = Object.keys(newSelection)
      .filter((key) => newSelection[key])
      .map((idx) => resources[parseInt(idx)]?.resourceUid)
      .filter(Boolean);
    onResourceSelectionChange(newResourceUids);
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
                        Array.from({
                          length: Math.min(
                            group.resourcesTotal,
                            MAX_SKELETON_ROWS,
                          ),
                        }).map((_, i) => <ResourceSkeletonRow key={i} />)
                      ) : rows.length > 0 ? (
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
