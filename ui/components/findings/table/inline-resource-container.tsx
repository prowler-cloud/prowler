"use client";

import {
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronsDown } from "lucide-react";
import { useImperativeHandle, useRef, useState } from "react";

import {
  loadFindingTriageDetail,
  loadLatestFindingTriageNote,
  updateFindingTriage,
} from "@/actions/findings";
import { LighthouseContextContributor } from "@/components/lighthouse/context-contributor";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { LoadingState } from "@/components/shadcn/spinner/loading-state";
import { TableCell, TableRow } from "@/components/shadcn/table";
import { useFindingGroupResourceState } from "@/hooks/use-finding-group-resource-state";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { useScrollHint } from "@/hooks/use-scroll-hint";
import { buildFindingResourceContext } from "@/lib/lighthouse/context/contributions";
import { cn } from "@/lib/utils";
import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";
import { FindingGroupRow } from "@/types";

import { getColumnFindingResources } from "./column-finding-resources";
import { FindingsSelectionContext } from "./findings-selection-context";
import {
  getFilteredFindingGroupResourceCount,
  getFindingGroupEmptyStateMessage,
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
  contextSelectionLimit: number;
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
const ACTIONS_COLUMN_ID = "actions";
const COMPACT_LABELED_COLUMN_IDS = new Set([
  "service",
  "region",
  "lastSeen",
  "failingFor",
  "triage",
]);
const STICKY_RESOURCE_ACTION_CELL_CLASS =
  "sticky right-0 z-20 min-w-12 last:rounded-r-none! overflow-visible bg-bg-neutral-secondary before:pointer-events-none before:absolute before:inset-y-0 before:-left-8 before:w-8 before:bg-gradient-to-r before:from-transparent before:to-bg-neutral-secondary before:content-[''] group-hover:bg-bg-neutral-tertiary group-hover:before:to-bg-neutral-tertiary group-data-[state=selected]:bg-bg-neutral-tertiary group-data-[state=selected]:before:to-bg-neutral-tertiary";

// The hover Skills pill overhangs the first cell into the scrollport's pl-6
// indent, which the row background never paints (and the row's rounded-l-full
// cap starts at the cell edge). This pseudo-element repaints the highlight
// from 24px left of the cell, so the hovered/selected row visually contains
// the pill instead of leaving a dark notch around it.
const SELECT_CELL_HOVER_EXTENSION_CLASS =
  "relative before:pointer-events-none before:absolute before:inset-y-0 before:-left-6 before:right-0 before:rounded-l-full before:content-[''] before:bg-transparent before:transition-colors group-hover:before:bg-bg-neutral-tertiary group-data-[state=selected]:before:bg-bg-neutral-tertiary";

const getResourceCellClassName = (columnId: string) =>
  cn(
    COMPACT_LABELED_COLUMN_IDS.has(columnId) && "align-top",
    columnId === "select" && SELECT_CELL_HOVER_EXTENSION_CLASS,
    columnId === ACTIONS_COLUMN_ID && STICKY_RESOURCE_ACTION_CELL_CLASS,
  );

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
      {/* Affected failing resource: name + uid */}
      <TableCell className={cellClassName}>
        <div className="space-y-1.5">
          <Skeleton className="h-4 w-32 rounded" />
          <Skeleton className="h-3.5 w-20 rounded" />
        </div>
      </TableCell>
      {/* Provider: alias + uid */}
      <TableCell className={cellClassName}>
        <div className="space-y-1.5">
          <Skeleton className="h-4 w-24 rounded" />
          <Skeleton className="h-3.5 w-16 rounded" />
        </div>
      </TableCell>
      {/* Severity */}
      <TableCell className={cellClassName}>
        <div className="flex items-center gap-2">
          <Skeleton className="size-2 rounded-full" />
          <Skeleton className="h-4.5 w-12 rounded" />
        </div>
      </TableCell>
      {/* Service */}
      <TableCell className={cellClassName}>
        <Skeleton className="h-4.5 w-16 rounded" />
      </TableCell>
      {/* Region */}
      <TableCell className={cellClassName}>
        <Skeleton className="h-4.5 w-20 rounded" />
      </TableCell>
      {/* Last seen */}
      <TableCell className={cellClassName}>
        <Skeleton className="h-4.5 w-24 rounded" />
      </TableCell>
      {/* Failing for */}
      <TableCell className={cellClassName}>
        <Skeleton className="h-4.5 w-16 rounded" />
      </TableCell>
      {/* Triage */}
      <TableCell className={cellClassName}>
        <Skeleton className="h-8 w-20 rounded-lg" />
      </TableCell>
      {/* Actions */}
      <TableCell
        className={cn(cellClassName, STICKY_RESOURCE_ACTION_CELL_CLASS)}
      >
        <div className="flex justify-end">
          <Skeleton className="size-8 rounded-md" />
        </div>
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
  contextSelectionLimit,
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
    selectedResources,
    selectedFindingIds,
    selectableRowCount,
    getRowId,
    getRowCanSelect,
    clearSelection,
    isSelected,
    handleMuteComplete,
    handleRowSelectionChange,
    resolveSelectedFindingIds,
    updateTriageOptimistically,
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

  // Pin geometry for the expanded panel (PostHog-style): sized to the outer
  // card's scrollport and stuck to its left edge, so horizontal scrolling
  // moves the group columns while this block stays in place — which also
  // lets the sub-table's own sticky actions column anchor to a scrollport
  // that is actually visible from the start.
  const [scrollportPin, setScrollportPin] = useState<{
    width: number;
    left: number;
  } | null>(null);
  useMountEffect(() => {
    const scrollParent = scrollContainerRef.current?.closest(
      "[data-table-scroll-container]",
    );
    if (!(scrollParent instanceof HTMLElement)) return;
    const measure = () => {
      const styles = getComputedStyle(scrollParent);
      const paddingLeft = parseFloat(styles.paddingLeft);
      setScrollportPin({
        width:
          scrollParent.clientWidth -
          paddingLeft -
          parseFloat(styles.paddingRight),
        left: paddingLeft,
      });
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(scrollParent);
    return () => observer.disconnect();
  });

  // Combine scrollContainerRef (for IntersectionObserver root) with scrollHintContainerRef
  const combinedScrollRef = (node: HTMLDivElement | null) => {
    scrollContainerRef.current = node;
    scrollHintContainerRef(node);
  };

  useImperativeHandle(ref, () => ({ refresh, clearSelection }));

  // A skill launch opens the drawer behind the chat: the Details tab must
  // register without stealing the AI tab the launch just selected.
  const [isSkillLaunchDrawer, setIsSkillLaunchDrawer] = useState(false);

  const columns = getColumnFindingResources({
    rowSelection,
    selectableRowCount,
    findingTitle: group.checkTitle,
    onSkillLaunchOpenDrawer: (rowIndex) => {
      setIsSkillLaunchDrawer(true);
      drawer.openDrawer(rowIndex);
    },
    onTriageUpdateAction: (input) =>
      updateTriageOptimistically(input, updateFindingTriage),
    onTriageNoteLoadAction: loadLatestFindingTriageNote,
    onTriageDetailLoadAction: loadFindingTriageDetail,
  });

  const table = useReactTable({
    data: resources,
    columns,
    enableRowSelection: getRowCanSelect,
    getRowId,
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
      {selectedResources.slice(0, contextSelectionLimit).map((finding) => (
        <LighthouseContextContributor
          key={`finding-resource-${finding.findingId}`}
          contributorId={`finding-resource-${finding.findingId}`}
          item={buildFindingResourceContext(finding)}
        />
      ))}
      <tr>
        <td colSpan={columnCount} className="max-w-0 p-0">
          <AnimatePresence initial>
            <motion.div
              // Onboarding anchor: the "Review the affected resources" tour step.
              data-tour-id="explore-findings-resources"
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.2, ease: "easeOut" }}
              className="sticky overflow-hidden"
              // Without a measured scrollport the insets stay auto, which
              // makes the sticky inert and falls back to spanning the row.
              style={
                scrollportPin
                  ? { width: scrollportPin.width, left: scrollportPin.left }
                  : undefined
              }
            >
              <div className="relative">
                <div
                  ref={combinedScrollRef}
                  // pl (not ml): padding sits inside the overflow clip region,
                  // giving the hover Skills pill room to extend left over the
                  // row indent — a margin would clip it at the content edge.
                  className="minimal-scrollbar max-h-[440px] overflow-auto pl-6"
                >
                  {/* Resource rows or skeleton placeholder. No w-max: auto
                      table layout compresses truncatable cells to fit, so
                      horizontal scroll (and its extra trackpad gestures) only
                      appears when columns genuinely can't fit. */}
                  <table className="-mt-2.5 min-w-full border-separate border-spacing-y-4">
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
                            className="group cursor-pointer"
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
                              setIsSkillLaunchDrawer(false);
                              drawer.openDrawer(row.index);
                              // The drawer may already be mounted (e.g. after
                              // a skill launch left the AI tab in front):
                              // a row click always fronts the Details tab.
                              useSidePanelStore
                                .getState()
                                .openPanel(SIDE_PANEL_TAB.CONTEXT);
                            }}
                          >
                            {row.getVisibleCells().map((cell) => (
                              <TableCell
                                key={cell.id}
                                className={getResourceCellClassName(
                                  cell.column.id,
                                )}
                              >
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
                            {getFindingGroupEmptyStateMessage(group, filters)}
                          </TableCell>
                        </TableRow>
                      )}
                    </tbody>
                  </table>

                  {/* Loading state for infinite scroll (subsequent pages only) */}
                  {isLoading && rows.length > 0 && (
                    <LoadingState label="Loading resources..." />
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
          if (!open) {
            drawer.closeDrawer();
            setIsSkillLaunchDrawer(false);
          }
        }}
        selectTabOnOpen={!isSkillLaunchDrawer}
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
        onTriageUpdate={drawer.patchTriageUpdate}
      />
    </FindingsSelectionContext.Provider>
  );
}
