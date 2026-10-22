"use client";

import {
  ColumnDef,
  ColumnFiltersState,
  ExpandedState,
  flexRender,
  getCoreRowModel,
  getExpandedRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  OnChangeFn,
  Row,
  RowSelectionState,
  SortingState,
  useReactTable,
} from "@tanstack/react-table";
import { AnimatePresence } from "framer-motion";
import type { ReactNode } from "react";
import { Fragment, useEffect, useRef, useState } from "react";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/shadcn/table";
import { DataTableAnimatedRow } from "@/components/shadcn/table/data-table-animated-row";
import {
  DataTablePagination,
  type DataTablePaginationLock,
} from "@/components/shadcn/table/data-table-pagination";
import { DataTableSearch } from "@/components/shadcn/table/data-table-search";
import { useFilterTransitionOptional } from "@/contexts";
import { useScrollportPin } from "@/hooks/use-scrollport-pin";
import { cn } from "@/lib/utils";
import { FilterOption, MetaDataProps } from "@/types";

type DataTableRowAttributes = {
  [key: `data-${string}`]: string | undefined;
};

/**
 * Default column size used by TanStack Table when no explicit size is set.
 * We skip applying inline width styles for columns with this default value
 * to allow them to flex naturally within the table layout.
 */
const DEFAULT_COLUMN_SIZE = 150;
const ACTIONS_COLUMN_ID = "actions";
const TABLE_COLUMN_GAP_CLASS = "pr-6";
const STICKY_ACTION_COLUMN_CLASS = "sticky right-0 z-20 min-w-12";
const STICKY_ACTION_CELL_CLASS = `${STICKY_ACTION_COLUMN_CLASS} last:rounded-r-none! overflow-visible bg-bg-neutral-secondary before:pointer-events-none before:absolute before:inset-y-0 before:-left-8 before:w-8 before:bg-gradient-to-r before:from-transparent before:to-bg-neutral-secondary before:content-[''] group-hover:bg-bg-neutral-tertiary group-hover:before:to-bg-neutral-tertiary group-data-[state=selected]:bg-bg-neutral-tertiary group-data-[state=selected]:before:to-bg-neutral-tertiary`;

// Locked cells stay in the DOM as a teaser but cannot be read or focused.
// The row receives clicks to open the upgrade prompt instead of cell actions.
// The blur goes on the cells: browsers do not reliably filter table rows.
const LOCKED_ROW_CLASS_NAME =
  "cursor-pointer select-none opacity-70 hover:bg-transparent [&>td]:blur-[6px]";

/**
 * Preview lock: rows past `visibleRowCount` render blurred with inert content,
 * `overlay` floats over them, and row/pagination clicks call `onLockedInteraction`.
 */
export interface DataTablePreviewLock extends DataTablePaginationLock {
  overlay: ReactNode;
}

const getTableColumnClassName = (
  columnId: string,
  variant: "header" | "cell",
) => {
  const isActionsColumn = columnId === ACTIONS_COLUMN_ID;

  return cn(
    !isActionsColumn && TABLE_COLUMN_GAP_CLASS,
    isActionsColumn && variant === "cell" && STICKY_ACTION_CELL_CLASS,
  );
};

interface DataTableProviderProps<TData, TValue> {
  columns: ColumnDef<TData, TValue>[];
  data: TData[];
  metadata?: MetaDataProps;
  customFilters?: FilterOption[];
  disableScroll?: boolean;
  enableRowSelection?: boolean;
  rowSelection?: RowSelectionState;
  onRowSelectionChange?: OnChangeFn<RowSelectionState>;
  /** Function to determine if a row can be selected */
  getRowCanSelect?: (row: Row<TData>) => boolean;
  /** Show search bar in the table toolbar */
  showSearch?: boolean;
  /** Function to extract sub-rows from a row for hierarchical data */
  getSubRows?: (row: TData) => TData[] | undefined;
  /** Controlled expanded state */
  expanded?: ExpandedState;
  /** Callback when expanded state changes */
  onExpandedChange?: OnChangeFn<ExpandedState>;
  /** Auto-select children when parent selected (default: true) */
  enableSubRowSelection?: boolean;
  /** Expand all rows by default, or provide specific expanded state */
  defaultExpanded?: boolean | ExpandedState;
  /** Prefix for URL params to avoid conflicts (e.g., "findings" -> "findingsPage") */
  paramPrefix?: string;

  /*
   * Controlled Mode Props
   * ---------------------
   * By default, DataTable uses URL params for pagination/search (via paramPrefix).
   * This causes Next.js page re-renders on every interaction.
   *
   * For tables inside drawers/modals, use controlled mode instead:
   * - Pass controlledPage, controlledPageSize, controlledSearch as state values
   * - Pass onPageChange, onPageSizeChange, onSearchChange as state setters
   * - This keeps state local, avoiding URL changes and unnecessary page re-renders
   *
   * Example:
   *   const [page, setPage] = useState(1);
   *   const [search, setSearch] = useState("");
   *   <DataTable
   *     controlledPage={page}
   *     onPageChange={setPage}
   *     controlledSearch={search}
   *     onSearchChange={setSearch}
   *     isLoading={isLoading}
   *   />
   */
  controlledSearch?: string;
  onSearchChange?: (value: string) => void;
  /**
   * Called when the user commits a search by pressing Enter.
   * Use this alongside onSearchChange to implement "search on Enter" behavior.
   */
  onSearchCommit?: (value: string) => void;
  controlledPage?: number;
  controlledPageSize?: number;
  onPageChange?: (page: number) => void;
  onPageSizeChange?: (pageSize: number) => void;
  /** Show loading state with opacity overlay (for controlled mode) */
  isLoading?: boolean;
  /** Custom placeholder text for the search input */
  searchPlaceholder?: string;
  /** Render additional content after each row (e.g., inline expansion) */
  renderAfterRow?: (row: Row<TData>) => ReactNode;
  /** Badge shown inside the search input (e.g., active drill-down group) */
  searchBadge?: { label: string; onDismiss: () => void };
  /** Optional click handler for top-level rows. */
  onRowClick?: (row: Row<TData>) => void;
  /** Optional data attributes applied to each top-level row. */
  getRowAttributes?: (row: Row<TData>) => DataTableRowAttributes;
  /** Optional header rendered inside the table container, above the toolbar. */
  header?: ReactNode;
  /** Optional content rendered in the toolbar before the total entries count. */
  toolbarRightContent?: ReactNode;
  previewLock?: DataTablePreviewLock;
}

export function DataTable<TData, TValue>({
  columns,
  data,
  metadata,
  disableScroll = false,
  enableRowSelection = false,
  rowSelection,
  onRowSelectionChange,
  getRowCanSelect,
  showSearch = false,
  getSubRows,
  expanded: controlledExpanded,
  onExpandedChange,
  enableSubRowSelection = true,
  defaultExpanded,
  paramPrefix = "",
  controlledSearch,
  onSearchChange,
  onSearchCommit,
  controlledPage,
  controlledPageSize,
  onPageChange,
  onPageSizeChange,
  isLoading = false,
  searchPlaceholder,
  renderAfterRow,
  searchBadge,
  onRowClick,
  getRowAttributes,
  header,
  toolbarRightContent,
  previewLock,
}: DataTableProviderProps<TData, TValue>) {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
  // ExpandedState should be a Record<string, boolean> for individual row control
  // Note: We don't use `true` (boolean) as it makes rows permanently expanded
  const [expanded, setExpanded] = useState<ExpandedState>(() => {
    if (typeof defaultExpanded === "object") return defaultExpanded;
    return {};
  });

  // Get transition state from context for loading indicator
  const filterTransition = useFilterTransitionOptional();
  // Use either context-based pending state or controlled isLoading prop
  const isPending = (filterTransition?.isPending ?? false) || isLoading;

  const table = useReactTable({
    data,
    columns,
    enableSorting: true,
    enableRowSelection: getRowCanSelect ?? enableRowSelection,
    getCoreRowModel: getCoreRowModel(),
    onSortingChange: setSorting,
    getSortedRowModel: getSortedRowModel(),
    onColumnFiltersChange: setColumnFilters,
    getFilteredRowModel: getFilteredRowModel(),
    onRowSelectionChange,
    manualPagination: true,
    // Expansion support for hierarchical data
    getSubRows,
    getExpandedRowModel: getSubRows ? getExpandedRowModel() : undefined,
    enableSubRowSelection,
    onExpandedChange: onExpandedChange ?? setExpanded,
    state: {
      sorting,
      columnFilters,
      rowSelection: rowSelection ?? {},
      expanded: controlledExpanded ?? expanded,
    },
  });

  // Track whether initial expansion has been applied
  const hasInitiallyExpanded = useRef(false);

  // The preview overlay pins itself to the visible scrollport: centered on the
  // full table width it would scroll away (and clip) on wide tables. Measured
  // on mount only, which is when a locked table arrives from the server.
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const previewOverlayRef = useRef<HTMLDivElement>(null);
  const lastRowRef = useRef<HTMLTableRowElement>(null);
  const [previewPaddingBottom, setPreviewPaddingBottom] = useState(0);
  const scrollportPin = useScrollportPin(() =>
    previewLock ? scrollContainerRef.current : null,
  );

  // Expand all rows on mount when defaultExpanded={true}
  useEffect(() => {
    if (
      !hasInitiallyExpanded.current &&
      defaultExpanded === true &&
      getSubRows
    ) {
      table.toggleAllRowsExpanded(true);
      hasInitiallyExpanded.current = true;
    }
  }, [defaultExpanded, getSubRows, table]);

  // Calculate selection key to force header re-render when selection changes
  const selectionKey = rowSelection
    ? Object.keys(rowSelection).filter((k) => rowSelection[k]).length
    : 0;

  // Calculate expansion key to force header re-render when expansion changes
  const currentExpanded = controlledExpanded ?? expanded;
  const expansionKey =
    currentExpanded === true
      ? "all"
      : typeof currentExpanded === "object"
        ? Object.keys(currentExpanded).filter((k) => currentExpanded[k]).length
        : 0;

  // Format total entries count
  const totalEntries = metadata?.pagination?.count ?? 0;
  const formattedTotal = totalEntries.toLocaleString();
  const showToolbar = showSearch || metadata || toolbarRightContent;

  const rows = table.getRowModel().rows;
  // Position in the rendered order, not row.index: the lock hides what the
  // user would see next, whatever the data order is.
  const isLockedPosition = (position: number) =>
    previewLock !== undefined && position >= previewLock.visibleRowCount;
  const overlayPosition =
    previewLock !== undefined && rows.length > previewLock.visibleRowCount
      ? previewLock.visibleRowCount - 1
      : null;

  // A short result set may not have enough blurred rows to contain the card.
  // Reserve its overflow inside the table so the scrollport cannot clip the CTA.
  useEffect(() => {
    const overlay = previewOverlayRef.current;
    const lastRow = lastRowRef.current;
    const scrollContainer = scrollContainerRef.current;
    if (overlayPosition === null || !overlay || !lastRow || !scrollContainer) {
      return;
    }

    const measure = () => {
      setPreviewPaddingBottom(
        Math.max(
          0,
          Math.ceil(
            overlay.getBoundingClientRect().bottom -
              lastRow.getBoundingClientRect().bottom,
          ),
        ),
      );
    };
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(measure);
    observer.observe(overlay);
    observer.observe(scrollContainer);
    return () => observer.disconnect();
  }, [overlayPosition, rows.length]);

  const handleRowClick = (
    row: Row<TData>,
    target: HTMLElement | null,
    position: number,
  ) => {
    if (isLockedPosition(position)) {
      previewLock?.onLockedInteraction();
      return;
    }

    if (!onRowClick) {
      return;
    }

    if (target?.closest("a, button, input, [role=menuitem]")) {
      return;
    }

    onRowClick(row);
  };

  return (
    <div
      ref={scrollContainerRef}
      // Expanded sub-rows pin themselves to this scrollport (sticky left) so
      // horizontal scrolling moves the group columns, not the expanded panel.
      data-table-scroll-container=""
      className={cn(
        "minimal-scrollbar border-border-neutral-secondary bg-bg-neutral-secondary relative z-0 flex w-full flex-col justify-between gap-4 overflow-auto rounded-[14px] border p-4 shadow-sm transition-opacity duration-200",
        isPending && "pointer-events-none opacity-60",
      )}
    >
      {header && <div className="w-full">{header}</div>}
      {/* Table Toolbar */}
      {showToolbar && (
        <div
          data-testid="data-table-toolbar"
          className="flex flex-col items-start gap-3 md:flex-row md:items-center md:justify-between"
        >
          <div className="w-full md:w-auto">
            {showSearch && (
              <DataTableSearch
                paramPrefix={paramPrefix}
                controlledValue={controlledSearch}
                onSearchChange={onSearchChange}
                onSearchCommit={onSearchCommit}
                placeholder={searchPlaceholder}
                badge={searchBadge}
              />
            )}
          </div>
          <div
            data-testid="data-table-toolbar-right"
            className="flex w-full flex-wrap items-center gap-x-4 gap-y-2 md:ml-auto md:w-auto"
          >
            {toolbarRightContent}
            {metadata && (
              <span className="text-text-neutral-secondary text-sm whitespace-nowrap">
                {formattedTotal} Total Entries
              </span>
            )}
          </div>
        </div>
      )}
      <Table
        className={getSubRows ? "table-fixed" : undefined}
        style={
          overlayPosition !== null
            ? { paddingBottom: previewPaddingBottom }
            : undefined
        }
      >
        <TableHeader>
          {table.getHeaderGroups().map((headerGroup) => (
            <TableRow key={`${headerGroup.id}-${selectionKey}-${expansionKey}`}>
              {headerGroup.headers.map((header) => {
                const size = header.getSize();
                const isActionsHeader = header.column.id === ACTIONS_COLUMN_ID;
                return (
                  <TableHead
                    key={header.id}
                    className={getTableColumnClassName(
                      header.column.id,
                      "header",
                    )}
                    style={
                      getSubRows && size !== DEFAULT_COLUMN_SIZE
                        ? { width: `${size}px` }
                        : undefined
                    }
                  >
                    {header.isPlaceholder || isActionsHeader
                      ? null
                      : flexRender(
                          header.column.columnDef.header,
                          header.getContext(),
                        )}
                  </TableHead>
                );
              })}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          <AnimatePresence initial={false}>
            {rows?.length ? (
              rows.map((row, position) =>
                getSubRows && row.depth > 0 ? (
                  <DataTableAnimatedRow
                    key={row.id}
                    row={row}
                    isSelected={row.getIsSelected()}
                    isSomeSelected={row.getIsSomeSelected()}
                  />
                ) : (
                  <Fragment key={row.id}>
                    <TableRow
                      ref={
                        position === rows.length - 1 ? lastRowRef : undefined
                      }
                      {...getRowAttributes?.(row)}
                      data-state={row.getIsSelected() && "selected"}
                      data-locked-row={
                        isLockedPosition(position) ? "" : undefined
                      }
                      aria-hidden={isLockedPosition(position) || undefined}
                      className={cn(
                        "group",
                        onRowClick && "cursor-pointer",
                        isLockedPosition(position) && LOCKED_ROW_CLASS_NAME,
                      )}
                      onClick={(event) =>
                        handleRowClick(
                          row,
                          event.target as HTMLElement,
                          position,
                        )
                      }
                    >
                      {row.getVisibleCells().map((cell) => (
                        <TableCell
                          key={cell.id}
                          className={getTableColumnClassName(
                            cell.column.id,
                            "cell",
                          )}
                        >
                          {isLockedPosition(position) ? (
                            <div inert className="pointer-events-none">
                              {flexRender(
                                cell.column.columnDef.cell,
                                cell.getContext(),
                              )}
                            </div>
                          ) : (
                            flexRender(
                              cell.column.columnDef.cell,
                              cell.getContext(),
                            )
                          )}
                        </TableCell>
                      ))}
                    </TableRow>
                    {!isLockedPosition(position) && renderAfterRow?.(row)}
                    {position === overlayPosition && previewLock && (
                      // Zero-height row: the overlay floats over the locked
                      // rows below without pushing them down.
                      <TableRow className="hover:bg-transparent">
                        <TableCell
                          colSpan={columns.length}
                          // p-0! beats first:pl-3/last:pr-3: any padding shrinks
                          // the range the sticky wrapper can pin across.
                          className="h-0 overflow-visible border-0 p-0! after:hidden"
                        >
                          {/* Sticky wrapper sized to the scrollport; without a
                              measurement it spans the row. z-30 clears the
                              sticky actions cells (z-20) of the locked rows. */}
                          <div
                            className="sticky left-0 z-30"
                            style={
                              scrollportPin && scrollportPin.width > 0
                                ? { width: scrollportPin.width }
                                : undefined
                            }
                          >
                            <div
                              ref={previewOverlayRef}
                              className="absolute inset-x-0 top-8 flex justify-center px-4"
                            >
                              {previewLock.overlay}
                            </div>
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                ),
              )
            ) : (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="h-24 text-center"
                >
                  No results.
                </TableCell>
              </TableRow>
            )}
          </AnimatePresence>
        </TableBody>
      </Table>
      {metadata && (
        <DataTablePagination
          metadata={metadata}
          disableScroll={disableScroll}
          paramPrefix={paramPrefix}
          controlledPage={controlledPage}
          controlledPageSize={controlledPageSize}
          onPageChange={onPageChange}
          onPageSizeChange={onPageSizeChange}
          lock={previewLock}
        />
      )}
    </div>
  );
}
