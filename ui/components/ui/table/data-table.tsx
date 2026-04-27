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
} from "@/components/ui/table";
import { DataTableAnimatedRow } from "@/components/ui/table/data-table-animated-row";
import { DataTablePagination } from "@/components/ui/table/data-table-pagination";
import { DataTableSearch } from "@/components/ui/table/data-table-search";
import { useFilterTransitionOptional } from "@/contexts";
import { cn } from "@/lib";
import { FilterOption, MetaDataProps } from "@/types";

/**
 * Default column size used by TanStack Table when no explicit size is set.
 * We skip applying inline width styles for columns with this default value
 * to allow them to flex naturally within the table layout.
 */
const DEFAULT_COLUMN_SIZE = 150;

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

  controlledSearch?: string;
  onSearchChange?: (value: string) => void;
  /**
   * Called when the user commits a search by pressing Enter.
   * Use this alongside onSearchChange to implement "search on Enter" behavior.
   */
  onSearchCommit?: (value: string) => void;
  controlledPage?: number;
  controlledPageSize?: number;
  onPaginationChange?: (page: number, pageSize: number) => void;
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
  /** Optional header rendered inside the table container, above the toolbar. */
  header?: ReactNode;
  /** Optional content rendered in the toolbar before the total entries count. */
  toolbarRightContent?: ReactNode;
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
  onPaginationChange,
  isLoading = false,
  searchPlaceholder,
  renderAfterRow,
  searchBadge,
  onRowClick,
  header,
  toolbarRightContent,
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

  const handleRowClick = (row: Row<TData>, target: HTMLElement | null) => {
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
      className={cn(
        "minimal-scrollbar rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary relative z-0 flex w-full flex-col justify-between gap-4 overflow-auto border p-4 transition-opacity duration-200",
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
            className="flex w-full flex-col items-start gap-2 md:ml-auto md:w-auto md:flex-row md:items-center md:gap-4"
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
      <Table className={getSubRows ? "table-fixed" : undefined}>
        <TableHeader>
          {table.getHeaderGroups().map((headerGroup) => (
            <TableRow key={`${headerGroup.id}-${selectionKey}-${expansionKey}`}>
              {headerGroup.headers.map((header) => {
                const size = header.getSize();
                return (
                  <TableHead
                    key={header.id}
                    style={
                      getSubRows && size !== DEFAULT_COLUMN_SIZE
                        ? { width: `${size}px` }
                        : undefined
                    }
                  >
                    {header.isPlaceholder
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
              rows.map((row) =>
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
                      data-state={row.getIsSelected() && "selected"}
                      className={cn(onRowClick && "cursor-pointer")}
                      onClick={(event) =>
                        handleRowClick(row, event.target as HTMLElement)
                      }
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
                    {renderAfterRow?.(row)}
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
          onPaginationChange={onPaginationChange}
        />
      )}
    </div>
  );
}
