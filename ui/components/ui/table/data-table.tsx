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
import { useEffect, useRef, useState } from "react";

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
  controlledPage?: number;
  controlledPageSize?: number;
  onPageChange?: (page: number) => void;
  onPageSizeChange?: (pageSize: number) => void;
  /** Show loading state with opacity overlay (for controlled mode) */
  isLoading?: boolean;
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
  controlledPage,
  controlledPageSize,
  onPageChange,
  onPageSizeChange,
  isLoading = false,
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
  const showToolbar = showSearch || metadata;

  const rows = table.getRowModel().rows;

  return (
    <div
      className={cn(
        "minimal-scrollbar rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary relative z-0 flex w-full flex-col justify-between gap-4 overflow-auto border p-4 transition-opacity duration-200",
        isPending && "pointer-events-none opacity-60",
      )}
    >
      {/* Table Toolbar */}
      {showToolbar && (
        <div className="flex items-center justify-between">
          <div>
            {showSearch && (
              <DataTableSearch
                paramPrefix={paramPrefix}
                controlledValue={controlledSearch}
                onSearchChange={onSearchChange}
              />
            )}
          </div>
          {metadata && (
            <span className="text-text-neutral-secondary text-sm">
              {formattedTotal} Total Entries
            </span>
          )}
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
                  <DataTableAnimatedRow key={row.id} row={row} />
                ) : (
                  <TableRow
                    key={row.id}
                    data-state={row.getIsSelected() && "selected"}
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
        />
      )}
    </div>
  );
}
