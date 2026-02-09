"use client";

import {
  ColumnDef,
  ColumnFiltersState,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  OnChangeFn,
  Row,
  RowSelectionState,
  SortingState,
  useReactTable,
} from "@tanstack/react-table";
import { useState } from "react";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { DataTablePagination } from "@/components/ui/table/data-table-pagination";
import { DataTableSearch } from "@/components/ui/table/data-table-search";
import { useFilterTransitionOptional } from "@/contexts";
import { cn } from "@/lib";
import { FilterOption, MetaDataProps } from "@/types";

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
    state: {
      sorting,
      columnFilters,
      rowSelection: rowSelection ?? {},
    },
  });

  // Calculate selection key to force header re-render when selection changes
  const selectionKey = rowSelection
    ? Object.keys(rowSelection).filter((k) => rowSelection[k]).length
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
      <Table>
        <TableHeader>
          {table.getHeaderGroups().map((headerGroup) => (
            <TableRow key={`${headerGroup.id}-${selectionKey}`}>
              {headerGroup.headers.map((header) => {
                return (
                  <TableHead key={header.id}>
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
          {rows?.length ? (
            rows.map((row) => (
              <TableRow
                key={row.id}
                data-state={row.getIsSelected() && "selected"}
              >
                {row.getVisibleCells().map((cell) => (
                  <TableCell key={cell.id}>
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </TableCell>
                ))}
              </TableRow>
            ))
          ) : (
            <TableRow>
              <TableCell colSpan={columns.length} className="h-24 text-center">
                No results.
              </TableCell>
            </TableRow>
          )}
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
