"use client";

import {
  ColumnDef,
  ColumnFiltersState,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
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
}: DataTableProviderProps<TData, TValue>) {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);

  const table = useReactTable({
    data,
    columns,
    enableSorting: true,
    // Use getRowCanSelect function if provided, otherwise use boolean
    enableRowSelection: getRowCanSelect ?? enableRowSelection,
    getCoreRowModel: getCoreRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
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

  return (
    <div className="minimal-scrollbar rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary relative z-0 flex w-full flex-col justify-between gap-4 overflow-auto border p-4">
      {/* Table Toolbar */}
      {(showSearch || metadata) && (
        <div className="flex items-center justify-between">
          <div>{showSearch && <DataTableSearch />}</div>
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
          {table.getRowModel().rows?.length ? (
            table.getRowModel().rows.map((row) => (
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
        />
      )}
    </div>
  );
}
