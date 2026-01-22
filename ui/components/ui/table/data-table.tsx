"use client";

import {
  ColumnDef,
  ColumnFiltersState,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  OnChangeFn,
  PaginationState,
  Row,
  RowSelectionState,
  SortingState,
  useReactTable,
} from "@tanstack/react-table";
import { useEffect, useState } from "react";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { DataTableClientPagination } from "@/components/ui/table/data-table-client-pagination";
import { ClientSideSearch } from "@/components/ui/table/data-table-client-search";
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
  /** Enable client-side pagination (for data already loaded in memory) */
  clientSidePagination?: boolean;
  /** Default page size for client-side pagination */
  defaultPageSize?: number;
  /** Function to filter data for client-side search. Returns true if row matches search term */
  clientSearchFilter?: (row: TData, searchTerm: string) => boolean;
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
  clientSidePagination = false,
  defaultPageSize = 10,
  clientSearchFilter,
}: DataTableProviderProps<TData, TValue>) {
  const [sorting, setSorting] = useState<SortingState>([]);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
  const [pagination, setPagination] = useState<PaginationState>({
    pageIndex: 0,
    pageSize: defaultPageSize,
  });
  const [clientSearchTerm, setClientSearchTerm] = useState("");

  // Get transition state from context for loading indicator
  const filterTransition = useFilterTransitionOptional();
  const isPending = filterTransition?.isPending ?? false;

  // Filter data for client-side search
  const filteredData =
    clientSearchFilter && clientSearchTerm
      ? data.filter((row) => clientSearchFilter(row, clientSearchTerm))
      : data;

  // Reset to first page when search changes
  useEffect(() => {
    if (clientSidePagination) {
      setPagination((prev) => ({ ...prev, pageIndex: 0 }));
    }
  }, [clientSearchTerm, clientSidePagination]);

  const table = useReactTable({
    data: filteredData,
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

  // Calculate pagination info for client-side pagination
  const totalPages = clientSidePagination
    ? Math.ceil(filteredData.length / pagination.pageSize)
    : 1;

  // Calculate selection key to force header re-render when selection changes
  const selectionKey = rowSelection
    ? Object.keys(rowSelection).filter((k) => rowSelection[k]).length
    : 0;

  // Format total entries count
  const totalEntries = clientSidePagination
    ? filteredData.length
    : (metadata?.pagination?.count ?? 0);
  const formattedTotal = totalEntries.toLocaleString();
  const showToolbar = showSearch || metadata || clientSidePagination;
  const useClientSearch = showSearch && clientSearchFilter;

  // For client-side pagination, manually slice the data
  const paginatedRows = clientSidePagination
    ? table
        .getRowModel()
        .rows.slice(
          pagination.pageIndex * pagination.pageSize,
          (pagination.pageIndex + 1) * pagination.pageSize,
        )
    : table.getRowModel().rows;

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
            {showSearch &&
              (useClientSearch ? (
                <ClientSideSearch
                  value={clientSearchTerm}
                  onChange={setClientSearchTerm}
                />
              ) : (
                <DataTableSearch />
              ))}
          </div>
          {(metadata || clientSidePagination) && (
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
          {paginatedRows?.length ? (
            paginatedRows.map((row) => (
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
      {metadata && !clientSidePagination && (
        <DataTablePagination
          metadata={metadata}
          disableScroll={disableScroll}
        />
      )}
      {clientSidePagination && data.length > 0 && (
        <DataTableClientPagination
          currentPage={pagination.pageIndex + 1}
          totalPages={totalPages}
          pageSize={pagination.pageSize}
          onPageChange={(page) =>
            setPagination((prev: PaginationState) => ({
              ...prev,
              pageIndex: page - 1,
            }))
          }
          onPageSizeChange={(size) =>
            setPagination({ pageIndex: 0, pageSize: size })
          }
        />
      )}
    </div>
  );
}
