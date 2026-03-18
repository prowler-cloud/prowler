"use client";

import {
  flexRender,
  getCoreRowModel,
  Row,
  RowSelectionState,
  useReactTable,
} from "@tanstack/react-table";
import { ChevronLeft, Loader2 } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useMemo, useState } from "react";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge, StatusFindingBadge } from "@/components/ui/table";
import { useInfiniteResources } from "@/hooks/use-infinite-resources";
import { cn, hasDateOrScanFilter } from "@/lib";
import { FindingGroupRow, FindingResourceRow } from "@/types";

import { FloatingMuteButton } from "../floating-mute-button";
import { getColumnFindingResources } from "./column-finding-resources";
import { FindingsSelectionContext } from "./findings-selection-context";
import { ImpactedResourcesCell } from "./impacted-resources-cell";
import { DeltaValues, NotificationIndicator } from "./notification-indicator";

interface FindingsGroupDrillDownProps {
  group: FindingGroupRow;
  onCollapse: () => void;
}

export function FindingsGroupDrillDown({
  group,
  onCollapse,
}: FindingsGroupDrillDownProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [resources, setResources] = useState<FindingResourceRow[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Derive hasDateOrScan from current URL params
  const currentParams = useMemo(
    () => Object.fromEntries(searchParams.entries()),
    [searchParams],
  );
  const hasDateOrScan = hasDateOrScanFilter(currentParams);

  // Stabilize filters object — only recompute when searchParams change
  const filters = useMemo(() => {
    const result: Record<string, string> = {};
    searchParams.forEach((value, key) => {
      if (key.startsWith("filter[") || key.includes("__in")) {
        result[key] = value;
      }
    });
    return result;
  }, [searchParams]);

  const handleSetResources = useCallback(
    (newResources: FindingResourceRow[], _hasMore: boolean) => {
      setResources(newResources);
      setIsLoading(false);
    },
    [],
  );

  const handleAppendResources = useCallback(
    (newResources: FindingResourceRow[], _hasMore: boolean) => {
      setResources((prev) => [...prev, ...newResources]);
      setIsLoading(false);
    },
    [],
  );

  const handleSetLoading = useCallback((loading: boolean) => {
    setIsLoading(loading);
  }, []);

  const { sentinelRef } = useInfiniteResources({
    checkId: group.checkId,
    hasDateOrScanFilter: hasDateOrScan,
    filters,
    onSetResources: handleSetResources,
    onAppendResources: handleAppendResources,
    onSetLoading: handleSetLoading,
  });

  // Selection logic for resources
  const selectedFindingIds = Object.keys(rowSelection)
    .filter((key) => rowSelection[key])
    .map((idx) => resources[parseInt(idx)]?.findingId)
    .filter(Boolean);

  const selectableRowCount = resources.filter((r) => !r.isMuted).length;

  const getRowCanSelect = (row: Row<FindingResourceRow>): boolean => {
    return !row.original.isMuted;
  };

  const clearSelection = () => {
    setRowSelection({});
  };

  const isSelected = (id: string) => {
    return selectedFindingIds.includes(id);
  };

  const handleMuteComplete = () => {
    clearSelection();
    router.refresh();
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
    onRowSelectionChange: setRowSelection,
    manualPagination: true,
    state: {
      rowSelection,
    },
  });

  // Delta for the sticky header
  const delta =
    group.newCount > 0
      ? DeltaValues.NEW
      : group.changedCount > 0
        ? DeltaValues.CHANGED
        : DeltaValues.NONE;

  const allMuted =
    group.mutedCount > 0 && group.mutedCount === group.resourcesTotal;

  const rows = table.getRowModel().rows;

  return (
    <FindingsSelectionContext.Provider
      value={{
        selectedFindingIds,
        selectedFindings: [],
        clearSelection,
        isSelected,
      }}
    >
      <div
        className={cn(
          "minimal-scrollbar rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary",
          "flex w-full flex-col overflow-auto border",
        )}
      >
        {/* Sticky header — expanded finding group summary */}
        <div className="bg-bg-neutral-secondary border-border-neutral-secondary sticky top-0 z-10 border-b p-4">
          <div className="flex items-center gap-3">
            {/* Back button */}
            <button
              type="button"
              aria-label="Collapse and go back to findings"
              className="hover:bg-bg-neutral-tertiary flex size-8 items-center justify-center rounded-md transition-colors"
              onClick={onCollapse}
            >
              <ChevronLeft className="text-text-neutral-secondary size-5" />
            </button>

            {/* Notification indicator */}
            <NotificationIndicator delta={delta} isMuted={allMuted} />

            {/* Status badge */}
            <StatusFindingBadge status={group.status} />

            {/* Finding title */}
            <div className="min-w-0 flex-1">
              <p className="text-text-neutral-primary truncate text-sm font-medium">
                {group.checkTitle}
              </p>
            </div>

            {/* Severity */}
            <SeverityBadge severity={group.severity} />

            {/* Impacted resources count */}
            <ImpactedResourcesCell
              impacted={group.resourcesFail}
              total={group.resourcesTotal}
            />
          </div>
        </div>

        {/* Resources table */}
        <div className="p-4 pt-0">
          <Table>
            <TableHeader>
              {table.getHeaderGroups().map((headerGroup) => (
                <TableRow key={headerGroup.id}>
                  {headerGroup.headers.map((header) => (
                    <TableHead key={header.id}>
                      {header.isPlaceholder
                        ? null
                        : flexRender(
                            header.column.columnDef.header,
                            header.getContext(),
                          )}
                    </TableHead>
                  ))}
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
                        {flexRender(
                          cell.column.columnDef.cell,
                          cell.getContext(),
                        )}
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              ) : !isLoading ? (
                <TableRow>
                  <TableCell
                    colSpan={columns.length}
                    className="h-24 text-center"
                  >
                    No resources found.
                  </TableCell>
                </TableRow>
              ) : null}
            </TableBody>
          </Table>

          {/* Loading indicator */}
          {isLoading && (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="text-text-neutral-tertiary size-6 animate-spin" />
            </div>
          )}

          {/* Sentinel for infinite scroll */}
          <div ref={sentinelRef} className="h-1" />
        </div>
      </div>

      {selectedFindingIds.length > 0 && (
        <FloatingMuteButton
          selectedCount={selectedFindingIds.length}
          selectedFindingIds={selectedFindingIds}
          onComplete={handleMuteComplete}
        />
      )}
    </FindingsSelectionContext.Provider>
  );
}
