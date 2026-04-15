"use client";

import { ColumnDef } from "@tanstack/react-table";
import { Check, Minus } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

import {
  RadioGroup,
  RadioGroupItem,
} from "@/components/shadcn/radio-group/radio-group";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { DateWithTime } from "@/components/ui/entities/date-with-time";
import { EntityInfo } from "@/components/ui/entities/entity-info";
import { DataTable, DataTableColumnHeader } from "@/components/ui/table";
import { formatDuration } from "@/lib/date-utils";
import { cn } from "@/lib/utils";
import type { MetaDataProps, ProviderType } from "@/types";
import type { AttackPathScan } from "@/types/attack-paths";
import { SCAN_STATES } from "@/types/attack-paths";

import { ScanStatusBadge } from "./scan-status-badge";

interface ScanListTableProps {
  scans: AttackPathScan[];
}

const DEFAULT_PAGE_SIZE = 5;
const PAGE_SIZE_OPTIONS = [2, 5, 10, 15];
const parsePageParam = (value: string | null, fallback: number) => {
  if (!value) return fallback;

  const parsedValue = Number.parseInt(value, 10);
  return Number.isNaN(parsedValue) || parsedValue < 1 ? fallback : parsedValue;
};

const formatNullableDuration = (duration: number | null) => {
  if (!duration) return "-";
  return formatDuration(duration);
};

const getDisabledTooltip = (scan: AttackPathScan): string | null => {
  if (scan.attributes.graph_data_ready) {
    return null;
  }

  if (scan.attributes.state === SCAN_STATES.SCHEDULED) {
    return "Graph will be available once this scan runs and completes.";
  }

  if (scan.attributes.state === SCAN_STATES.AVAILABLE) {
    return "This scan is queued. Graph will be available once it completes.";
  }

  if (scan.attributes.state === SCAN_STATES.EXECUTING) {
    return "Scan is running. Graph will be available once it completes.";
  }

  if (scan.attributes.state === SCAN_STATES.FAILED) {
    return "This scan failed. No graph data is available.";
  }

  if (scan.attributes.state === SCAN_STATES.COMPLETED) {
    return "This scan completed without producing graph data.";
  }

  return "Graph data is not available for this scan.";
};

const getSelectedRowSelection = (
  scans: AttackPathScan[],
  selectedScanId: string | null,
) => {
  const selectedIndex = scans.findIndex((scan) => scan.id === selectedScanId);

  if (selectedIndex === -1) {
    return {};
  }

  return { [selectedIndex]: true };
};

const buildMetadata = (
  totalEntries: number,
  currentPage: number,
  totalPages: number,
): MetaDataProps => ({
  pagination: {
    page: currentPage,
    pages: totalPages,
    count: totalEntries,
    itemsPerPage: PAGE_SIZE_OPTIONS,
  },
  version: "1",
});

const getColumns = ({
  selectedScanId,
}: {
  selectedScanId: string | null;
}): ColumnDef<AttackPathScan>[] => [
  {
    id: "select",
    header: () => <span className="text-sm font-medium">Select</span>,
    cell: ({ row }) => {
      const isSelected = selectedScanId === row.original.id;
      const canSelect = row.original.attributes.graph_data_ready;
      const tooltip = getDisabledTooltip(row.original);

      const radio = (
        <RadioGroupItem
          value={row.original.id}
          checked={isSelected}
          disabled={!canSelect}
          className={cn(
            "size-5",
            canSelect &&
              !isSelected &&
              "border-text-neutral-secondary cursor-pointer",
            !canSelect && "disabled:opacity-70",
          )}
          aria-label={
            isSelected
              ? "Selected scan"
              : canSelect
                ? "Select scan"
                : "Scan not available"
          }
        />
      );

      if (!canSelect && !isSelected && tooltip) {
        return (
          <Tooltip>
            <TooltipTrigger asChild>
              <span tabIndex={0}>{radio}</span>
            </TooltipTrigger>
            <TooltipContent>{tooltip}</TooltipContent>
          </Tooltip>
        );
      }

      return radio;
    },
    enableSorting: false,
  },
  {
    accessorKey: "provider",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Account" />
    ),
    cell: ({ row }) => (
      <EntityInfo
        cloudProvider={row.original.attributes.provider_type as ProviderType}
        entityAlias={row.original.attributes.provider_alias}
        entityId={row.original.attributes.provider_uid}
      />
    ),
    enableSorting: false,
  },
  {
    accessorKey: "completed_at",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Last Scan Date" />
    ),
    cell: ({ row }) =>
      row.original.attributes.completed_at ? (
        <DateWithTime inline dateTime={row.original.attributes.completed_at} />
      ) : (
        "-"
      ),
    enableSorting: false,
  },
  {
    accessorKey: "state",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Status" />
    ),
    cell: ({ row }) => (
      <div className="flex">
        <ScanStatusBadge
          status={row.original.attributes.state}
          progress={row.original.attributes.progress}
        />
      </div>
    ),
    enableSorting: false,
  },
  {
    accessorKey: "graph_data_ready",
    header: () => <span className="text-sm font-medium">Graph</span>,
    cell: ({ row }) =>
      row.original.attributes.graph_data_ready ? (
        <Check
          size={16}
          aria-label="Graph available"
          className="text-text-success-primary"
        />
      ) : (
        <Minus
          size={16}
          aria-label="Graph not available"
          className="text-text-neutral-secondary"
        />
      ),
    enableSorting: false,
  },
  {
    accessorKey: "duration",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Duration" />
    ),
    cell: ({ row }) => (
      <span className="text-sm">
        {formatNullableDuration(row.original.attributes.duration)}
      </span>
    ),
    enableSorting: false,
  },
];

/**
 * Table displaying AWS account Attack Paths scans
 * Shows scan metadata and allows selection of completed scans
 */
export const ScanListTable = ({ scans }: ScanListTableProps) => {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const router = useRouter();

  const selectedScanId = searchParams.get("scanId");
  const pageSize = parsePageParam(
    searchParams.get("scanPageSize"),
    DEFAULT_PAGE_SIZE,
  );
  const requestedPage = parsePageParam(searchParams.get("scanPage"), 1);
  const totalPages = Math.max(1, Math.ceil(scans.length / pageSize));
  const currentPage = Math.min(requestedPage, totalPages);
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = startIndex + pageSize;
  const paginatedScans = scans.slice(startIndex, endIndex);

  const pushWithParams = (nextParams: Record<string, string>) => {
    const params = new URLSearchParams(searchParams.toString());

    for (const [key, value] of Object.entries(nextParams)) {
      params.set(key, value);
    }

    router.push(`${pathname}?${params.toString()}`);
  };

  const handleSelectScan = (scanId: string) => {
    pushWithParams({ scanId });
  };

  const handlePageChange = (page: number) => {
    pushWithParams({ scanPage: page.toString() });
  };

  const handlePageSizeChange = (nextPageSize: number) => {
    pushWithParams({
      scanPage: "1",
      scanPageSize: nextPageSize.toString(),
    });
  };

  return (
    <RadioGroup
      value={selectedScanId ?? ""}
      onValueChange={handleSelectScan}
      className="gap-0"
    >
      <DataTable
        columns={getColumns({ selectedScanId })}
        data={paginatedScans}
        metadata={buildMetadata(scans.length, currentPage, totalPages)}
        controlledPage={currentPage}
        controlledPageSize={pageSize}
        onPageChange={handlePageChange}
        onPageSizeChange={handlePageSizeChange}
        onRowClick={(row) => {
          if (row.original.attributes.graph_data_ready) {
            handleSelectScan(row.original.id);
          }
        }}
        enableRowSelection
        rowSelection={getSelectedRowSelection(paginatedScans, selectedScanId)}
      />
    </RadioGroup>
  );
};
