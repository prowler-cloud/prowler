"use client";

import { ColumnDef } from "@tanstack/react-table";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

import { Button } from "@/components/shadcn/button/button";
import { DateWithTime } from "@/components/ui/entities/date-with-time";
import { EntityInfo } from "@/components/ui/entities/entity-info";
import { DataTable, DataTableColumnHeader } from "@/components/ui/table";
import { formatDuration } from "@/lib/date-utils";
import type { MetaDataProps, ProviderType } from "@/types";
import type { AttackPathScan, ScanState } from "@/types/attack-paths";
import { SCAN_STATES } from "@/types/attack-paths";

import { ScanStatusBadge } from "./scan-status-badge";

interface ScanListTableProps {
  scans: AttackPathScan[];
}

const DEFAULT_PAGE_SIZE = 5;
const PAGE_SIZE_OPTIONS = [2, 5, 10, 15];
const WAITING_STATES: readonly ScanState[] = [
  SCAN_STATES.SCHEDULED,
  SCAN_STATES.AVAILABLE,
  SCAN_STATES.EXECUTING,
];

const parsePageParam = (value: string | null, fallback: number) => {
  if (!value) return fallback;

  const parsedValue = Number.parseInt(value, 10);
  return Number.isNaN(parsedValue) || parsedValue < 1 ? fallback : parsedValue;
};

const formatNullableDuration = (duration: number | null) => {
  if (!duration) return "-";
  return formatDuration(duration);
};

const isSelectDisabled = (
  scan: AttackPathScan,
  selectedScanId: string | null,
) => {
  return !scan.attributes.graph_data_ready || selectedScanId === scan.id;
};

const getSelectButtonLabel = (
  scan: AttackPathScan,
  selectedScanId: string | null,
) => {
  if (selectedScanId === scan.id) {
    return "Selected";
  }

  if (scan.attributes.graph_data_ready) {
    return "Select";
  }

  if (WAITING_STATES.includes(scan.attributes.state)) {
    return "Waiting...";
  }

  if (scan.attributes.state === SCAN_STATES.FAILED) {
    return "Failed";
  }

  return "Select";
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
  onSelectScan,
}: {
  selectedScanId: string | null;
  onSelectScan: (scanId: string) => void;
}): ColumnDef<AttackPathScan>[] => [
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
      <ScanStatusBadge
        status={row.original.attributes.state}
        progress={row.original.attributes.progress}
        graphDataReady={row.original.attributes.graph_data_ready}
      />
    ),
    enableSorting: false,
  },
  {
    accessorKey: "progress",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Progress" />
    ),
    cell: ({ row }) => (
      <span className="text-sm">{row.original.attributes.progress}%</span>
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
  {
    id: "actions",
    header: () => <span className="sr-only">Actions</span>,
    cell: ({ row }) => {
      const isDisabled = isSelectDisabled(row.original, selectedScanId);

      return (
        <div className="flex justify-end">
          <Button
            type="button"
            aria-label="Select scan"
            disabled={isDisabled}
            variant={isDisabled ? "secondary" : "default"}
            onClick={() => onSelectScan(row.original.id)}
            className="w-full max-w-24"
          >
            {getSelectButtonLabel(row.original, selectedScanId)}
          </Button>
        </div>
      );
    },
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
    <DataTable
      columns={getColumns({
        selectedScanId,
        onSelectScan: handleSelectScan,
      })}
      data={paginatedScans}
      metadata={buildMetadata(scans.length, currentPage, totalPages)}
      controlledPage={currentPage}
      controlledPageSize={pageSize}
      onPageChange={handlePageChange}
      onPageSizeChange={handlePageSizeChange}
      enableRowSelection
      rowSelection={getSelectedRowSelection(paginatedScans, selectedScanId)}
    />
  );
};
