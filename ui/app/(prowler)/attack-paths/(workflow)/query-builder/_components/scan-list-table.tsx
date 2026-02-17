"use client";

import {
  ChevronLeftIcon,
  ChevronRightIcon,
  DoubleArrowLeftIcon,
  DoubleArrowRightIcon,
} from "@radix-ui/react-icons";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/shadcn/button/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { DateWithTime } from "@/components/ui/entities/date-with-time";
import { EntityInfo } from "@/components/ui/entities/entity-info";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import type { ProviderType } from "@/types";
import type { AttackPathScan, ScanState } from "@/types/attack-paths";
import { SCAN_STATES } from "@/types/attack-paths";

import { ScanStatusBadge } from "./scan-status-badge";

interface ScanListTableProps {
  scans: AttackPathScan[];
}

const TABLE_COLUMN_COUNT = 6;
const DEFAULT_PAGE_SIZE = 5;
const PAGE_SIZE_OPTIONS = [2, 5, 10, 15];
const WAITING_STATES: readonly ScanState[] = [
  SCAN_STATES.SCHEDULED,
  SCAN_STATES.AVAILABLE,
  SCAN_STATES.EXECUTING,
];

const baseLinkClass =
  "relative block rounded border-0 bg-transparent px-3 py-1.5 text-button-primary outline-none transition-all duration-300 hover:bg-bg-neutral-tertiary hover:text-text-neutral-primary focus:shadow-none dark:hover:bg-bg-neutral-secondary dark:hover:text-text-neutral-primary";

const disabledLinkClass =
  "text-border-neutral-secondary dark:text-border-neutral-secondary hover:bg-transparent hover:text-border-neutral-secondary dark:hover:text-border-neutral-secondary cursor-default pointer-events-none";

/**
 * Table displaying AWS account Attack Paths scans
 * Shows scan metadata and allows selection of completed scans
 */
export const ScanListTable = ({ scans }: ScanListTableProps) => {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const router = useRouter();

  const selectedScanId = searchParams.get("scanId");
  const currentPage = parseInt(searchParams.get("scanPage") ?? "1");
  const pageSize = parseInt(
    searchParams.get("scanPageSize") ?? String(DEFAULT_PAGE_SIZE),
  );
  const [selectedPageSize, setSelectedPageSize] = useState(String(pageSize));

  const totalPages = Math.ceil(scans.length / pageSize);
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = startIndex + pageSize;
  const paginatedScans = scans.slice(startIndex, endIndex);

  const handleSelectScan = (scanId: string) => {
    const params = new URLSearchParams(searchParams);
    params.set("scanId", scanId);
    router.push(`${pathname}?${params.toString()}`);
  };

  const isSelectDisabled = (scan: AttackPathScan) => {
    return !scan.attributes.graph_data_ready || selectedScanId === scan.id;
  };

  const getSelectButtonLabel = (scan: AttackPathScan) => {
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

  const createPageUrl = (pageNumber: number | string) => {
    const params = new URLSearchParams(searchParams);

    // Preserve scanId if it exists
    const scanId = searchParams.get("scanId");

    if (+pageNumber > totalPages) {
      return `${pathname}?${params.toString()}`;
    }

    params.set("scanPage", pageNumber.toString());

    // Ensure that scanId is preserved
    if (scanId) params.set("scanId", scanId);

    return `${pathname}?${params.toString()}`;
  };

  const isFirstPage = currentPage === 1;
  const isLastPage = currentPage === totalPages;

  return (
    <>
      <div className="minimal-scrollbar rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary relative z-0 flex w-full flex-col gap-4 overflow-auto border p-4">
        <Table aria-label="Attack Paths scans table listing provider accounts, scan dates, status, progress, and duration">
          <TableHeader>
            <TableRow>
              <TableHead>Provider / Account</TableHead>
              <TableHead>Last Scan Date</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Progress</TableHead>
              <TableHead>Duration</TableHead>
              <TableHead className="text-right">Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {scans.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={TABLE_COLUMN_COUNT}
                  className="h-24 text-center"
                >
                  No Attack Paths scans available.
                </TableCell>
              </TableRow>
            ) : (
              paginatedScans.map((scan) => {
                const isDisabled = isSelectDisabled(scan);
                const isSelected = selectedScanId === scan.id;
                const duration = scan.attributes.duration
                  ? `${Math.floor(scan.attributes.duration / 60)}m ${scan.attributes.duration % 60}s`
                  : "-";

                return (
                  <TableRow
                    key={scan.id}
                    className={
                      isSelected
                        ? "bg-button-primary/10 dark:bg-button-primary/10"
                        : ""
                    }
                  >
                    <TableCell className="font-medium">
                      <EntityInfo
                        cloudProvider={
                          scan.attributes.provider_type as ProviderType
                        }
                        entityAlias={scan.attributes.provider_alias}
                        entityId={scan.attributes.provider_uid}
                      />
                    </TableCell>
                    <TableCell>
                      {scan.attributes.completed_at ? (
                        <DateWithTime
                          inline
                          dateTime={scan.attributes.completed_at}
                        />
                      ) : (
                        "-"
                      )}
                    </TableCell>
                    <TableCell>
                      <ScanStatusBadge
                        status={scan.attributes.state}
                        progress={scan.attributes.progress}
                        graphDataReady={scan.attributes.graph_data_ready}
                      />
                    </TableCell>
                    <TableCell>
                      <span className="text-sm">
                        {scan.attributes.progress}%
                      </span>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm">{duration}</span>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        type="button"
                        aria-label="Select scan"
                        disabled={isDisabled}
                        variant={isDisabled ? "secondary" : "default"}
                        onClick={() => handleSelectScan(scan.id)}
                        className="w-full max-w-24"
                      >
                        {getSelectButtonLabel(scan)}
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>

        {/* Pagination Controls */}
        {scans.length > 0 && (
          <div className="flex w-full flex-col-reverse items-center justify-between gap-4 overflow-auto p-1 sm:flex-row sm:gap-8">
            <div className="text-sm whitespace-nowrap">
              {scans.length} scans in total
            </div>
            {scans.length > DEFAULT_PAGE_SIZE && (
              <div className="flex flex-col-reverse items-center gap-4 sm:flex-row sm:gap-6 lg:gap-8">
                {/* Rows per page selector */}
                <div className="flex items-center gap-2">
                  <p className="text-sm font-medium whitespace-nowrap">
                    Rows per page
                  </p>
                  <Select
                    value={selectedPageSize}
                    onValueChange={(value) => {
                      setSelectedPageSize(value);

                      const params = new URLSearchParams(searchParams);

                      // Preserve scanId if it exists
                      const scanId = searchParams.get("scanId");

                      params.set("scanPageSize", value);
                      params.set("scanPage", "1");

                      // Ensure that scanId is preserved
                      if (scanId) params.set("scanId", scanId);

                      router.push(`${pathname}?${params.toString()}`);
                    }}
                  >
                    <SelectTrigger className="h-8 w-18">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent side="top">
                      {PAGE_SIZE_OPTIONS.map((size) => (
                        <SelectItem
                          key={size}
                          value={`${size}`}
                          className="cursor-pointer"
                        >
                          {size}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex items-center justify-center text-sm font-medium">
                  Page {currentPage} of {totalPages}
                </div>
                <div className="flex items-center gap-2">
                  <Link
                    aria-label="Go to first page"
                    className={cn(
                      baseLinkClass,
                      isFirstPage && disabledLinkClass,
                    )}
                    href={
                      isFirstPage
                        ? pathname + "?" + searchParams.toString()
                        : createPageUrl(1)
                    }
                    aria-disabled={isFirstPage}
                    onClick={(e) => isFirstPage && e.preventDefault()}
                  >
                    <DoubleArrowLeftIcon
                      className="size-4"
                      aria-hidden="true"
                    />
                  </Link>
                  <Link
                    aria-label="Go to previous page"
                    className={cn(
                      baseLinkClass,
                      isFirstPage && disabledLinkClass,
                    )}
                    href={
                      isFirstPage
                        ? pathname + "?" + searchParams.toString()
                        : createPageUrl(currentPage - 1)
                    }
                    aria-disabled={isFirstPage}
                    onClick={(e) => isFirstPage && e.preventDefault()}
                  >
                    <ChevronLeftIcon className="size-4" aria-hidden="true" />
                  </Link>
                  <Link
                    aria-label="Go to next page"
                    className={cn(
                      baseLinkClass,
                      isLastPage && disabledLinkClass,
                    )}
                    href={
                      isLastPage
                        ? pathname + "?" + searchParams.toString()
                        : createPageUrl(currentPage + 1)
                    }
                    aria-disabled={isLastPage}
                    onClick={(e) => isLastPage && e.preventDefault()}
                  >
                    <ChevronRightIcon className="size-4" aria-hidden="true" />
                  </Link>
                  <Link
                    aria-label="Go to last page"
                    className={cn(
                      baseLinkClass,
                      isLastPage && disabledLinkClass,
                    )}
                    href={
                      isLastPage
                        ? pathname + "?" + searchParams.toString()
                        : createPageUrl(totalPages)
                    }
                    aria-disabled={isLastPage}
                    onClick={(e) => isLastPage && e.preventDefault()}
                  >
                    <DoubleArrowRightIcon
                      className="size-4"
                      aria-hidden="true"
                    />
                  </Link>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
      <p className="text-text-neutral-secondary dark:text-text-neutral-secondary mt-6 text-xs">
        Scans can be selected when data is available. A new scan does not
        interrupt access to existing data.
      </p>
    </>
  );
};
