"use client";

import type { ColumnDef } from "@tanstack/react-table";

import { DateWithTime } from "@/components/ui/entities";
import { DataTableColumnHeader } from "@/components/ui/table";
import { StatusBadge } from "@/components/ui/table/status-badge";
import { SCAN_JOBS_TAB, type ScanJobsTab, type ScanProps } from "@/types";

import { formatScanDuration } from "../scans.utils";
import {
  AccountCell,
  ProgressCell,
  ResourceCountCell,
  ScanInfoCell,
  ScheduleCell,
} from "./cells";
import { ScanJobsRowActions } from "./scan-jobs-row-actions";

interface GetScanJobsColumnsOptions {
  tab: ScanJobsTab;
}

const accountColumn: ColumnDef<ScanProps> = {
  id: "account",
  header: ({ column }) => (
    <DataTableColumnHeader column={column} title="Provider" />
  ),
  cell: ({ row }) => <AccountCell scan={row.original} />,
  enableSorting: false,
};

const scanInfoColumn: ColumnDef<ScanProps> = {
  id: "scanInfo",
  accessorFn: (row) => row.attributes.name,
  header: ({ column }) => (
    <DataTableColumnHeader column={column} title="Info" param="name" />
  ),
  cell: ({ row }) => <ScanInfoCell scan={row.original} />,
};

const scanScheduleColumn: ColumnDef<ScanProps> = {
  id: "scanSchedule",
  accessorFn: (row) => row.attributes.trigger,
  header: ({ column }) => (
    <DataTableColumnHeader column={column} title="Schedule" param="trigger" />
  ),
  cell: ({ row }) => <ScheduleCell scan={row.original} />,
};

const resourcesColumn: ColumnDef<ScanProps> = {
  id: "resources",
  header: ({ column }) => (
    <DataTableColumnHeader column={column} title="Resources" />
  ),
  cell: ({ row }) => (
    <ResourceCountCell count={row.original.attributes.unique_resource_count} />
  ),
  enableSorting: false,
};

const actionsColumn: ColumnDef<ScanProps> = {
  id: "actions",
  header: ({ column }) => <DataTableColumnHeader column={column} title="" />,
  cell: ({ row }) => <ScanJobsRowActions scan={row.original} />,
  enableSorting: false,
};

const durationColumn: ColumnDef<ScanProps> = {
  id: "duration",
  header: ({ column }) => (
    <DataTableColumnHeader column={column} title="Duration" />
  ),
  cell: ({ row }) => formatScanDuration(row.original.attributes.duration),
  enableSorting: false,
};

const activeColumns = (): ColumnDef<ScanProps>[] => [
  accountColumn,
  scanInfoColumn,
  {
    id: "progress",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Progress" />
    ),
    cell: ({ row }) => <ProgressCell scan={row.original} />,
    enableSorting: false,
  },
  scanScheduleColumn,
  {
    id: "launched",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Launched" />
    ),
    cell: ({ row }) => (
      <DateWithTime dateTime={row.original.attributes.started_at} />
    ),
    enableSorting: false,
  },
  actionsColumn,
];

const completedColumns = (): ColumnDef<ScanProps>[] => [
  accountColumn,
  scanInfoColumn,
  resourcesColumn,
  durationColumn,
  {
    id: "status",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Status" />
    ),
    cell: ({ row }) => <StatusBadge status={row.original.attributes.state} />,
    enableSorting: false,
  },
  scanScheduleColumn,
  {
    id: "scanDate",
    accessorFn: (row) => row.attributes.completed_at,
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title="Completed"
        param="updated_at"
      />
    ),
    cell: ({ row }) => (
      <DateWithTime dateTime={row.original.attributes.completed_at} />
    ),
  },
  actionsColumn,
];

const scheduledColumns = (): ColumnDef<ScanProps>[] => [
  accountColumn,
  scanInfoColumn,
  scanScheduleColumn,
  /*
   * TODO: Restore this column when the API exposes the last completed scan date for this schedule.
   * {
   *   id: "lastScan",
   *   header: ({ column }) => (
   *     <DataTableColumnHeader column={column} title="Last Run" />
   *   ),
   *   cell: ({ row }) => (
   *     <DateWithTime dateTime={row.original.attributes.completed_at} />
   *   ),
   *   enableSorting: false,
   * },
   */
  {
    id: "nextScan",
    accessorFn: (row) =>
      row.attributes.next_scan_at || row.attributes.scheduled_at,
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title="Next Run"
        param="scheduled_at"
      />
    ),
    cell: ({ row }) => (
      <DateWithTime
        dateTime={
          row.original.attributes.next_scan_at ||
          row.original.attributes.scheduled_at
        }
      />
    ),
  },
  actionsColumn,
];

export function getScanJobsColumns(
  options: GetScanJobsColumnsOptions,
): ColumnDef<ScanProps>[] {
  if (options.tab === SCAN_JOBS_TAB.SCHEDULED) return scheduledColumns();
  if (options.tab === SCAN_JOBS_TAB.ACTIVE) return activeColumns();
  return completedColumns();
}
