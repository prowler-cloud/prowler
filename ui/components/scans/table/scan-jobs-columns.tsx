"use client";

import type { ColumnDef } from "@tanstack/react-table";

import { DateWithTime } from "@/components/ui/entities";
import { DataTableColumnHeader } from "@/components/ui/table";
import { StatusBadge } from "@/components/ui/table/status-badge";
import { formatLocalTimeWithZone } from "@/lib/date-utils";
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

const getScanScheduleColumn = (title: string): ColumnDef<ScanProps> => ({
  id: "scanSchedule",
  accessorFn: (row) => row.attributes.trigger,
  header: ({ column }) => (
    <DataTableColumnHeader column={column} title={title} param="trigger" />
  ),
  cell: ({ row }) => <ScheduleCell scan={row.original} />,
});

const getScheduleSummary = (scan: ScanProps) =>
  scan.pendingSchedule ?? scan.providerSchedule;

const scheduledScanScheduleColumn: ColumnDef<ScanProps> = {
  id: "scanSchedule",
  accessorFn: (row) => row.attributes.scheduled_at,
  header: ({ column }) => (
    <DataTableColumnHeader column={column} title="Schedule" />
  ),
  // Two lines mirroring DateWithTime: cadence on top, local fire time underneath.
  cell: ({ row }) => {
    const schedule = getScheduleSummary(row.original);
    if (!schedule) return <span>-</span>;

    const fireTime = formatLocalTimeWithZone(
      row.original.attributes.scheduled_at,
    );

    return (
      <div className="flex flex-col gap-1">
        <span className="text-text-neutral-primary text-sm whitespace-nowrap">
          {schedule.cadence ?? schedule.summary}
        </span>
        {fireTime && (
          <span className="text-text-neutral-tertiary text-xs font-medium whitespace-nowrap">
            {fireTime}
          </span>
        )}
      </div>
    );
  },
  enableSorting: false,
};

const nextScanColumn: ColumnDef<ScanProps> = {
  id: "nextScan",
  header: ({ column }) => (
    <DataTableColumnHeader column={column} title="Next Scan" />
  ),
  // Real rows carry their fire time in scheduled_at; pending rows are
  // synthesized with the server-computed next_scan_at in the same field.
  cell: ({ row }) => (
    <DateWithTime dateTime={row.original.attributes.scheduled_at} showTime />
  ),
  enableSorting: false,
};

const lastScanColumn: ColumnDef<ScanProps> = {
  id: "lastScan",
  header: ({ column }) => (
    <DataTableColumnHeader column={column} title="Last Scan" />
  ),
  cell: ({ row }) => (
    <DateWithTime
      dateTime={getScheduleSummary(row.original)?.lastScanAt ?? null}
      showTime
    />
  ),
  enableSorting: false,
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
  getScanScheduleColumn("Schedule"),
  {
    id: "launched",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Launched" />
    ),
    cell: ({ row }) => (
      <DateWithTime
        dateTime={
          row.original.attributes.started_at ||
          row.original.attributes.inserted_at
        }
      />
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
  getScanScheduleColumn("Type"),
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
  scheduledScanScheduleColumn,
  nextScanColumn,
  lastScanColumn,
  actionsColumn,
];

export function getScanJobsColumns(
  options: GetScanJobsColumnsOptions,
): ColumnDef<ScanProps>[] {
  if (options.tab === SCAN_JOBS_TAB.SCHEDULED) return scheduledColumns();
  if (options.tab === SCAN_JOBS_TAB.ACTIVE) return activeColumns();
  return completedColumns();
}
