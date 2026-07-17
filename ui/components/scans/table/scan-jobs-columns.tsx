"use client";

import type { ColumnDef } from "@tanstack/react-table";

import { StackedCell } from "@/components/shadcn";
import { DataTableColumnHeader } from "@/components/shadcn/table";
import { StatusBadge } from "@/components/shadcn/table/status-badge";
import { formatLocalDate, formatLocalTimeWithZone } from "@/lib/date-utils";
import { SCAN_JOBS_TAB, type ScanJobsTab, type ScanProps } from "@/types";
import type { ScanScheduleCapability } from "@/types/schedules";

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
  capability?: ScanScheduleCapability;
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

const renderDateCell = (value: string | null) => {
  const date = formatLocalDate(value);
  if (!date) return <span>-</span>;

  return (
    <StackedCell primary={date} secondary={formatLocalTimeWithZone(value)} />
  );
};

const scheduledScanScheduleColumn: ColumnDef<ScanProps> = {
  id: "scanSchedule",
  accessorFn: (row) => row.attributes.scheduled_at,
  header: ({ column }) => (
    <DataTableColumnHeader column={column} title="Schedule" />
  ),
  // Cadence on top, local fire time underneath.
  cell: ({ row }) => {
    const schedule = getScheduleSummary(row.original);
    if (!schedule) return <span>-</span>;

    return (
      <StackedCell
        primary={schedule.cadence ?? schedule.summary}
        secondary={formatLocalTimeWithZone(
          row.original.attributes.scheduled_at,
        )}
      />
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
  cell: ({ row }) => renderDateCell(row.original.attributes.scheduled_at),
  enableSorting: false,
};

const lastScanColumn: ColumnDef<ScanProps> = {
  id: "lastScan",
  header: ({ column }) => (
    <DataTableColumnHeader column={column} title="Last Scan" />
  ),
  cell: ({ row }) =>
    renderDateCell(getScheduleSummary(row.original)?.lastScanAt ?? null),
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

const actionsColumn = (
  tab: ScanJobsTab,
  capability?: ScanScheduleCapability,
): ColumnDef<ScanProps> => ({
  id: "actions",
  header: ({ column }) => <DataTableColumnHeader column={column} title="" />,
  cell: ({ row }) => (
    <ScanJobsRowActions scan={row.original} tab={tab} capability={capability} />
  ),
  enableSorting: false,
});

const durationColumn: ColumnDef<ScanProps> = {
  id: "duration",
  header: ({ column }) => (
    <DataTableColumnHeader column={column} title="Duration" />
  ),
  cell: ({ row }) => formatScanDuration(row.original.attributes.duration),
  enableSorting: false,
};

const activeColumns = (
  capability?: ScanScheduleCapability,
): ColumnDef<ScanProps>[] => [
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
    cell: ({ row }) =>
      renderDateCell(
        row.original.attributes.started_at ||
          row.original.attributes.inserted_at,
      ),
    enableSorting: false,
  },
  actionsColumn(SCAN_JOBS_TAB.ACTIVE, capability),
];

const completedColumns = (
  capability?: ScanScheduleCapability,
): ColumnDef<ScanProps>[] => [
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
    cell: ({ row }) => renderDateCell(row.original.attributes.completed_at),
  },
  actionsColumn(SCAN_JOBS_TAB.COMPLETED, capability),
];

const scheduledColumns = (
  capability?: ScanScheduleCapability,
): ColumnDef<ScanProps>[] => [
  accountColumn,
  scanInfoColumn,
  scheduledScanScheduleColumn,
  nextScanColumn,
  lastScanColumn,
  actionsColumn(SCAN_JOBS_TAB.SCHEDULED, capability),
];

export function getScanJobsColumns(
  options: GetScanJobsColumnsOptions,
): ColumnDef<ScanProps>[] {
  if (options.tab === SCAN_JOBS_TAB.SCHEDULED) {
    return scheduledColumns(options.capability);
  }
  if (options.tab === SCAN_JOBS_TAB.ACTIVE) {
    return activeColumns(options.capability);
  }
  return completedColumns(options.capability);
}
