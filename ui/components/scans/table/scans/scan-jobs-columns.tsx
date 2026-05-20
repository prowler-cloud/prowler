"use client";

import type { ColumnDef, RowSelectionState } from "@tanstack/react-table";
import { Bell, ShieldCheck, TriangleAlert } from "lucide-react";

import {
  Badge,
  Checkbox,
  Progress,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn";
import { DateWithTime, EntityInfo } from "@/components/ui/entities";
import { DataTableColumnHeader } from "@/components/ui/table";
import type { ProviderType, ScanProps } from "@/types";

import {
  formatScanDuration,
  getScanAlias,
  getScanFindingsSummary,
  getScanScheduleLabel,
  getScanStatusLabel,
  SCAN_JOBS_TAB,
  type ScanJobsTab,
} from "../../scans-table.utils";
import { ScanJobsRowActions } from "./scan-jobs-row-actions";

interface GetScanJobsColumnsOptions {
  tab: ScanJobsTab;
  rowSelection: RowSelectionState;
  selectableRowCount: number;
}

function SelectHeader({
  table,
  selectedCount,
  selectableRowCount,
}: {
  table: { toggleAllPageRowsSelected: (value: boolean) => void };
  selectedCount: number;
  selectableRowCount: number;
}) {
  const isAllSelected =
    selectedCount > 0 && selectedCount === selectableRowCount;
  const isSomeSelected =
    selectedCount > 0 && selectedCount < selectableRowCount;

  return (
    <Checkbox
      size="sm"
      checked={isAllSelected}
      indeterminate={isSomeSelected}
      onCheckedChange={(checked) =>
        table.toggleAllPageRowsSelected(checked === true)
      }
      onClick={(event) => event.stopPropagation()}
      aria-label="Select all scans"
      disabled={selectableRowCount === 0}
    />
  );
}

function AccountCell({ scan }: { scan: ScanProps }) {
  const providerInfo = scan.providerInfo;

  if (!providerInfo) {
    return <span className="text-text-neutral-tertiary text-sm">-</span>;
  }

  return (
    <div className="max-w-[240px] min-w-0">
      <EntityInfo
        cloudProvider={providerInfo.provider as ProviderType}
        entityAlias={providerInfo.alias}
        entityId={providerInfo.uid}
      />
    </div>
  );
}

function ScanNoteCell({ scan }: { scan: ScanProps }) {
  const scanNote = getScanAlias(scan);

  if (scanNote === "-") {
    return <span className="text-text-neutral-tertiary text-sm">-</span>;
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="text-text-neutral-primary block max-w-[180px] truncate text-sm font-medium whitespace-nowrap">
          {scanNote}
        </span>
      </TooltipTrigger>
      <TooltipContent side="top">{scanNote}</TooltipContent>
    </Tooltip>
  );
}

function ResourceCountCell({ count }: { count?: number }) {
  return (
    <Badge variant="tag" className="rounded text-sm">
      <span className="font-bold">{(count ?? 0).toLocaleString()}</span>
    </Badge>
  );
}

function ProgressCell({ scan }: { scan: ScanProps }) {
  const progress = scan.attributes.progress ?? 0;
  const isQueued = scan.attributes.state === "available";

  if (isQueued) {
    return <Badge variant="warning">Queued for scan</Badge>;
  }

  return (
    <div className="flex min-w-[220px] items-center gap-3">
      <Progress value={progress} className="h-2 min-w-[140px]" />
      <span className="text-text-neutral-secondary min-w-9 text-xs font-medium">
        {progress}%
      </span>
    </div>
  );
}

function FindingsSummaryCell({ scan }: { scan: ScanProps }) {
  const summary = getScanFindingsSummary(scan.attributes);

  if (!summary) {
    return <span className="text-text-neutral-tertiary text-sm">-</span>;
  }

  return (
    <div className="flex min-w-[160px] items-center gap-4">
      <div className="flex flex-col gap-1">
        <Badge variant="error">
          <TriangleAlert className="size-3" />
          {summary.fail.toLocaleString()}
        </Badge>
        {typeof summary.failNew === "number" && (
          <span className="text-text-neutral-secondary flex items-center gap-1 text-xs">
            <Bell className="size-3" />
            {summary.failNew.toLocaleString()} New
          </span>
        )}
      </div>
      <div className="flex flex-col gap-1">
        <Badge variant="success">
          <ShieldCheck className="size-3" />
          {summary.pass.toLocaleString()}
        </Badge>
        {typeof summary.passNew === "number" && (
          <span className="text-text-neutral-secondary flex items-center gap-1 text-xs">
            <Bell className="size-3" />
            {summary.passNew.toLocaleString()} New
          </span>
        )}
      </div>
    </div>
  );
}

function StatusCell({ scan }: { scan: ScanProps }) {
  const state = scan.attributes.state;
  const variant =
    state === "completed"
      ? "success"
      : state === "failed" || state === "cancelled"
        ? "error"
        : "tag";

  return <Badge variant={variant}>{getScanStatusLabel(state)}</Badge>;
}

function ScheduleCell({ scan }: { scan: ScanProps }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-text-neutral-primary text-sm">
        {getScanScheduleLabel(scan.attributes.trigger)}
      </span>
      {scan.attributes.scheduled_at && (
        <DateWithTime dateTime={scan.attributes.scheduled_at} showTime />
      )}
    </div>
  );
}

const selectColumn = ({
  rowSelection,
  selectableRowCount,
}: GetScanJobsColumnsOptions): ColumnDef<ScanProps> => ({
  id: "select",
  header: ({ table }) => (
    <div className="flex min-w-10">
      <SelectHeader
        table={table}
        selectedCount={Object.values(rowSelection).filter(Boolean).length}
        selectableRowCount={selectableRowCount}
      />
    </div>
  ),
  cell: ({ row }) => (
    <div className="flex min-w-10">
      <Checkbox
        size="sm"
        checked={row.getIsSelected()}
        onCheckedChange={(checked) => row.toggleSelected(checked === true)}
        onClick={(event) => event.stopPropagation()}
        aria-label="Select scan"
      />
    </div>
  ),
  enableSorting: false,
  enableHiding: false,
});

const accountColumn: ColumnDef<ScanProps> = {
  id: "account",
  header: ({ column }) => (
    <DataTableColumnHeader column={column} title="Account" />
  ),
  cell: ({ row }) => <AccountCell scan={row.original} />,
  enableSorting: false,
};

const scanNoteColumn: ColumnDef<ScanProps> = {
  id: "scanNote",
  header: ({ column }) => (
    <DataTableColumnHeader column={column} title="Scan Note" param="name" />
  ),
  cell: ({ row }) => <ScanNoteCell scan={row.original} />,
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

const activeColumns = (
  options: GetScanJobsColumnsOptions,
): ColumnDef<ScanProps>[] => [
  selectColumn(options),
  accountColumn,
  scanNoteColumn,
  {
    id: "progress",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Progress" />
    ),
    cell: ({ row }) => <ProgressCell scan={row.original} />,
    enableSorting: false,
  },
  {
    id: "scanTime",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Scan Time" />
    ),
    cell: ({ row }) => formatScanDuration(row.original.attributes.duration),
    enableSorting: false,
  },
  {
    id: "scanSchedule",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Scan Schedule" />
    ),
    cell: ({ row }) => <ScheduleCell scan={row.original} />,
    enableSorting: false,
  },
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

const completedColumns = (
  options: GetScanJobsColumnsOptions,
): ColumnDef<ScanProps>[] => [
  selectColumn(options),
  accountColumn,
  scanNoteColumn,
  resourcesColumn,
  {
    id: "findings",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Findings" />
    ),
    cell: ({ row }) => <FindingsSummaryCell scan={row.original} />,
    enableSorting: false,
  },
  {
    id: "status",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Status" />
    ),
    cell: ({ row }) => <StatusCell scan={row.original} />,
    enableSorting: false,
  },
  {
    id: "scanSchedule",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Scan Schedule" />
    ),
    cell: ({ row }) => <ScheduleCell scan={row.original} />,
    enableSorting: false,
  },
  {
    id: "scanDate",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title="Scan Date"
        param="updated_at"
      />
    ),
    cell: ({ row }) => (
      <DateWithTime dateTime={row.original.attributes.completed_at} />
    ),
  },
  actionsColumn,
];

const scheduledColumns = (
  options: GetScanJobsColumnsOptions,
): ColumnDef<ScanProps>[] => [
  selectColumn(options),
  accountColumn,
  {
    id: "scanSchedule",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Scan Schedule" />
    ),
    cell: ({ row }) => <ScheduleCell scan={row.original} />,
    enableSorting: false,
  },
  {
    id: "lastScan",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Last Scan" />
    ),
    cell: ({ row }) => (
      <DateWithTime dateTime={row.original.attributes.completed_at} />
    ),
    enableSorting: false,
  },
  {
    id: "nextScan",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="Next Scan" />
    ),
    cell: ({ row }) => (
      <DateWithTime
        dateTime={
          row.original.attributes.next_scan_at ||
          row.original.attributes.scheduled_at
        }
      />
    ),
    enableSorting: false,
  },
  actionsColumn,
];

export function getScanJobsColumns(
  options: GetScanJobsColumnsOptions,
): ColumnDef<ScanProps>[] {
  if (options.tab === SCAN_JOBS_TAB.SCHEDULED) return scheduledColumns(options);
  if (options.tab === SCAN_JOBS_TAB.ACTIVE) return activeColumns(options);
  return completedColumns(options);
}
