"use client";

import { ColumnDef } from "@tanstack/react-table";

import { InfoIcon, PlusIcon } from "@/components/icons";
import { DateWithTime, EntityInfoShort } from "@/components/ui/entities";
import { TriggerSheet } from "@/components/ui/sheet";
import { DataTableColumnHeader, StatusBadge } from "@/components/ui/table";
import { ScanProps } from "@/types";

import { DataTableRowActions } from "./data-table-row-actions";
import { DataTableRowDetails } from "./data-table-row-details";

const getScanData = (row: { original: ScanProps }) => {
  return row.original;
};

export const ColumnGetScans: ColumnDef<ScanProps>[] = [
  {
    accessorKey: "name",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Name"} param="name" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { name },
      } = getScanData(row);
      return <EntityInfoShort entityAlias={name} entityId={row.original.id} />;
    },
  },
  {
    accessorKey: "trigger",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Type"} param="trigger" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { trigger },
      } = getScanData(row);
      return <p>{trigger}</p>;
    },
  },

  {
    accessorKey: "status",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Status"} param="state" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { state },
      } = getScanData(row);
      return <StatusBadge status={state} />;
    },
  },
  {
    accessorKey: "scheduled_at",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Scheduled at"}
        param="scheduled_at"
      />
    ),
    cell: ({ row }) => {
      const {
        attributes: { scheduled_at },
      } = getScanData(row);
      return <DateWithTime dateTime={scheduled_at} />;
    },
  },
  {
    accessorKey: "started_at",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Started at"}
        param="started_at"
      />
    ),
    cell: ({ row }) => {
      const {
        attributes: { started_at },
      } = getScanData(row);
      return <DateWithTime dateTime={started_at} />;
    },
  },
  {
    accessorKey: "completed_at",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Completed at"}
        param="completed_at"
      />
    ),
    cell: ({ row }) => {
      const {
        attributes: { completed_at },
      } = getScanData(row);
      return <DateWithTime dateTime={completed_at} />;
    },
  },
  {
    accessorKey: "scanner_args",
    header: "Scanner Args",
    cell: ({ row }) => {
      const {
        attributes: { scanner_args },
      } = getScanData(row);
      return <p className="font-medium">{scanner_args?.only_logs}</p>;
    },
  },
  {
    accessorKey: "resources",
    header: "Resources",
    cell: ({ row }) => {
      const {
        attributes: { unique_resource_count },
      } = getScanData(row);
      return <p className="font-medium">{unique_resource_count}</p>;
    },
  },
  {
    id: "moreInfo",
    header: "Details",
    cell: ({ row }) => {
      return (
        <TriggerSheet
          triggerComponent={<InfoIcon className="text-primary" size={16} />}
          title="Scan Details"
          description="View the scan details"
        >
          <DataTableRowDetails entityId={row.original.id} />
        </TriggerSheet>
      );
    },
  },

  {
    id: "actions",
    cell: ({ row }) => {
      return <DataTableRowActions row={row} />;
    },
  },
];
