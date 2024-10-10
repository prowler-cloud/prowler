"use client";

import { ColumnDef } from "@tanstack/react-table";
import { add } from "date-fns";

import { DateWithTime, EntityInfoShort } from "@/components/ui/entities";
import { DataTableColumnHeader, StatusBadge } from "@/components/ui/table";
import { ScanProps } from "@/types";

import { DataTableRowActions } from "./data-table-row-actions";

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
    accessorKey: "lastScan",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Completed At"}
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
    accessorKey: "nextScan",
    header: "Next Scan",
    cell: ({ row }) => {
      const {
        attributes: { scheduled_at, completed_at },
      } = getScanData(row);
      const nextDay = add(new Date(completed_at), {
        hours: 24,
      });
      if (scheduled_at === null)
        return <DateWithTime dateTime={nextDay.toISOString()} />;
      return <DateWithTime dateTime={scheduled_at} />;
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
    accessorKey: "started_at",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Started At"}
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
    id: "actions",
    cell: ({ row }) => {
      return <DataTableRowActions row={row} />;
    },
  },
];
