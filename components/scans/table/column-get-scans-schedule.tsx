"use client";

import { ColumnDef } from "@tanstack/react-table";

import { DateWithTime, EntityInfoShort } from "@/components/ui/entities";
import { DataTableColumnHeader, StatusBadge } from "@/components/ui/table";
import { ScanProps } from "@/types";

import { DataTableRowActions } from "./data-table-row-actions";

const getScanData = (row: { original: ScanProps }) => {
  return row.original;
};

export const ColumnGetScansSchedule: ColumnDef<ScanProps>[] = [
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
    id: "actions",
    cell: ({ row }) => {
      return <DataTableRowActions row={row} />;
    },
  },
];
