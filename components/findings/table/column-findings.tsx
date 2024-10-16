"use client";

import { ColumnDef } from "@tanstack/react-table";

import { DateWithTime, SnippetId } from "@/components/ui/entities";
import { DataTableColumnHeader, StatusBadge } from "@/components/ui/table";
import { FindingsProps } from "@/types";

import { DataTableRowActions } from "./data-table-row-actions";

const getFindingsData = (row: { original: FindingsProps }) => {
  return row.original;
};

export const ColumnFindings: ColumnDef<FindingsProps>[] = [
  // {
  //   header: " ",
  //   cell: ({ row }) => <p className="text-medium">{row.index + 1}</p>,
  // },
  {
    accessorKey: "account",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Status"} param="status" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { status },
      } = getFindingsData(row);
      return <p>{status}</p>;
    },
  },
  {
    accessorKey: "uid",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title={"Id"} param="uid" />
    ),
    cell: ({ row }) => {
      const {
        attributes: { uid },
      } = getFindingsData(row);
      return <SnippetId className="h-7 max-w-48" entityId={uid} />;
    },
  },
  {
    accessorKey: "status",
    header: "Scan Status",
    cell: () => {
      // Temporarily overwriting the value until the API is functional.
      return <StatusBadge status={"completed"} />;
    },
  },
  {
    accessorKey: "lastScan",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Last Scan"}
        param="updated_at"
      />
    ),
    cell: ({ row }) => {
      const {
        attributes: { updated_at },
      } = getFindingsData(row);
      return <DateWithTime dateTime={updated_at} />;
    },
  },
  {
    accessorKey: "added",
    header: ({ column }) => (
      <DataTableColumnHeader
        column={column}
        title={"Added"}
        param="inserted_at"
      />
    ),
    cell: ({ row }) => {
      const {
        attributes: { inserted_at },
      } = getFindingsData(row);
      return <DateWithTime dateTime={inserted_at} showTime={false} />;
    },
  },
  {
    id: "actions",
    cell: ({ row }) => {
      return <DataTableRowActions row={row} />;
    },
  },
];
