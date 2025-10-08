"use client";

import { ColumnDef } from "@tanstack/react-table";

import { DataTableColumnHeader } from "@/components/ui/table";

import { DataTableRowActions } from "./data-table-row-actions";
import {
  DateCell,
  LastUsedCell,
  NameCell,
  PrefixCell,
  StatusCell,
} from "./table-cells";
import { ApiKeyData } from "./types";

export const createApiKeyColumns = (
  onEdit: (apiKey: ApiKeyData) => void,
  onDelete: (apiKey: ApiKeyData) => void,
): ColumnDef<ApiKeyData>[] => [
  {
    accessorKey: "name",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="NAME" />
    ),
    cell: ({ row }) => <NameCell apiKey={row.original} />,
  },
  {
    accessorKey: "prefix",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="PREFIX" />
    ),
    cell: ({ row }) => <PrefixCell apiKey={row.original} />,
  },
  {
    accessorKey: "inserted_at",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="CREATED" />
    ),
    cell: ({ row }) => <DateCell date={row.original.attributes.inserted_at} />,
  },
  {
    accessorKey: "last_used_at",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="LAST USED" />
    ),
    cell: ({ row }) => <LastUsedCell apiKey={row.original} />,
  },
  {
    accessorKey: "expires_at",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="EXPIRES" />
    ),
    cell: ({ row }) => <DateCell date={row.original.attributes.expires_at} />,
  },
  {
    accessorKey: "status",
    header: ({ column }) => (
      <DataTableColumnHeader column={column} title="STATUS" />
    ),
    cell: ({ row }) => <StatusCell apiKey={row.original} />,
  },
  {
    id: "actions",
    header: "Actions",
    cell: ({ row }) => {
      return (
        <DataTableRowActions row={row} onEdit={onEdit} onDelete={onDelete} />
      );
    },
  },
];
